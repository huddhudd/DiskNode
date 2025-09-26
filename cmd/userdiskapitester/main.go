package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"saveserver/nvservice/listdata"
)

type fileFixture struct {
	Path string
	Data []byte
	Hash string
}

type workflowSuite struct {
	client   *http.Client
	baseURL  string
	uid      uint64
	doc      bool
	steam    bool
	deep     bool
	prefix   string
	fixtures []*fileFixture
	now      time.Time
}

type checkResponse struct {
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Files []struct {
		Hash string `json:"hash"`
	} `json:"files"`
}

type simpleResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func main() {
	var (
		baseURL = flag.String("base-url", "http://127.0.0.1:8080", "UserDisk 服务器基地址")
		uid     = flag.Uint64("uid", 1108494, "用户 UID")
		doc     = flag.Bool("doc", true, "是否携带 doc=1 参数")
		steam   = flag.Bool("steam", true, "check_files 时是否加 steam=1")
		deep    = flag.Bool("deep", true, "check_files 时是否加 deep=1")
		prefix  = flag.String("prefix", "apitest", "生成的文件路径前缀（会追加时间戳确保唯一）")
		timeout = flag.Duration("timeout", 10*time.Second, "HTTP 请求超时时间")
	)
	flag.Parse()

	client := &http.Client{Timeout: *timeout}
	now := time.Now().UTC()

	suite := &workflowSuite{
		client:  client,
		baseURL: strings.TrimRight(*baseURL, "/"),
		uid:     *uid,
		doc:     *doc,
		steam:   *steam,
		deep:    *deep,
		prefix:  fmt.Sprintf("%s_%d", sanitizePrefix(*prefix), now.Unix()),
		now:     now,
	}

	suite.initFixtures()

	if err := suite.run(); err != nil {
		log.Fatalf("workflow failed: %v", err)
	}

	log.Println("workflow completed successfully")
}

func sanitizePrefix(prefix string) string {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return "apitest"
	}
	trimmed = strings.ReplaceAll(trimmed, "/", "_")
	trimmed = strings.ReplaceAll(trimmed, "\\", "_")
	return trimmed
}

func (s *workflowSuite) initFixtures() {
	join := func(parts ...string) string {
		joined := strings.Join(parts, "\\")
		return listdata.NormalizePath(joined)
	}

	s.fixtures = []*fileFixture{
		{Path: join(s.prefix, "aaa.txt"), Data: []byte("alpha-user-disk-data-1")},
		{Path: join(s.prefix, "dir", "orig.txt"), Data: []byte("beta-user-disk-data-2")},
		{Path: join(s.prefix, "bbb.txt"), Data: []byte("gamma-user-disk-data-3")},
		{Path: join(s.prefix, "tempdir", "temp.txt"), Data: []byte("temporary-data-to-delete")},
	}

	for _, fx := range s.fixtures {
		sum := sha1.Sum(fx.Data)
		fx.Hash = hex.EncodeToString(sum[:])
	}
}

func (s *workflowSuite) run() error {
	log.Printf("使用 UID=%d doc=%v steam=%v deep=%v 前缀=%s", s.uid, s.doc, s.steam, s.deep, s.prefix)

	if err := s.getInitialList(); err != nil {
		return err
	}

	if err := s.checkAndUpload(); err != nil {
		return err
	}

	if err := s.uploadList(); err != nil {
		return err
	}

	if err := s.verifyFinalList(); err != nil {
		return err
	}

	return nil
}

func (s *workflowSuite) getInitialList() error {
	log.Println("Step 1: 拉取清单 (可能不存在)")
	resp, err := s.client.Get(s.listURL())
	if err != nil {
		return fmt.Errorf("GET list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Println("已有历史清单，将继续追加测试数据")
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	log.Printf("初次获取返回状态 %d, 响应: %s", resp.StatusCode, truncate(string(body), 200))
	return nil
}

func (s *workflowSuite) checkAndUpload() error {
	log.Println("Step 2: check_files -> upload_file")

	payload := make([]map[string]string, len(s.fixtures))
	for i, fx := range s.fixtures {
		payload[i] = map[string]string{"hash": fx.Hash}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal check payload: %w", err)
	}

	qs := url.Values{}
	qs.Set("size", fmt.Sprintf("%d", len(raw)))
	if s.steam {
		qs.Set("steam", "1")
	}
	if s.deep {
		qs.Set("deep", "1")
	}

	checkURL := fmt.Sprintf("%s?%s", s.endpointURL("/UserDisk/check_files"), qs.Encode())
	log.Printf("POST %s", checkURL)

	resp, err := s.client.Post(checkURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("POST check_files: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("check_files status %d body=%s", resp.StatusCode, truncate(string(body), 200))
	}

	var decoded checkResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fmt.Errorf("decode check_files: %w", err)
	}
	if decoded.Code != 0 {
		return fmt.Errorf("check_files code=%d msg=%s", decoded.Code, decoded.Msg)
	}

	missing := make(map[string]*fileFixture)
	for _, fx := range s.fixtures {
		missing[fx.Hash] = fx
	}
	for _, entry := range decoded.Files {
		hash := strings.ToLower(strings.TrimSpace(entry.Hash))
		if _, ok := missing[hash]; !ok {
			log.Printf("服务器报告未知 hash: %s", hash)
			continue
		}
		missing[hash].Hash = hash
	}

	for hash, fx := range missing {
		if fx == nil {
			continue
		}
		if err := s.uploadFile(hash, fx.Data); err != nil {
			return err
		}
		delete(missing, hash)
	}

	return s.recheck(payload)
}

func (s *workflowSuite) uploadFile(hash string, data []byte) error {
	qs := url.Values{}
	qs.Set("hash", hash)
	qs.Set("size", fmt.Sprintf("%d", len(data)))

	uploadURL := fmt.Sprintf("%s?%s", s.endpointURL("/UserDisk/upload_file"), qs.Encode())
	log.Printf("POST %s (size=%d)", uploadURL, len(data))

	resp, err := s.client.Post(uploadURL, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("upload_file %s: %w", hash, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload_file status=%d body=%s", resp.StatusCode, truncate(string(body), 200))
	}

	var decoded simpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fmt.Errorf("decode upload_file: %w", err)
	}
	if decoded.Code != 0 {
		return fmt.Errorf("upload_file code=%d msg=%s", decoded.Code, decoded.Msg)
	}

	log.Printf("hash=%s 上传完成", hash)
	return nil
}

func (s *workflowSuite) recheck(payload []map[string]string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal recheck payload: %w", err)
	}

	qs := url.Values{}
	qs.Set("size", fmt.Sprintf("%d", len(raw)))

	recheckURL := fmt.Sprintf("%s?%s", s.endpointURL("/UserDisk/check_files"), qs.Encode())
	log.Printf("POST %s", recheckURL)

	resp, err := s.client.Post(recheckURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("POST recheck: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("recheck status %d body=%s", resp.StatusCode, truncate(string(body), 200))
	}

	var decoded checkResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fmt.Errorf("decode recheck: %w", err)
	}
	if decoded.Code != 0 {
		return fmt.Errorf("recheck code=%d msg=%s", decoded.Code, decoded.Msg)
	}
	if len(decoded.Files) > 0 {
		return fmt.Errorf("仍有缺失文件: %+v", decoded.Files)
	}

	log.Println("所有文件已存在，无需再次上传")
	return nil
}

func (s *workflowSuite) uploadList() error {
	log.Println("Step 3: upload_list 更新清单")

	instructions := s.buildInstructions()
	raw, err := json.Marshal(instructions)
	if err != nil {
		return fmt.Errorf("marshal instructions: %w", err)
	}

	qs := url.Values{}
	qs.Set("uid", fmt.Sprintf("%d", s.uid))
	qs.Set("size", fmt.Sprintf("%d", len(raw)))
	if s.doc {
		qs.Set("doc", "1")
	}

	uploadURL := fmt.Sprintf("%s?%s", s.endpointURL("/UserDisk/upload_list"), qs.Encode())
	log.Printf("POST %s", uploadURL)

	resp, err := s.client.Post(uploadURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("POST upload_list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload_list status=%d body=%s", resp.StatusCode, truncate(string(body), 200))
	}

	var decoded simpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fmt.Errorf("decode upload_list: %w", err)
	}
	if decoded.Code != 0 {
		return fmt.Errorf("upload_list code=%d msg=%s", decoded.Code, decoded.Msg)
	}

	log.Printf("upload_list 成功: %s", decoded.Msg)
	return nil
}

func (s *workflowSuite) buildInstructions() []map[string]any {
	filetime := windowsFiletime(s.now)

	rename1From := s.fixtures[1].Path
	rename1To := listdata.NormalizePath(strings.Replace(rename1From, "orig.txt", "orig_renamed.txt", 1))
	rename2From := listdata.NormalizePath(strings.Join([]string{s.prefix, "dir"}, "\\"))
	rename2To := listdata.NormalizePath(strings.Join([]string{s.prefix, "dir_renamed"}, "\\"))

	instructions := make([]map[string]any, 0, 8)

	for _, fx := range s.fixtures {
		instructions = append(instructions, map[string]any{
			"add": map[string]any{
				"hash": fx.Hash,
				"path": fx.Path,
				"size": len(fx.Data),
				"attr": uint32(listdata.FileAttributeArchive),
				"time": filetime,
			},
		})
	}

	instructions = append(instructions,
		map[string]any{"ren": map[string]string{rename1From: rename1To}},
		map[string]any{"ren": map[string]string{rename2From: rename2To}},
		map[string]any{"del": map[string]string{"name": listdata.NormalizePath(strings.Join([]string{s.prefix, "tempdir"}, "\\"))}},
	)

	s.fixtures[1].Path = listdata.NormalizePath(strings.Join([]string{rename2To, baseName(rename1To)}, "\\"))
	s.fixtures = s.fixtures[:3]

	return instructions
}

func baseName(path string) string {
	if idx := strings.LastIndex(path, "\\"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func (s *workflowSuite) verifyFinalList() error {
	log.Println("Step 4: 再次拉取清单并验证结果")

	resp, err := s.client.Get(s.listURL())
	if err != nil {
		return fmt.Errorf("GET final list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("final list status=%d body=%s", resp.StatusCode, truncate(string(body), 200))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read final list: %w", err)
	}

	file, err := listdata.Parse(data)
	if err != nil {
		return fmt.Errorf("parse final list: %w", err)
	}

	entries := file.CloneEntries()

	expected := make(map[string]*fileFixture)
	for _, fx := range s.fixtures {
		expected[strings.ToLower(listdata.NormalizePath(fx.Path))] = fx
	}

	for key, fx := range expected {
		entry, ok := entries[key]
		if !ok {
			return fmt.Errorf("缺少条目 %s", fx.Path)
		}
		if hex.EncodeToString(entry.Hash[:]) != fx.Hash {
			return fmt.Errorf("条目 %s hash=%x 期望=%s", fx.Path, entry.Hash, fx.Hash)
		}
		if int(entry.Size) != len(fx.Data) {
			return fmt.Errorf("条目 %s size=%d 期望=%d", fx.Path, entry.Size, len(fx.Data))
		}
	}

	deletedKey := strings.ToLower(listdata.NormalizePath(strings.Join([]string{s.prefix, "tempdir"}, "\\")))
	for key := range entries {
		if strings.HasPrefix(key, deletedKey) {
			return fmt.Errorf("发现已删除目录残留: %s", key)
		}
	}

	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	log.Println("最终清单包含条目:")
	for _, key := range keys {
		entry := entries[key]
		log.Printf("  - %s (size=%d hash=%s attr=%#x)", entry.Path, entry.Size, hex.EncodeToString(entry.Hash[:]), entry.Attributes)
	}

	return nil
}

func (s *workflowSuite) endpointURL(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return s.baseURL + path
}

func (s *workflowSuite) listURL() string {
	qs := url.Values{}
	qs.Set("uid", fmt.Sprintf("%d", s.uid))
	if s.doc {
		qs.Set("doc", "1")
	}
	return fmt.Sprintf("%s?%s", s.endpointURL("/UserDisk/list"), qs.Encode())
}

func windowsFiletime(ts time.Time) int64 {
	const windowsEpochDiff = int64(11644473600)
	return (ts.Unix()+windowsEpochDiff)*10000000 + int64(ts.Nanosecond()/100)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
