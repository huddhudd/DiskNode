package usersave

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"saveserver/nvservice/storage"
)

const (
	uploadChunkSize   = 1 << 20
	uploadSign        = "0641db64f7701ec8b8333e243e151e44"
	dataCenterTimeout = 30 * time.Second
)

type DataCenterShareClient struct {
	base       *url.URL
	httpClient *http.Client
	storage    *storage.DataFactory
}

type DataCenterShareDownloader struct {
	base       *url.URL
	httpClient *http.Client
	storage    *storage.DataFactory
}

func NewDataCenterShareClient(rawURL string, client *http.Client, factory *storage.DataFactory) (*DataCenterShareClient, error) {
	base, err := parseDataCenterBase(rawURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("http client is nil")
	}
	if factory == nil {
		return nil, errors.New("storage is nil")
	}
	return &DataCenterShareClient{base: base, httpClient: client, storage: factory}, nil
}

func NewDataCenterShareDownloader(rawURL string, client *http.Client, factory *storage.DataFactory) (*DataCenterShareDownloader, error) {
	base, err := parseDataCenterBase(rawURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("http client is nil")
	}
	if factory == nil {
		return nil, errors.New("storage is nil")
	}
	return &DataCenterShareDownloader{base: base, httpClient: client, storage: factory}, nil
}

func (c *DataCenterShareClient) Share(ctx context.Context, req *ShareRequest) error {
	if req == nil {
		return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x101"}
	}
	uploads, err := c.checkRemote(ctx, req)
	if err != nil {
		return err
	}

	uploadedTotal := int64(0)
	filesUploaded := int64(0)

	progress := func(delta int64) {
		if delta <= 0 {
			return
		}
		uploadedTotal += delta
		if req.Progress != nil {
			req.Progress(uploadedTotal, filesUploaded)
		}
	}

	for _, file := range req.Files {
		hash := strings.ToLower(strings.TrimSpace(file.Hash))
		offset, needUpload := uploads[hash]
		if needUpload {
			if err := c.uploadFile(ctx, req, file, offset, progress); err != nil {
				return err
			}
			delete(uploads, hash)
		}
		filesUploaded++
		if req.Progress != nil {
			req.Progress(uploadedTotal, filesUploaded)
		}
	}

	if err := c.sendShare(ctx, req); err != nil {
		return err
	}

	if req.Progress != nil {
		req.Progress(uploadedTotal, filesUploaded)
	}
	return nil
}

type checkFile struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

type checkResponse struct {
	Code  int           `json:"code"`
	Msg   string        `json:"msg"`
	Files []checkResult `json:"files"`
}

type checkResult struct {
	Hash   string `json:"hash"`
	State  int    `json:"state"`
	Offset int64  `json:"size"`
}

func (c *DataCenterShareClient) checkRemote(ctx context.Context, req *ShareRequest) (map[string]int64, error) {
	body := make([]checkFile, 0, len(req.Files))
	for _, f := range req.Files {
		body = append(body, checkFile{Hash: strings.ToLower(strings.TrimSpace(f.Hash)), Size: f.Size})
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x101", Err: err}
	}

	checkURL := resolveDataCenterPath(c.base, "/server/UserSave/check")
	ctx, cancel := context.WithTimeout(ctx, dataCenterTimeout)
	defer cancel()

	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL.String(), bytes.NewReader(data))
	if err != nil {
		return nil, &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x101", Err: err}
	}
	reqHTTP.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(reqHTTP)
	if err != nil {
		return nil, &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x101", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x101", Err: fmt.Errorf("status %d", resp.StatusCode)}
	}

	var parsed checkResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x102", Err: err}
	}
	if parsed.Code != 0 {
		return nil, &TaskFailure{Message: chooseString(parsed.Msg, "鍏变韩涓婁紶澶辫触! 0x103")}
	}

	uploads := make(map[string]int64, len(parsed.Files))
	for _, item := range parsed.Files {
		if item.State == 3 || item.State == 4 {
			continue
		}
		hash := strings.ToLower(strings.TrimSpace(item.Hash))
		if len(hash) != 40 {
			continue
		}
		uploads[hash] = item.Offset
	}
	return uploads, nil
}

func (c *DataCenterShareClient) uploadFile(ctx context.Context, req *ShareRequest, file ShareFile, offset int64, progress func(int64)) error {
	hash := strings.ToLower(strings.TrimSpace(file.Hash))
	localPath, ok := c.storage.ExistsArchive(hash)
	if !ok {
		if fallback, ok := c.storage.Exists(hash); ok {
			localPath = fallback
		}
	}
	if localPath == "" {
		return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x104"}
	}

	f, err := os.Open(localPath)
	if err != nil {
		return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x104", Err: err}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x104", Err: err}
	}
	size := info.Size()
	if offset >= size {
		offset = 0
	}

	buf := make([]byte, uploadChunkSize)

	for offset < size {
		chunk := int64(uploadChunkSize)
		if remaining := size - offset; remaining < chunk {
			chunk = remaining
		}

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x104", Err: err}
		}
		n, err := io.ReadFull(f, buf[:chunk])
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x104", Err: err}
		}

		uploadURL := resolveDataCenterPath(c.base, "/server/UserSave/upload")
		q := uploadURL.Query()
		q.Set("type", "USERSAVE")
		q.Set("hash", hash)
		q.Set("size", strconv.FormatInt(size, 10))
		q.Set("offset", strconv.FormatInt(offset, 10))
		q.Set("token", buildUploadToken(size, offset, hash))
		uploadURL.RawQuery = q.Encode()

		ctxReq, cancel := context.WithTimeout(ctx, dataCenterTimeout)
		reqHTTP, err := http.NewRequestWithContext(ctxReq, http.MethodPost, uploadURL.String(), bytes.NewReader(buf[:n]))
		if err != nil {
			cancel()
			return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x105", Err: err}
		}
		reqHTTP.Header.Set("Content-Type", "application/octet-stream")

		resp, err := c.httpClient.Do(reqHTTP)
		if err != nil {
			cancel()
			return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x105", Err: err}
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		cancel()

		if resp.StatusCode != http.StatusOK {
			return &TaskFailure{Message: "鍏变韩涓婁紶澶辫触! 0x105", Err: fmt.Errorf("status %d", resp.StatusCode)}
		}

		if progress != nil {
			progress(int64(n))
		}
		offset += int64(n)
	}

	if progress != nil {
		progress(0)
	}
	return nil
}

func (c *DataCenterShareClient) sendShare(ctx context.Context, req *ShareRequest) error {
	payload := map[string]any{
		"info": map[string]any{
			"share_id": req.ShareID,
			"uid":      req.UID,
			"token":    req.Token,
			"rid":      req.RID,
			"name":     req.Info.Name,
			"ver":      req.Info.Version,
			"rec_time": req.Info.RecTime,
			"size":     req.Info.Size,
			"capture":  req.Info.Capture,
			"comment":  req.Info.Comment,
			"add":      req.Info.Add,
		},
	}

	files := make([]map[string]any, 0, len(req.Files))
	for _, f := range req.Files {
		files = append(files, map[string]any{
			"file":     f.Path,
			"size":     f.Size,
			"hash":     strings.ToLower(strings.TrimSpace(f.Hash)),
			"attr":     f.Attr,
			"creation": f.Creation,
			"ver":      f.Ver,
			"rec_time": f.RecTime,
		})
	}
	payload["files"] = files

	data, err := json.Marshal(payload)
	if err != nil {
		return &TaskFailure{Message: "鍏变韩澶辫触! 0x201", Err: err}
	}

	shareURL := resolveDataCenterPath(c.base, "/server/UserSave/share")
	ctxReq, cancel := context.WithTimeout(ctx, dataCenterTimeout)
	defer cancel()

	reqHTTP, err := http.NewRequestWithContext(ctxReq, http.MethodPost, shareURL.String(), bytes.NewReader(data))
	if err != nil {
		return &TaskFailure{Message: "鍏变韩澶辫触! 0x202", Err: err}
	}
	reqHTTP.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(reqHTTP)
	if err != nil {
		return &TaskFailure{Message: "鍏变韩澶辫触! 0x202", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &TaskFailure{Message: "鍏变韩澶辫触! 0x202", Err: fmt.Errorf("status %d", resp.StatusCode)}
	}

	var parsed struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return &TaskFailure{Message: "鍏变韩澶辫触! 0x203", Err: err}
	}
	if parsed.Code != 0 {
		return &TaskFailure{Message: chooseString(parsed.Msg, "鍏变韩澶辫触! 0x203")}
	}

	if len(parsed.Data) > 0 {
		var payloadData struct {
			ShareID json.Number `json:"share_id"`
			SID     json.Number `json:"sid"`
			Info    struct {
				ShareID json.Number `json:"share_id"`
			} `json:"info"`
		}
		if err := json.Unmarshal(parsed.Data, &payloadData); err == nil {
			if id := extractShareID(payloadData.ShareID); id > 0 {
				req.ShareID = id
			} else if id := extractShareID(payloadData.SID); id > 0 {
				req.ShareID = id
			} else if id := extractShareID(payloadData.Info.ShareID); id > 0 {
				req.ShareID = id
			}
		}
	}

	return nil
}

func extractShareID(num json.Number) int64 {
	if num == "" {
		return 0
	}
	if v, err := num.Int64(); err == nil && v > 0 {
		return v
	}
	if f, err := strconv.ParseFloat(num.String(), 64); err == nil && f > 0 {
		return int64(f)
	}
	return 0
}

func (d *DataCenterShareDownloader) Download(ctx context.Context, req *DownloadShareRequest) (*DownloadShareResult, error) {
	if req == nil {
		return nil, &TaskFailure{Message: "鎷夊彇瀛樻。澶辫触锛岃绋嶅€欏啀璇曪紒0x1"}
	}
	shareURL := resolveDataCenterPath(d.base, "/server/usersave/share_down")
	q := shareURL.Query()
	q.Set("shared_id", strconv.FormatInt(req.ShareID, 10))
	q.Set("uid", strconv.FormatUint(uint64(req.UID), 10))
	if strings.TrimSpace(req.Token) != "" {
		q.Set("token", req.Token)
	}
	shareURL.RawQuery = q.Encode()

	ctxReq, cancel := context.WithTimeout(ctx, dataCenterTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctxReq, http.MethodGet, shareURL.String(), nil)
	if err != nil {
		return nil, &TaskFailure{Message: "鎷夊彇瀛樻。澶辫触锛岃绋嶅€欏啀璇曪紒0x1", Err: err}
	}

	resp, err := d.httpClient.Do(httpReq)
	if err != nil {
		return nil, &TaskFailure{Message: "鎷夊彇瀛樻。澶辫触锛岃绋嶅€欏啀璇曪紒0x1", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &TaskFailure{Message: "鎷夊彇瀛樻。澶辫触锛岃绋嶅€欏啀璇曪紒0x1", Err: fmt.Errorf("status %d", resp.StatusCode)}
	}

	var payload struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Info  shareDownInfo   `json:"info"`
			Files []shareDownFile `json:"files"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, &TaskFailure{Message: "鎷夊彇瀛樻。澶辫触锛岃绋嶅€欏啀璇曪紒0x2", Err: err}
	}
	if payload.Code != 0 {
		return nil, &TaskFailure{Message: chooseString(payload.Msg, "鎷夊彇瀛樻。澶辫触锛岃绋嶅€欏啀璇曪紒0x1")}
	}

	if payload.Data.Info.RID == 0 {
		return nil, &TaskFailure{Message: "鐠囥儱鐡ㄥ锝勭瑝鐎涙ê婀敍?x6"}
	}

	for _, file := range payload.Data.Files {
		hash := strings.ToLower(file.Hash)
		if hash == "" {
			continue
		}
		if _, ok := d.storage.ExistsArchive(hash); ok {
			continue
		}
		if err := d.downloadArchiveFile(ctx, hash); err != nil {
			return nil, err
		}
	}

	result := &DownloadShareResult{
		Info: ShareInfo{
			Name:    payload.Data.Info.Name,
			Comment: payload.Data.Info.Comment,
			Add:     payload.Data.Info.Add,
			Size:    payload.Data.Info.Size,
			Version: payload.Data.Info.Ver,
			RecTime: payload.Data.Info.RecTime,
			Capture: payload.Data.Info.Capture,
		},
		RID: payload.Data.Info.RID,
	}

	var totalSize int64
	for _, file := range payload.Data.Files {
		hash := strings.ToLower(file.Hash)
		result.Files = append(result.Files, DownloadShareFile{
			Path:     file.File,
			Size:     file.Size,
			Hash:     hash,
			Attr:     file.Attr,
			Creation: file.Creation,
			RecTime:  file.RecTime,
		})
		totalSize += file.Size
	}

	if result.Info.Size == 0 {
		result.Info.Size = totalSize
	}

	return result, nil
}

type shareDownInfo struct {
	RID     uint32 `json:"rid"`
	Name    string `json:"name"`
	Ver     int64  `json:"ver"`
	RecTime int64  `json:"rec_time"`
	Capture string `json:"capture"`
	Comment string `json:"comment"`
	Add     string `json:"add"`
	Size    int64  `json:"size"`
}

type shareDownFile struct {
	File     string `json:"file"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
	Attr     uint32 `json:"attr"`
	Creation int64  `json:"creation"`
	RecTime  int64  `json:"rec_time"`
}

func (d *DataCenterShareDownloader) downloadArchiveFile(ctx context.Context, hash string) error {
	if len(hash) != 40 {
		return &TaskFailure{Message: "鎷夊彇瀛樻。鏂囦欢澶辫触锛?0x9"}
	}
	if _, ok := d.storage.ExistsArchive(hash); ok {
		return nil
	}

	path := fmt.Sprintf("/DataCenter/%s/%s/%s", hash[:2], hash[2:4], hash)
	fileURL := resolveDataCenterPath(d.base, path)

	ctxReq, cancel := context.WithTimeout(ctx, dataCenterTimeout)
	defer cancel()

	reqHTTP, err := http.NewRequestWithContext(ctxReq, http.MethodGet, fileURL.String(), nil)
	if err != nil {
		return &TaskFailure{Message: "鎷夊彇瀛樻。鏂囦欢澶辫触锛?0x9", Err: err}
	}

	resp, err := d.httpClient.Do(reqHTTP)
	if err != nil {
		return &TaskFailure{Message: "鎷夊彇瀛樻。鏂囦欢澶辫触锛?0x9", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &TaskFailure{Message: "鎷夊彇瀛樻。鏂囦欢澶辫触锛?0x9", Err: fmt.Errorf("status %d", resp.StatusCode)}
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return &TaskFailure{Message: "鎷夊彇瀛樻。鏂囦欢澶辫触锛?0x9", Err: err}
	}

	if _, err := d.storage.SaveArchiveFile(hash, data); err != nil {
		return &TaskFailure{Message: "鎷夊彇瀛樻。鏂囦欢澶辫触锛?0x9", Err: err}
	}

	return nil
}

func buildUploadToken(size, offset int64, hash string) string {
	input := fmt.Sprintf("%d%d%s%s", size, offset, hash, uploadSign)
	sum := md5.Sum([]byte(input))
	return hex.EncodeToString(sum[:])
}

func parseDataCenterBase(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("data center url is empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("data center url invalid")
	}
	base := &url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
	}
	return base, nil
}

func resolveDataCenterPath(base *url.URL, path string) *url.URL {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	ref := &url.URL{Path: path}
	return base.ResolveReference(ref)
}

func chooseString(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}
