package server

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"saveserver/nvfiles"
	"saveserver/nvservice/listdata"
	"saveserver/nvservice/storage"
)

type fileFixture struct {
	path    string
	payload []byte
	hash    string
}

func TestUserDiskWorkflow(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	store, err := nvfiles.Open(ctx, filepath.Join(tmp, "nvfiles.db"))
	if err != nil {
		t.Fatalf("open nvfiles store: %v", err)
	}
	defer store.Close()

	factory, err := storage.NewDataFactory([]string{tmp})
	if err != nil {
		t.Fatalf("create storage factory: %v", err)
	}

	srv, err := New(tmp, store, factory)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	srv.dataCenterURL = ""

	srv.httpClient = nil
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := ts.Client()
	uid := uint64(1108494)

	resp, err := client.Get(fmt.Sprintf("%s/UserDisk/list?uid=%d&doc=1", ts.URL, uid))
	if err != nil {
		t.Fatalf("initial list request: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 on initial list, got %d", resp.StatusCode)
	}
	var initialList struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	decodeJSON(t, resp.Body, &initialList)
	if initialList.Code != 2 {
		t.Fatalf("unexpected initial list code: %d", initialList.Code)
	}

	fixtures := []fileFixture{
		{
			path:    "aaa.txt",
			payload: []byte("alpha-user-disk-data-1"),
		},
		{
			path:    "aaaa\\bbb\\cc\\dd.txt",
			payload: []byte("beta-user-disk-data-2"),
		},
		{
			path:    "bbb.txt",
			payload: []byte("gamma-user-disk-data-3"),
		},
	}
	hashToFixture := make(map[string]*fileFixture)
	for i := range fixtures {
		sum := sha1.Sum(fixtures[i].payload)
		fixtures[i].hash = hex.EncodeToString(sum[:])
		hashToFixture[fixtures[i].hash] = &fixtures[i]
	}

	checkPayload := make([]map[string]string, len(fixtures))
	for i, fx := range fixtures {
		checkPayload[i] = map[string]string{"hash": fx.hash}
	}
	checkBody, err := json.Marshal(checkPayload)
	if err != nil {
		t.Fatalf("marshal check payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/UserDisk/check_files?size=%d&deep=1&steam=1", ts.URL, len(checkBody)), bytes.NewReader(checkBody))
	if err != nil {
		t.Fatalf("construct check_files request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("check_files request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check_files status: %d", resp.StatusCode)
	}
	var checkResp struct {
		Code  int                 `json:"code"`
		Files []map[string]string `json:"files"`
	}
	decodeJSON(t, resp.Body, &checkResp)
	if checkResp.Code != 0 {
		t.Fatalf("check_files code: %d", checkResp.Code)
	}
	if len(checkResp.Files) != len(fixtures) {
		t.Fatalf("check_files missing count: got %d want %d", len(checkResp.Files), len(fixtures))
	}

	for _, missing := range checkResp.Files {
		hash := missing["hash"]
		fx, ok := hashToFixture[hash]
		if !ok {
			t.Fatalf("unexpected missing hash %q", hash)
		}
		uploadReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/UserDisk/upload_file?size=%d&hash=%s", ts.URL, len(fx.payload), hash), bytes.NewReader(fx.payload))
		if err != nil {
			t.Fatalf("construct upload request: %v", err)
		}
		uploadReq.Header.Set("Content-Type", "application/octet-stream")
		uploadResp, err := client.Do(uploadReq)
		if err != nil {
			t.Fatalf("upload_file request: %v", err)
		}
		if uploadResp.StatusCode != http.StatusOK {
			t.Fatalf("upload_file status: %d", uploadResp.StatusCode)
		}
		var uploadResult struct {
			Code int `json:"code"`
		}
		decodeJSON(t, uploadResp.Body, &uploadResult)
		if uploadResult.Code != 0 {
			t.Fatalf("upload_file code: %d", uploadResult.Code)
		}
	}

	req, err = http.NewRequest(http.MethodPost, fmt.Sprintf("%s/UserDisk/check_files?size=%d", ts.URL, len(checkBody)), bytes.NewReader(checkBody))
	if err != nil {
		t.Fatalf("construct recheck request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("recheck request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recheck status: %d", resp.StatusCode)
	}
	var recheckResp struct {
		Code  int                 `json:"code"`
		Files []map[string]string `json:"files"`
	}
	decodeJSON(t, resp.Body, &recheckResp)
	if recheckResp.Code != 0 {
		t.Fatalf("recheck code: %d", recheckResp.Code)
	}
	if len(recheckResp.Files) != 0 {
		t.Fatalf("files still missing: %+v", recheckResp.Files)
	}

	filetime := windowsFiletime(time.Now().UTC())

	instructions := []map[string]any{
		{
			"add": map[string]any{
				"hash": fixtures[0].hash,
				"path": fixtures[0].path,
				"size": len(fixtures[0].payload),
				"attr": uint32(listdata.FileAttributeArchive),
				"time": filetime,
			},
		},
		{
			"add": map[string]any{
				"hash": fixtures[1].hash,
				"path": fixtures[1].path,
				"size": len(fixtures[1].payload),
				"attr": uint32(listdata.FileAttributeArchive),
				"time": filetime,
			},
		},
		{
			"ren": map[string]string{
				"aaaa\\bbb\\cc\\dd.txt": "aaaa\\bbb\\cc\\ddd.txt",
			},
		},
		{
			"ren": map[string]string{
				"aaaa\\bbb": "aaaa\\bbbbbb",
			},
		},
		{
			"del": map[string]string{
				"name": "ghost.txt",
			},
		},
		{
			"add": map[string]any{
				"hash": fixtures[2].hash,
				"path": fixtures[2].path,
				"size": len(fixtures[2].payload),
				"attr": uint32(listdata.FileAttributeArchive),
				"time": filetime,
			},
		},
	}
	listBody, err := json.Marshal(instructions)
	if err != nil {
		t.Fatalf("marshal upload_list payload: %v", err)
	}
	listReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/UserDisk/upload_list?uid=%d&doc=1&size=%d", ts.URL, uid, len(listBody)), bytes.NewReader(listBody))
	if err != nil {
		t.Fatalf("construct upload_list request: %v", err)
	}
	listReq.Header.Set("Content-Type", "application/json")
	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("upload_list request: %v", err)
	}
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("upload_list status: %d", listResp.StatusCode)
	}
	var listResult struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	decodeJSON(t, listResp.Body, &listResult)
	if listResult.Code != 0 {
		t.Fatalf("upload_list code: %d msg=%q", listResult.Code, listResult.Msg)
	}

	resp, err = client.Get(fmt.Sprintf("%s/UserDisk/list?uid=%d&doc=1", ts.URL, uid))
	if err != nil {
		t.Fatalf("final list request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final list status: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read list body: %v", err)
	}
	listFile, err := listdata.Parse(data)
	if err != nil {
		t.Fatalf("parse list data: %v", err)
	}
	entries := listFile.CloneEntries()

	expectEntry := func(path string, expectedHash string, expectedSize int) {
		t.Helper()
		key := strings.ToLower(listdata.NormalizePath(path))
		entry, ok := entries[key]
		if !ok {
			t.Fatalf("entry %q not found", path)
		}
		if int(entry.Size) != expectedSize {
			t.Fatalf("entry %q size %d want %d", path, entry.Size, expectedSize)
		}
		if hex.EncodeToString(entry.Hash[:]) != expectedHash {
			t.Fatalf("entry %q hash %x want %s", path, entry.Hash, expectedHash)
		}
	}

	expectMissing := func(path string) {
		t.Helper()
		key := strings.ToLower(listdata.NormalizePath(path))
		if _, ok := entries[key]; ok {
			t.Fatalf("entry %q should not exist", path)
		}
	}

	expectEntry("aaa.txt", fixtures[0].hash, len(fixtures[0].payload))
	expectEntry("bbb.txt", fixtures[2].hash, len(fixtures[2].payload))
	expectEntry("aaaa\\bbbbbb\\cc\\ddd.txt", fixtures[1].hash, len(fixtures[1].payload))
	expectMissing("aaaa\\bbb")
	expectMissing("aaaa\\bbb\\cc\\dd.txt")
}

func decodeJSON(t *testing.T, body io.ReadCloser, target any) {
	t.Helper()
	defer body.Close()
	if err := json.NewDecoder(body).Decode(target); err != nil {
		t.Fatalf("decode json: %v", err)
	}
}

func windowsFiletime(ts time.Time) int64 {
	const windowsEpochDiff = int64(11644473600)
	return (ts.Unix()+windowsEpochDiff)*10000000 + int64(ts.Nanosecond()/100)
}
