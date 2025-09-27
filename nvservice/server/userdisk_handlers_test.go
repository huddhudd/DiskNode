package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saveserver/nvfiles"
	"saveserver/nvservice/storage"
)

func TestHandleUserDiskListReadErrorMatchesNotFound(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	store, err := nvfiles.Open(ctx, filepath.Join(tmp, "nvfiles.db"))
	if err != nil {
		t.Fatalf("open nvfiles store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	factory, err := storage.NewDataFactory([]string{tmp})
	if err != nil {
		t.Fatalf("create storage factory: %v", err)
	}

	srv, err := New(tmp, store, factory)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	uid := uint64(4192)
	dir, listPath, _ := srv.userListPaths(uid, appIDUserDisk)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("make user list dir: %v", err)
	}
	if err := os.MkdirAll(listPath, 0o755); err != nil {
		t.Fatalf("create conflicting list path: %v", err)
	}

	resp, err := http.Get(ts.URL + "/UserDisk/list?uid=" + "4192")
	if err != nil {
		t.Fatalf("user disk list request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}

	var payload struct {
		Code int `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Code != 2 {
		t.Fatalf("code = %d, want 2", payload.Code)
	}
}

func TestHandleUserDiskListEmptyFileReturnsEmptyResponse(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	store, err := nvfiles.Open(ctx, filepath.Join(tmp, "nvfiles.db"))
	if err != nil {
		t.Fatalf("open nvfiles store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	factory, err := storage.NewDataFactory([]string{tmp})
	if err != nil {
		t.Fatalf("create storage factory: %v", err)
	}

	srv, err := New(tmp, store, factory)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	uid := uint64(9001)
	dir, listPath, _ := srv.userListPaths(uid, appIDUserDisk)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("make user list dir: %v", err)
	}
	if err := os.WriteFile(listPath, nil, 0o644); err != nil {
		t.Fatalf("create empty list file: %v", err)
	}

	resp, err := http.Get(ts.URL + "/UserDisk/list?uid=" + "9001")
	if err != nil {
		t.Fatalf("user disk list request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "stream/fileslist" {
		t.Fatalf("content-type = %q, want stream/fileslist", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("body length = %d, want 0", len(body))
	}
}

func TestHandleUserDiskCheckFilesRequiresSizeParam(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	store, err := nvfiles.Open(ctx, filepath.Join(tmp, "nvfiles.db"))
	if err != nil {
		t.Fatalf("open nvfiles store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	factory, err := storage.NewDataFactory([]string{tmp})
	if err != nil {
		t.Fatalf("create storage factory: %v", err)
	}

	srv, err := New(tmp, store, factory)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	payload := []byte(`[{"hash":"` + strings.Repeat("a", 40) + `"}]`)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/UserDisk/check_files", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("construct request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}

	var result struct {
		Code int `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Code != 2 {
		t.Fatalf("code = %d, want 2", result.Code)
	}
}

func TestHandleUserDiskCheckFilesRejectsMismatchedSize(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	store, err := nvfiles.Open(ctx, filepath.Join(tmp, "nvfiles.db"))
	if err != nil {
		t.Fatalf("open nvfiles store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	factory, err := storage.NewDataFactory([]string{tmp})
	if err != nil {
		t.Fatalf("create storage factory: %v", err)
	}

	srv, err := New(tmp, store, factory)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	payload := []byte(`[{"hash":"` + strings.Repeat("b", 40) + `"}]`)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/UserDisk/check_files?size=999", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("construct request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}

	var result struct {
		Code int `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Code != 2 {
		t.Fatalf("code = %d, want 2", result.Code)
	}
}

func TestHandleUserDiskCheckFilesRejectsEmptyBody(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	store, err := nvfiles.Open(ctx, filepath.Join(tmp, "nvfiles.db"))
	if err != nil {
		t.Fatalf("open nvfiles store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	factory, err := storage.NewDataFactory([]string{tmp})
	if err != nil {
		t.Fatalf("create storage factory: %v", err)
	}

	srv, err := New(tmp, store, factory)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/UserDisk/check_files?size=10", http.NoBody)
	if err != nil {
		t.Fatalf("construct request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}

	var result struct {
		Code int `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Code != 1 {
		t.Fatalf("code = %d, want 1", result.Code)
	}
}
