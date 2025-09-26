package server

import (
	"bytes"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"saveserver/nvfiles"
	"saveserver/nvservice/listdata"
	"saveserver/nvservice/storage"
)

func newUserDataTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

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

	return srv, ts
}

func TestUserDataUploadSave(t *testing.T) {
	srv, ts := newUserDataTestServer(t)

	uid := uint32(1001)
	rid := uint32(5)
	data := []byte("hello userdata upload")
	sum := sha1.Sum(data)
	hashHex := hex.EncodeToString(sum[:])

	params := url.Values{}
	params.Set("uid", strconv.Itoa(int(uid)))
	params.Set("rid", strconv.Itoa(int(rid)))
	params.Set("hash", hashHex)
	params.Set("path", "folder\\save.dat")
	params.Set("attr", "32")
	params.Set("size", strconv.Itoa(len(data)))

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/UserData/uploadSave?"+params.Encode(), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status: %d", resp.StatusCode)
	}

	var payload struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Code != 0 {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	tempDir, err := srv.userSave.UserTempDir(uid, false)
	if err != nil {
		t.Fatalf("user temp dir: %v", err)
	}
	savedPath := filepath.Join(tempDir, strconv.Itoa(int(rid)), "folder", "save.dat")
	content, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if !bytes.Equal(content, data) {
		t.Fatalf("saved content mismatch: %q", content)
	}
}

func TestUserDataDeleteFiles(t *testing.T) {
	srv, ts := newUserDataTestServer(t)

	uid := uint32(2002)
	rid := uint32(9)
	tempDir, err := srv.userSave.UserTempDir(uid, true)
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	target := filepath.Join(tempDir, strconv.Itoa(int(rid)), "folder", "delete.dat")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(target, []byte("delete me"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	body := map[string]any{"files": []string{"folder\\delete.dat"}}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/UserData/deleteFiles?uid=%d&rid=%d", ts.URL, uid, rid), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status: %d", resp.StatusCode)
	}

	var result struct {
		Code            int    `json:"code"`
		Msg             string `json:"msg"`
		TotalFilesCount int    `json:"TotleFilesCount"`
		FailedCount     uint32 `json:"FailedCount"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Code != 0 || result.TotalFilesCount != 1 || result.FailedCount != 0 {
		t.Fatalf("unexpected response: %+v", result)
	}

	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file not removed: %v", err)
	}
}

func TestUserDataUploadSavePic(t *testing.T) {
	srv, ts := newUserDataTestServer(t)

	uid := uint32(3003)
	rid := uint32(11)
	data := []byte(strings.Repeat("p", 128))

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/UserData/uploadSavePic?uid=%d&rid=%d&size=%d", ts.URL, uid, rid, len(data)), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("upload pic request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload pic status: %d", resp.StatusCode)
	}

	var payload struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Code != 0 {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	tempDir, err := srv.userSave.UserTempDir(uid, false)
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	pic := filepath.Join(tempDir, fmt.Sprintf("%d.jpg", rid))
	content, err := os.ReadFile(pic)
	if err != nil {
		t.Fatalf("read pic: %v", err)
	}
	if !bytes.Equal(content, data) {
		t.Fatalf("pic content mismatch")
	}
}

func TestUserDataList(t *testing.T) {
	ctx := context.Background()
	srv, ts := newUserDataTestServer(t)

	uid := uint32(4004)
	rid := uint32(21)
	ver := time.Now().UnixMilli()
	rec := ver + 1000
	hash := strings.Repeat("a", 40)

	historyInsert := `INSERT INTO history (uid, rid, ver, rec_time, name, size, inuse) VALUES (?, ?, ?, ?, ?, ?, 1)`
	if err := srv.userSave.Exec(ctx, historyInsert, uid, rid, ver, rec, "slot", int64(11)); err != nil {
		t.Fatalf("insert history: %v", err)
	}

	filesInsert := `INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if err := srv.userSave.Exec(ctx, filesInsert, uid, rid, fmt.Sprintf("%d\\folder\\save.dat", rid), int64(20), hash, time.Now().UTC().UnixNano()/100, uint32(listdata.FileAttributeArchive), ver, rec); err != nil {
		t.Fatalf("insert file: %v", err)
	}

	if _, err := srv.userSave.BuildFilesList(ctx, uid); err != nil {
		t.Fatalf("build files list: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/UserData/userSaveList?uid=%d", ts.URL, uid), nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "stream/fileslist" {
		t.Fatalf("unexpected content type: %s", ct)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	file, err := listdata.Parse(data)
	if err != nil {
		t.Fatalf("parse list: %v", err)
	}
	entries := file.CloneEntries()
	if len(entries) == 0 {
		t.Fatalf("expected entries in list")
	}
}

func TestUserDataLostFileByHash(t *testing.T) {
	ctx := context.Background()
	srv, ts := newUserDataTestServer(t)

	uid := uint32(5005)
	rid := uint32(31)
	ver := time.Now().UnixMilli()
	rec := ver + 500
	hash := strings.Repeat("b", 40)

	historyInsert := `INSERT INTO history (uid, rid, ver, rec_time, name, size, inuse) VALUES (?, ?, ?, ?, ?, ?, 1)`
	if err := srv.userSave.Exec(ctx, historyInsert, uid, rid, ver, rec, "slot", int64(7)); err != nil {
		t.Fatalf("insert history: %v", err)
	}

	filesInsert := `INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if err := srv.userSave.Exec(ctx, filesInsert, uid, rid, fmt.Sprintf("%d\\folder\\lost.dat", rid), int64(10), hash, time.Now().UTC().UnixNano()/100, uint32(listdata.FileAttributeArchive), ver, rec); err != nil {
		t.Fatalf("insert file: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/UserData/lostFile?hash=%s", ts.URL, hash), nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("lost file request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lost file status: %d", resp.StatusCode)
	}

	var payload struct {
		Code int            `json:"code"`
		Data map[string]int `json:"data"`
		Msg  string         `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Code != 0 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if payload.Data["deldb"] == 0 {
		t.Fatalf("expected deletion count")
	}
	if _, ok := payload.Data[strconv.FormatUint(uint64(uid), 10)]; !ok {
		t.Fatalf("missing uid result")
	}

	if code, err := srv.userSave.RefreshUserList(ctx, uid); err != nil {
		t.Fatalf("refresh list: %v", err)
	} else if code != 0 && code != 2 {
		t.Fatalf("unexpected refresh code: %d", code)
	}
}

func TestUserDataLostFileByUID(t *testing.T) {
	ctx := context.Background()
	srv, ts := newUserDataTestServer(t)

	uid := uint32(6006)
	rid := uint32(41)
	ver := time.Now().UnixMilli()
	rec := ver + 800
	hash := strings.Repeat("c", 40)

	historyInsert := `INSERT INTO history (uid, rid, ver, rec_time, name, size, inuse) VALUES (?, ?, ?, ?, ?, ?, 1)`
	if err := srv.userSave.Exec(ctx, historyInsert, uid, rid, ver, rec, "slot", int64(5)); err != nil {
		t.Fatalf("insert history: %v", err)
	}

	filesInsert := `INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if err := srv.userSave.Exec(ctx, filesInsert, uid, rid, fmt.Sprintf("%d\\folder\\missing.dat", rid), int64(12), hash, time.Now().UTC().UnixNano()/100, uint32(listdata.FileAttributeArchive), ver, rec); err != nil {
		t.Fatalf("insert file: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/UserData/lostFile?uid=%d", ts.URL, uid), nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("lost file request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lost file status: %d", resp.StatusCode)
	}

	var payload struct {
		Code int            `json:"code"`
		Data map[string]int `json:"data"`
		Msg  string         `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Code != 0 {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	uidKey := strconv.FormatUint(uint64(uid), 10)
	result, ok := payload.Data[uidKey]
	if !ok {
		t.Fatalf("missing uid result")
	}
	if result != 0 && result != 2 {
		t.Fatalf("unexpected result code: %d", result)
	}
}
func TestUserDataClearupRemovesStaleArchive(t *testing.T) {
	srv, ts := newUserDataTestServer(t)

	dirs := srv.storage.ArchiveDirs()
	if len(dirs) == 0 {
		t.Fatalf("no archive directories")
	}
	hash := strings.Repeat("d", 40)
	archivePath := filepath.Join(dirs[0], hash[:2], hash[2:4])
	if err := os.MkdirAll(archivePath, 0o755); err != nil {
		t.Fatalf("mkdir archive: %v", err)
	}
	target := filepath.Join(archivePath, hash)
	if err := os.WriteFile(target, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	oldTime := time.Now().AddDate(0, 0, -120)
	if err := os.Chtimes(target, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/UserData/clearup", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("clearup request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clearup status: %d", resp.StatusCode)
	}

	var payload struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Code != 0 {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("archive file still present: %v", err)
	}
}

func TestUserDataClearupRemovesDatabaseState(t *testing.T) {
	ctx := context.Background()
	srv, ts := newUserDataTestServer(t)

	uid := uint32(8080)
	rid := uint32(42)
	ver := time.Now().UnixMilli()
	rec := ver + 500
	hash := strings.Repeat("f", 40)

	historyInsert := `INSERT INTO history (uid, rid, ver, rec_time, name, size, capture, comment, "add", inuse) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`
	if err := srv.userSave.Exec(ctx, historyInsert, uid, rid, ver, rec, "slot", int64(32), "cap", "note", "extra"); err != nil {
		t.Fatalf("insert history: %v", err)
	}

	filesInsert := `INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	filePath := fmt.Sprintf("%d\\folder\\arch.dat", rid)
	creation := time.Now().UTC().UnixNano() / 100
	if err := srv.userSave.Exec(ctx, filesInsert, uid, rid, filePath, int64(64), hash, creation, uint32(listdata.FileAttributeArchive), ver, rec); err != nil {
		t.Fatalf("insert file: %v", err)
	}

	dirs := srv.storage.ArchiveDirs()
	if len(dirs) == 0 {
		t.Fatalf("no archive directory configured")
	}
	archiveDir := filepath.Join(dirs[0], hash[:2], hash[2:4])
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatalf("mkdir archive dir: %v", err)
	}
	archivePath := filepath.Join(archiveDir, hash)
	if err := os.WriteFile(archivePath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write archive file: %v", err)
	}
	oldTime := time.Now().AddDate(0, 0, -120)
	if err := os.Chtimes(archivePath, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	pictureDir := filepath.Dir(srv.userSave.UserListFilePath(uid))
	if err := os.MkdirAll(pictureDir, 0o755); err != nil {
		t.Fatalf("mkdir picture dir: %v", err)
	}
	picturePath := filepath.Join(pictureDir, fmt.Sprintf("%d.%d.jpg", rid, ver))
	if err := os.WriteFile(picturePath, []byte("pic"), 0o644); err != nil {
		t.Fatalf("write picture: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/UserData/clearup?keep_days=1", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("clearup request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clearup status: %d", resp.StatusCode)
	}
	var payload struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Code != 0 {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	if _, err := os.Stat(archivePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archive file still present: %v", err)
	}
	if _, err := os.Stat(picturePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("picture still present: %v", err)
	}

	listPath := srv.userSave.UserListFilePath(uid)
	userDir := filepath.Dir(listPath)
	userListRoot := filepath.Dir(userDir)
	dataDir := filepath.Dir(userListRoot)
	archDBPath := filepath.Join(dataDir, "Arch.db")
	db, err := sql.Open("sqlite", archDBPath)
	if err != nil {
		t.Fatalf("open arch db: %v", err)
	}
	defer db.Close()
	row := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM files WHERE hash=?`, hash)
	var count int
	if err := row.Scan(&count); err != nil {
		t.Fatalf("scan files: %v", err)
	}
	if count != 0 {
		t.Fatalf("files entry still present")
	}

	row = db.QueryRowContext(ctx, `SELECT COUNT(1) FROM DelRecord WHERE hash=?`, hash)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("scan delrecord: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected delrecord entry")
	}
}
