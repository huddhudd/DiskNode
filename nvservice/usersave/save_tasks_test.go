package usersave

import (
	"context"
	"database/sql"
	"encoding/hex"
	"sync"
	"testing"
	"time"
)

func insertHistory(t *testing.T, svc *Service, ctx context.Context, uid, rid uint32, ver int64, inuse int, name string) int64 {
	t.Helper()
	var id int64
	err := svc.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO history (uid, rid, ver, rec_time, name, size, inuse) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			uid, rid, ver, ver, name, int64(1024), inuse)
		if err != nil {
			return err
		}
		newID, err := res.LastInsertId()
		if err != nil {
			return err
		}
		id = newID
		return nil
	})
	if err != nil {
		t.Fatalf("insert history: %v", err)
	}
	return id
}

func insertFileRecordTest(t *testing.T, svc *Service, ctx context.Context, uid, rid uint32, ver int64, path string) {
	t.Helper()
	hashBytes := make([]byte, 20)
	for i := range hashBytes {
		hashBytes[i] = byte(i)
	}
	hash := hex.EncodeToString(hashBytes)
	if err := svc.Exec(ctx, `INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uid, rid, path, int64(len(path)), hash, time.Now().Unix(), uint32(32), ver, ver); err != nil {
		t.Fatalf("insert file: %v", err)
	}
}

func waitForTaskStatus(t *testing.T, fetch func() []TaskStatus) TaskStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		statuses := fetch()
		if len(statuses) > 0 {
			st := statuses[0]
			if st.Status == taskStatusSuccess || st.Status == taskStatusFailed {
				return st
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("task did not complete in time")
	return TaskStatus{}
}

func assertHistoryInUse(t *testing.T, svc *Service, ctx context.Context, uid uint32, id int64, want bool) {
	t.Helper()
	db, err := svc.dbConn()
	if err != nil {
		t.Fatalf("db conn: %v", err)
	}
	var inuse int
	row := db.QueryRowContext(ctx, `SELECT inuse FROM history WHERE uid=? AND id=?`, uid, id)
	if err := row.Scan(&inuse); err != nil {
		t.Fatalf("scan inuse: %v", err)
	}
	if (inuse != 0) != want {
		t.Fatalf("history %d inuse=%d want %v", id, inuse, want)
	}
}

func TestRunUseTaskWithExistingHistory(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	uid := uint32(123)
	rid := uint32(7)

	oldID := insertHistory(t, svc, ctx, uid, rid, time.Now().Add(-time.Hour).UnixMilli(), 1, "old")
	newVer := time.Now().UnixMilli()
	newID := insertHistory(t, svc, ctx, uid, rid, newVer, 0, "new")
	insertFileRecordTest(t, svc, ctx, uid, rid, newVer, "7\\save.dat")

	taskID, _, err := svc.StartUse(uid, newID, 0, "")
	if err != nil {
		t.Fatalf("start use: %v", err)
	}

	status := waitForTaskStatus(t, func() []TaskStatus { return svc.UseTaskStatuses(uid, taskID) })
	if status.Status != taskStatusSuccess {
		t.Fatalf("unexpected status: %+v", status)
	}

	assertHistoryInUse(t, svc, ctx, uid, newID, true)
	assertHistoryInUse(t, svc, ctx, uid, oldID, false)
}

type fakeShareDownloader struct {
	result *DownloadShareResult
}

func (f *fakeShareDownloader) Download(ctx context.Context, req *DownloadShareRequest) (*DownloadShareResult, error) {
	if f.result == nil {
		return nil, &TaskFailure{Message: "拉取存档失败，请稍候再试！0x1"}
	}
	return f.result, nil
}

func TestRunUseTaskWithShareDownloader(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	uid := uint32(234)
	rid := uint32(9)

	downloader := &fakeShareDownloader{
		result: &DownloadShareResult{
			RID: rid,
			Info: ShareInfo{
				Name:    "shared",
				Comment: "note",
				Add:     "extra",
			},
			Files: []DownloadShareFile{{
				Path:     "9\\slot\\save.dat",
				Size:     2048,
				Hash:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Attr:     32,
				Creation: time.Now().Unix(),
			}},
		},
	}
	svc.SetShareDownloader(downloader)

	taskID, _, err := svc.StartUse(uid, 0, 555, "token")
	if err != nil {
		t.Fatalf("start use share: %v", err)
	}

	status := waitForTaskStatus(t, func() []TaskStatus { return svc.UseTaskStatuses(uid, taskID) })
	if status.Status != taskStatusSuccess {
		t.Fatalf("unexpected status: %+v", status)
	}

	// Verify history inserted
	db, err := svc.dbConn()
	if err != nil {
		t.Fatalf("db conn: %v", err)
	}
	row := db.QueryRowContext(ctx, `SELECT id, name FROM history WHERE uid=? ORDER BY id DESC LIMIT 1`, uid)
	var id int64
	var name string
	if err := row.Scan(&id, &name); err != nil {
		t.Fatalf("scan history: %v", err)
	}
	if name != "shared" {
		t.Fatalf("unexpected history name %q", name)
	}
	if status.UseID != 0 {
		t.Fatalf("expected UseID to remain 0 for share use, got %+v", status)
	}
	if status.ShareID != 555 {
		t.Fatalf("expected ShareID 555, got %+v", status)
	}
	if status.HistoryID == 0 {
		t.Fatalf("expected non-zero history id after share use: %+v", status)
	}

	taskID2, reused, err := svc.StartUse(uid, 0, 555, "token2")
	if err != nil {
		t.Fatalf("restart share use: %v", err)
	}
	if !reused {
		t.Fatalf("expected task reuse on second start")
	}
	if taskID2 != taskID {
		t.Fatalf("task id changed across reuse: %q vs %q", taskID2, taskID)
	}

	status2 := waitForTaskStatus(t, func() []TaskStatus { return svc.UseTaskStatuses(uid, taskID2) })
	if status2.Status != taskStatusSuccess {
		t.Fatalf("unexpected status after reuse: %+v", status2)
	}
	if status2.UseID != 0 {
		t.Fatalf("expected UseID to remain 0 after reuse: %+v", status2)
	}
	if status2.ShareID != 555 {
		t.Fatalf("expected ShareID to remain 555: %+v", status2)
	}
	if status2.HistoryID == 0 {
		t.Fatalf("expected non-zero history id after reuse: %+v", status2)
	}
}

type recordingShareClient struct {
	mu  sync.Mutex
	req *ShareRequest
	err error
}

func (r *recordingShareClient) Share(ctx context.Context, req *ShareRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.req = req
	if req != nil && req.Progress != nil {
		var uploaded int64
		for _, f := range req.Files {
			uploaded += f.Size
		}
		req.Progress(uploaded, int64(len(req.Files)))
	}
	return r.err
}

func (r *recordingShareClient) Request() *ShareRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.req
}

func (r *recordingShareClient) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.req = nil
}

func TestRunShareTaskInvokesClient(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	uid := uint32(321)
	rid := uint32(11)
	ver := time.Now().UnixMilli()
	historyID := insertHistory(t, svc, ctx, uid, rid, ver, 1, "slot")
	insertFileRecordTest(t, svc, ctx, uid, rid, ver, "11\\slot\\save.dat")

	client := &recordingShareClient{}
	svc.SetShareClient(client)

	params := `{"name":"updated","comment":"c","add":"a"}`
	taskID, restarted, err := svc.StartShare(uid, rid, historyID, 999, "token", params)
	if err != nil {
		t.Fatalf("start share: %v", err)
	}
	if restarted {
		t.Fatalf("unexpected reuse flag on first start")
	}

	status := waitForTaskStatus(t, func() []TaskStatus { return svc.ShareTaskStatuses(uid, taskID) })
	if status.Status != taskStatusSuccess {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.Name != "updated" {
		t.Fatalf("status name mismatch: %+v", status)
	}
	if status.Comment != "c" {
		t.Fatalf("status comment mismatch: %+v", status)
	}
	if status.Add != "a" {
		t.Fatalf("status add mismatch: %+v", status)
	}
	if status.Files != 1 || status.FilesUploaded != 1 {
		t.Fatalf("unexpected file counters: %+v", status)
	}
	if status.Uploaded <= 0 {
		t.Fatalf("uploaded bytes not recorded: %+v", status)
	}
	if status.Version != ver {
		t.Fatalf("status version mismatch: %+v", status)
	}
	if status.RecTime != ver {
		t.Fatalf("status rectime mismatch: %+v", status)
	}
	if status.HistoryID != historyID {
		t.Fatalf("status history id mismatch: %+v", status)
	}
	if status.ShareID != 999 {
		t.Fatalf("status share id mismatch: %+v", status)
	}

	req := client.Request()
	if req == nil {
		t.Fatalf("share client not invoked")
	}
	if req.Info.Name != "updated" || req.Info.Comment != "c" || req.Info.Add != "a" {
		t.Fatalf("override name/comment/add not applied: %+v", req.Info)
	}
	if req.Token != "token" {
		t.Fatalf("share token mismatch: %+v", req)
	}
	if len(req.Files) != 1 {
		t.Fatalf("expected files in share request")
	}
	if req.HistoryID != historyID {
		t.Fatalf("history id mismatch: got %d want %d", req.HistoryID, historyID)
	}

	client.Clear()
	params2 := `{"name":"second","comment":"d"}`
	taskID2, reused, err := svc.StartShare(uid, rid, historyID, 1234, "token2", params2)
	if err != nil {
		t.Fatalf("restart share: %v", err)
	}
	if !reused {
		t.Fatalf("expected task reuse on second start")
	}
	if taskID2 != taskID {
		t.Fatalf("task id changed across reuse: %q vs %q", taskID2, taskID)
	}

	status = waitForTaskStatus(t, func() []TaskStatus { return svc.ShareTaskStatuses(uid, taskID2) })
	if status.Status != taskStatusSuccess {
		t.Fatalf("unexpected status after reuse: %+v", status)
	}
	if status.Name != "second" {
		t.Fatalf("reuse status name mismatch: %+v", status)
	}
	if status.Comment != "d" {
		t.Fatalf("reuse status comment mismatch: %+v", status)
	}
	if status.Add != "" {
		t.Fatalf("reuse status add expected empty: %+v", status)
	}
	if status.ShareID != 1234 {
		t.Fatalf("reuse share id mismatch: %+v", status)
	}
	if status.Files != 1 || status.FilesUploaded != 1 {
		t.Fatalf("unexpected file counters after reuse: %+v", status)
	}
	if status.Uploaded <= 0 {
		t.Fatalf("uploaded bytes not recorded after reuse: %+v", status)
	}

	req = client.Request()
	if req == nil {
		t.Fatalf("share client not invoked on reuse")
	}
	if req.Token != "token2" {
		t.Fatalf("reuse share token mismatch: %+v", req)
	}
	if req.ShareID != 1234 {
		t.Fatalf("reuse share id mismatch: %+v", req)
	}
	if req.Info.Name != "second" || req.Info.Comment != "d" {
		t.Fatalf("reuse override mismatch: %+v", req.Info)
	}
}
