package server

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"saveserver/nvfiles"
	"saveserver/nvservice/storage"
)

func TestUserSaveQueryEndpoints(t *testing.T) {
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
	srv.dataCenterURL = ""
	srv.httpClient = nil

	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	uid := uint32(4242)
	rid := uint32(7)
	ver := time.Now().UnixMilli()
	recTime := ver + 1234

	historyInsert := `INSERT INTO history ("rid", "uid", "ver", "rec_time", "name", "size", "capture", "comment", "add", "inuse") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`
	if err := srv.userSave.Exec(ctx, historyInsert, rid, uid, ver, recTime, "slot-1", int64(11), "cap", "note", "extra"); err != nil {
		t.Fatalf("insert history: %v", err)
	}

	fileCreation := (time.Now().UTC().Unix()+11644473600)*10_000_000 + int64(time.Now().UTC().Nanosecond()/100)
	hash := sha1.Sum([]byte("content"))
	hashHex := hex.EncodeToString(hash[:])
	fileInsert := `INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if err := srv.userSave.Exec(ctx, fileInsert, uid, rid, "7\\folder\\save.dat", int64(len("content")), hashHex, fileCreation, uint32(32), ver, recTime); err != nil {
		t.Fatalf("insert file: %v", err)
	}

	if _, err := srv.userSave.HistoryRecords(ctx, uid, rid, true); err != nil {
		t.Logf("HistoryRecords error: %v", err)
		if cause := errors.Unwrap(err); cause != nil {
			t.Logf("HistoryRecords cause: %v", cause)
		}
		t.Fatalf("history records lookup failed")
	}
	token := makeAuthToken(uid)
	historyCtx, historyCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer historyCancel()
	records, err := srv.userSave.HistoryRecords(historyCtx, uid, rid, true)
	if err != nil {
		t.Logf("HistoryRecords query error: %v", err)
		if cause := errors.Unwrap(err); cause != nil {
			t.Logf("HistoryRecords query cause: %v", cause)
		}
		t.Fatalf("history records query failed")
	}
	if len(records) == 0 {
		t.Fatalf("expected history records")
	}
	historyID := records[0].ID
	t.Logf("history records: %+v", records)
	client := ts.Client()

	waitTaskStatus := func(endpoint, taskID string) int {
		deadline := time.Now().Add(2 * time.Second)
		for {
			req, _ := http.NewRequest(http.MethodGet, ts.URL+endpoint+"?task_id="+url.QueryEscape(taskID), nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("task request (%s): %v", endpoint, err)
			}
			var payload struct {
				Code int    `json:"code"`
				Msg  string `json:"msg"`
				Data []struct {
					TaskID string `json:"task_id"`
					Status int    `json:"status"`
					Err    string `json:"err"`
				} `json:"data"`
			}
			func() {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("task status (%s): %d", endpoint, resp.StatusCode)
				}
				if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
					t.Fatalf("decode task (%s): %v", endpoint, err)
				}
			}()
			if payload.Code != 0 {
				t.Fatalf("task payload (%s): %+v", endpoint, payload)
			}
			if len(payload.Data) > 0 {
				status := payload.Data[0].Status
				if status == 2 || status == 3 {
					return status
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("task poll timeout for %s (%s)", taskID, endpoint)
			}
			time.Sleep(50 * time.Millisecond)
		}
		return 0
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status: %d", resp.StatusCode)
	}
	var listPayload struct {
		Code int           `json:"code"`
		Msg  string        `json:"msg"`
		Data []interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listPayload.Code != 0 || len(listPayload.Data) != 1 {
		t.Fatalf("unexpected list payload: %+v", listPayload)
	}

	hReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/history?rid="+strconv.Itoa(int(rid))+"&show_files=1", nil)
	hReq.Header.Set("Authorization", "Bearer "+token)
	hResp, err := client.Do(hReq)
	if err != nil {
		t.Fatalf("history request: %v", err)
	}
	t.Cleanup(func() { _ = hResp.Body.Close() })
	if hResp.StatusCode != http.StatusOK {
		t.Fatalf("history status: %d", hResp.StatusCode)
	}
	var historyPayload struct {
		Code int               `json:"code"`
		Msg  string            `json:"msg"`
		Data []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(hResp.Body).Decode(&historyPayload); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if historyPayload.Code != 0 || len(historyPayload.Data) == 0 {
		t.Fatalf("unexpected history payload: %+v", historyPayload)
	}

	sReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/SaveInfo", nil)
	sReq.Header.Set("Authorization", "Bearer "+token)
	sResp, err := client.Do(sReq)
	if err != nil {
		t.Fatalf("save info request: %v", err)
	}
	t.Cleanup(func() { _ = sResp.Body.Close() })
	if sResp.StatusCode != http.StatusOK {
		t.Fatalf("save info status: %d", sResp.StatusCode)
	}
	var saveInfoPayload struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(sResp.Body).Decode(&saveInfoPayload); err != nil {
		t.Fatalf("decode save info: %v", err)
	}
	if saveInfoPayload.Code != 0 || len(saveInfoPayload.Data) == 0 {
		t.Fatalf("unexpected save info payload")
	}

	tempBase, err := srv.userSave.UserTempDir(uid, true)
	if err != nil {
		t.Fatalf("prepare temp dir: %v", err)
	}
	tempRidDir := filepath.Join(tempBase, strconv.Itoa(int(rid)), "folder")
	if err := os.MkdirAll(tempRidDir, 0o755); err != nil {
		t.Fatalf("mkdir temp rid dir: %v", err)
	}
	tempFile := filepath.Join(tempRidDir, "unsaved.txt")
	if err := os.WriteFile(tempFile, []byte("unsaved"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	reqDelPath := filepath.Join(tempBase, strconv.Itoa(int(rid))+".reqdel")
	if err := os.WriteFile(reqDelPath, []byte("folder\\old.txt|\r\n"), 0o644); err != nil {
		t.Fatalf("write reqdel: %v", err)
	}

	uReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/UnSaveInfo?rid="+strconv.Itoa(int(rid)), nil)
	uReq.Header.Set("Authorization", "Bearer "+token)
	uResp, err := client.Do(uReq)
	if err != nil {
		t.Fatalf("unsave info request: %v", err)
	}
	t.Cleanup(func() { _ = uResp.Body.Close() })
	if uResp.StatusCode != http.StatusOK {
		t.Fatalf("unsave info status: %d", uResp.StatusCode)
	}
	var unsavePayload struct {
		Code int `json:"code"`
	}
	if err := json.NewDecoder(uResp.Body).Decode(&unsavePayload); err != nil {
		t.Fatalf("decode unsave info: %v", err)
	}
	if unsavePayload.Code != 0 {
		t.Fatalf("unexpected unsave info payload: %+v", unsavePayload)
	}

	renameReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/name?id="+strconv.FormatInt(historyID, 10)+"&name="+url.QueryEscape("renamed-slot"), nil)
	renameReq.Header.Set("Authorization", "Bearer "+token)
	renameResp, err := client.Do(renameReq)
	if err != nil {
		t.Fatalf("rename request: %v", err)
	}
	t.Cleanup(func() { _ = renameResp.Body.Close() })
	if renameResp.StatusCode != http.StatusOK {
		t.Fatalf("rename status: %d", renameResp.StatusCode)
	}
	var renamePayload struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(renameResp.Body).Decode(&renamePayload); err != nil {
		t.Fatalf("decode rename: %v", err)
	}
	if renamePayload.Code != 0 {
		t.Fatalf("unexpected rename payload: %+v", renamePayload)
	}
	renamedRecords, err := srv.userSave.HistoryRecords(ctx, uid, rid, true)
	if err != nil {
		t.Fatalf("history after rename: %v", err)
	}
	if len(renamedRecords) == 0 || renamedRecords[0].Name != "renamed-slot" {
		t.Fatalf("rename not applied: %+v", renamedRecords)
	}

	deleteReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/delete?id="+strconv.FormatInt(historyID, 10), nil)
	deleteReq.Header.Set("Authorization", "Bearer "+token)
	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	t.Cleanup(func() { _ = deleteResp.Body.Close() })
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status: %d", deleteResp.StatusCode)
	}
	var deletePayload struct {
		Code int `json:"code"`
	}
	if err := json.NewDecoder(deleteResp.Body).Decode(&deletePayload); err != nil {
		t.Fatalf("decode delete: %v", err)
	}
	if deletePayload.Code != 0 {
		t.Fatalf("unexpected delete payload: %+v", deletePayload)
	}
	deletedRecords, err := srv.userSave.HistoryRecords(ctx, uid, rid, true)
	if err != nil {
		t.Fatalf("history after delete: %v", err)
	}
	if len(deletedRecords) != 0 {
		t.Fatalf("expected no history after delete: %+v", deletedRecords)
	}

	listReq2, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/list", nil)
	listReq2.Header.Set("Authorization", "Bearer "+token)
	listResp2, err := client.Do(listReq2)
	if err != nil {
		t.Fatalf("list2 request: %v", err)
	}
	t.Cleanup(func() { _ = listResp2.Body.Close() })
	if listResp2.StatusCode != http.StatusOK {
		t.Fatalf("list2 status: %d", listResp2.StatusCode)
	}
	var listPayload2 struct {
		Code int           `json:"code"`
		Msg  string        `json:"msg"`
		Data []interface{} `json:"data"`
	}
	if err := json.NewDecoder(listResp2.Body).Decode(&listPayload2); err != nil {
		t.Fatalf("decode list2: %v", err)
	}
	if listPayload2.Code != 0 {
		t.Fatalf("unexpected list2 payload: %+v", listPayload2)
	}

	unsaveStartReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/unsave?rid="+strconv.Itoa(int(rid)), nil)
	unsaveStartReq.Header.Set("Authorization", "Bearer "+token)
	unsaveStartResp, err := client.Do(unsaveStartReq)
	if err != nil {
		t.Fatalf("unsave start request: %v", err)
	}
	t.Cleanup(func() { _ = unsaveStartResp.Body.Close() })
	if unsaveStartResp.StatusCode != http.StatusOK {
		t.Fatalf("unsave start status: %d", unsaveStartResp.StatusCode)
	}
	var unsaveStartPayload struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			TaskID string `json:"task_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(unsaveStartResp.Body).Decode(&unsaveStartPayload); err != nil {
		t.Fatalf("decode unsave start: %v", err)
	}
	if unsaveStartPayload.Code != 0 || unsaveStartPayload.Data.TaskID == "" {
		t.Fatalf("unexpected unsave start payload: %+v", unsaveStartPayload)
	}
	waitTaskStatus("/UserSave/saveTask", unsaveStartPayload.Data.TaskID)
	if _, err := os.Stat(tempFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file not cleaned: %v", err)
	}
	if _, err := os.Stat(reqDelPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reqdel not removed: %v", err)
	}

	saveRid := uint32(9)
	saveDir := filepath.Join(tempBase, strconv.Itoa(int(saveRid)), "slot")
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		t.Fatalf("mkdir save dir: %v", err)
	}
	saveFile := filepath.Join(saveDir, "new.txt")
	if err := os.WriteFile(saveFile, []byte("new data"), 0o644); err != nil {
		t.Fatalf("write save temp: %v", err)
	}
	saveStartReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/UserSave/save?rid="+strconv.Itoa(int(saveRid)), nil)
	saveStartReq.Header.Set("Authorization", "Bearer "+token)
	saveStartResp, err := client.Do(saveStartReq)
	if err != nil {
		t.Fatalf("save start request: %v", err)
	}
	t.Cleanup(func() { _ = saveStartResp.Body.Close() })
	if saveStartResp.StatusCode != http.StatusOK {
		t.Fatalf("save start status: %d", saveStartResp.StatusCode)
	}
	var saveStartPayload struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			TaskID string `json:"task_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(saveStartResp.Body).Decode(&saveStartPayload); err != nil {
		t.Fatalf("decode save start: %v", err)
	}
	if saveStartPayload.Code != 0 || saveStartPayload.Data.TaskID == "" {
		t.Fatalf("unexpected save start payload: %+v", saveStartPayload)
	}
	waitTaskStatus("/UserSave/saveTask", saveStartPayload.Data.TaskID)
	if _, err := os.Stat(saveFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("save temp file still present: %v", err)
	}
	saveHistory, err := srv.userSave.HistoryRecords(ctx, uid, saveRid, true)
	if err != nil {
		t.Fatalf("history after save: %v", err)
	}
	if len(saveHistory) == 0 {
		t.Fatalf("expected history entries for rid %d", saveRid)
	}
	expectedPath := fmt.Sprintf("%d\\slot\\new.txt", saveRid)
	found := false
	for _, rec := range saveHistory {
		if rec.RID != saveRid {
			continue
		}
		for _, f := range rec.Files {
			if f.Path == expectedPath {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatalf("expected archived file %s in history", expectedPath)
	}
}

func makeAuthToken(uid uint32) string {
	header := base64.StdEncoding.EncodeToString([]byte("{}"))
	payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("{\"uid\":%d}", uid)))
	signature := base64.StdEncoding.EncodeToString([]byte("sig"))
	return header + "." + payload + "." + signature
}
