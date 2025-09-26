package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

const userSaveRequestTimeout = 10 * time.Second

func (s *Server) handleUserSave(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/UserSave")
	rel = strings.TrimPrefix(rel, "/")
	rel = path.Clean(rel)
	if rel == "." {
		http.NotFound(w, r)
		return
	}

	switch {
	case strings.EqualFold(rel, "list"):
		s.handleUserSaveList(w, r)
	case strings.HasPrefix(strings.ToLower(rel), "history"):
		s.handleUserSaveHistory(w, r)
	case strings.EqualFold(rel, "saveinfo"):
		s.handleUserSaveSaveInfo(w, r)
	case strings.EqualFold(rel, "unsaveinfo"):
		s.handleUserSaveUnsaveInfo(w, r)
	case strings.EqualFold(rel, "delete"):
		s.handleUserSaveDelete(w, r)
	case strings.EqualFold(rel, "name"):
		s.handleUserSaveRename(w, r)
	case strings.EqualFold(rel, "save"):
		s.handleUserSaveSave(w, r, false)
	case strings.EqualFold(rel, "unsave"):
		s.handleUserSaveSave(w, r, true)
	case strings.EqualFold(rel, "savetask"):
		s.handleUserSaveSaveTask(w, r)
	case strings.EqualFold(rel, "use"):
		s.handleUserSaveUse(w, r)
	case strings.EqualFold(rel, "usetask"):
		s.handleUserSaveUseTask(w, r)
	case strings.EqualFold(rel, "share"):
		s.handleUserSaveShare(w, r)
	case strings.EqualFold(rel, "sharetask"):
		s.handleUserSaveShareTask(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleUserSaveList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), userSaveRequestTimeout)
	defer cancel()

	items, err := s.userSave.ListSaves(ctx, uid)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "database error"})
		return
	}

	data := make([]map[string]any, 0, len(items))
	for _, item := range items {
		row := map[string]any{
			"uid":      uid,
			"rid":      item.RID,
			"ver":      item.Version,
			"rec_time": item.RecTime,
			"size":     item.Size,
			"path":     fmt.Sprintf("\\\\Users\\\\Save\\\\%d\\\\%d", uid, item.RID),
			"pic":      fmt.Sprintf("UserSave/ArchivePic/%d/%d.%d.jpg", uid, item.RID, item.Version),
		}
		data = append(data, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

func (s *Server) handleUserSaveHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	ridParam := strings.TrimSpace(r.URL.Query().Get("rid"))
	if ridParam == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}
	ridVal, err := strconv.ParseUint(ridParam, 10, 32)
	if err != nil || ridVal == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}
	showFiles := strings.TrimSpace(r.URL.Query().Get("show_files")) == "1"

	ctx, cancel := context.WithTimeout(r.Context(), userSaveRequestTimeout)
	defer cancel()

	records, err := s.userSave.HistoryRecords(ctx, uid, uint32(ridVal), showFiles)
	if err != nil {
		switch {
		case errors.Is(err, s.userSave.ErrHistoryQuery()):
			writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "db error"})
		case errors.Is(err, s.userSave.ErrHistoryFilesQuery()):
			writeJSON(w, http.StatusOK, map[string]any{"code": 3, "msg": "db error"})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"code": 3, "msg": "db error"})
		}
		return
	}

	data := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		row := map[string]any{
			"id":       rec.ID,
			"uid":      uid,
			"rid":      rec.RID,
			"ver":      rec.Version,
			"rec_time": rec.RecTime,
			"name":     rec.Name,
			"size":     rec.Size,
			"capture":  rec.Capture,
			"comment":  rec.Comment,
			"add":      rec.Add,
			"inuse":    rec.InUse,
			"pic":      fmt.Sprintf("UserSave/ArchivePic/%d/%d.%d.jpg", uid, rec.RID, rec.Version),
		}
		if showFiles && len(rec.Files) > 0 {
			files := make([]map[string]any, 0, len(rec.Files))
			for _, f := range rec.Files {
				files = append(files, map[string]any{
					"file": f.Path,
					"size": f.Size,
					"time": f.Time,
				})
			}
			row["files"] = files
		}
		data = append(data, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

func (s *Server) handleUserSaveSaveInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	ridParam := strings.TrimSpace(r.URL.Query().Get("rid"))
	var ridVal uint64
	if ridParam != "" {
		ridVal, err = strconv.ParseUint(ridParam, 10, 32)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), userSaveRequestTimeout)
	defer cancel()

	info, err := s.userSave.GetSaveInfo(ctx, uid, uint32(ridVal))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "failed"})
		return
	}
	if len(info) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 4, "msg": "failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": json.RawMessage(info),
	})
}

func (s *Server) handleUserSaveUnsaveInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	ridParam := strings.TrimSpace(r.URL.Query().Get("rid"))
	var ridVal uint64
	if ridParam != "" {
		ridVal, err = strconv.ParseUint(ridParam, 10, 32)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), userSaveRequestTimeout)
	defer cancel()

	details, err := s.userSave.UnsaveInfo(ctx, uid, uint32(ridVal))
	if err != nil {
		if errors.Is(err, s.userSave.ErrTempDirMissing()) {
			writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "tmp dir is empty"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"code": 4, "msg": "failed"})
		return
	}

	files := make(map[string][]map[string]any)
	for rid, entries := range details.Files {
		ridKey := fmt.Sprintf("%d", rid)
		for _, entry := range entries {
			files[ridKey] = append(files[ridKey], map[string]any{
				"file": entry.Path,
				"size": entry.Size,
				"time": entry.Time,
			})
		}
	}

	delfiles := make(map[string][]string)
	for name, list := range details.DelFiles {
		delfiles[name] = append([]string(nil), list...)
	}

	payload := map[string]any{
		"code": 0,
		"data": map[string]any{
			"unsaved": map[string]any{
				"files":       files,
				"total_size":  details.TotalSize,
				"total_files": details.TotalFiles,
				"delfiles":    delfiles,
			},
		},
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleUserSaveDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	idParam := strings.TrimSpace(r.URL.Query().Get("id"))
	if idParam == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}
	idVal, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil || idVal <= 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), userSaveRequestTimeout)
	defer cancel()

	if _, _, err := s.userSave.DeleteHistoryRecord(ctx, uid, idVal); err != nil {
		switch {
		case errors.Is(err, s.userSave.ErrHistoryNotFound()):
			writeJSON(w, http.StatusOK, map[string]any{"code": 4, "msg": "\u8be5\u5b58\u6863\u4e0d\u5b58\u5728!"})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "db error"})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) handleUserSaveRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	idParam := strings.TrimSpace(r.URL.Query().Get("id"))
	nameParam := r.URL.Query().Get("name")
	if idParam == "" || nameParam == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}
	idVal, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil || idVal <= 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), userSaveRequestTimeout)
	defer cancel()

	if err := s.userSave.RenameHistoryRecord(ctx, uid, idVal, nameParam); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "db error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) handleUserSaveSave(w http.ResponseWriter, r *http.Request, unsave bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	ridParam := strings.TrimSpace(r.URL.Query().Get("rid"))
	var ridVal uint64
	if ridParam != "" {
		ridVal, err = strconv.ParseUint(ridParam, 10, 32)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
	}

	var taskID string
	if unsave {
		taskID, _, err = s.userSave.StartUnsave(uid, uint32(ridVal))
	} else {
		taskID, _, err = s.userSave.StartSave(uid, uint32(ridVal))
	}
	if err != nil || taskID == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": map[string]any{"task_id": taskID},
	})
}

func (s *Server) handleUserSaveSaveTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	taskID := strings.TrimSpace(r.URL.Query().Get("task_id"))

	uid, err := s.uidFromRequest(r)
	if err != nil {
		if taskID == "" {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
		uid = 0
	}

	statuses := s.userSave.SaveTaskStatuses(uid, taskID)
	data := make([]map[string]any, 0, len(statuses))
	for _, st := range statuses {
		data = append(data, map[string]any{
			"task_id": st.ID,
			"status":  st.Status,
			"err":     st.Err,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

func (s *Server) handleUserSaveUse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	idParam := strings.TrimSpace(r.URL.Query().Get("id"))
	sidParam := strings.TrimSpace(r.URL.Query().Get("sid"))

	var idVal, sidVal int64
	if idParam != "" {
		if idVal, err = strconv.ParseInt(idParam, 10, 64); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
	}
	if sidParam != "" {
		if sidVal, err = strconv.ParseInt(sidParam, 10, 64); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
	}
	if idVal == 0 && sidVal == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	token, err := s.authTokenFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	taskID, _, err := s.userSave.StartUse(uid, idVal, sidVal, token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": map[string]any{"task_id": taskID},
	})
}

func (s *Server) handleUserSaveUseTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	taskID := strings.TrimSpace(r.URL.Query().Get("task_id"))

	uid, err := s.uidFromRequest(r)
	if err != nil {
		if taskID == "" {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
		uid = 0
	}

	statuses := s.userSave.UseTaskStatuses(uid, taskID)
	data := make([]map[string]any, 0, len(statuses))
	for _, st := range statuses {
		data = append(data, map[string]any{
			"task_id": st.ID,
			"status":  st.Status,
			"err":     st.Err,
			"id":      st.UseID,
			"sid":     st.ShareID,
			"uid":     st.UID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

func (s *Server) handleUserSaveShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, err := s.uidFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	ridParam := strings.TrimSpace(r.URL.Query().Get("rid"))
	idParam := strings.TrimSpace(r.URL.Query().Get("id"))
	sidParam := strings.TrimSpace(r.URL.Query().Get("sid"))

	var (
		ridVal uint64
		idVal  int64
		sidVal int64
	)
	if ridParam != "" {
		if ridVal, err = strconv.ParseUint(ridParam, 10, 32); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
	}
	if idParam != "" {
		if idVal, err = strconv.ParseInt(idParam, 10, 64); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
	}
	if sidParam != "" {
		if sidVal, err = strconv.ParseInt(sidParam, 10, 64); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
	}
	if ridVal == 0 && idVal == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	if idVal == 0 {
		ctx, cancel := context.WithTimeout(r.Context(), userSaveRequestTimeout)
		defer cancel()
		latestID, err := s.userSave.LatestHistoryID(ctx, uid, uint32(ridVal))
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "error"})
			return
		}
		if latestID == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"code": 4, "msg": "该存档不存在!"})
			return
		}
		idVal = latestID
	}

	token, err := s.authTokenFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
		return
	}

	var params string
	if r.Body != nil {
		defer r.Body.Close()
		if body, readErr := io.ReadAll(r.Body); readErr == nil {
			params = string(body)
		}
	}

	taskID, _, err := s.userSave.StartShare(uid, uint32(ridVal), idVal, sidVal, token, params)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": map[string]any{"task_id": taskID},
	})
}

func (s *Server) handleUserSaveShareTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	taskID := strings.TrimSpace(r.URL.Query().Get("task_id"))

	uid, err := s.uidFromRequest(r)
	if err != nil {
		if taskID == "" {
			writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "invalid params"})
			return
		}
		uid = 0
	}

	statuses := s.userSave.ShareTaskStatuses(uid, taskID)
	data := make([]map[string]any, 0, len(statuses))
	for _, st := range statuses {
		data = append(data, map[string]any{
			"task_id":        st.ID,
			"status":         st.Status,
			"err":            st.Err,
			"uid":            st.UID,
			"rid":            st.RID,
			"db_id":          st.HistoryID,
			"sid":            st.ShareID,
			"ver":            st.Version,
			"rec_time":       st.RecTime,
			"name":           st.Name,
			"size":           st.Size,
			"capture":        st.Capture,
			"comment":        st.Comment,
			"add":            st.Add,
			"uploaded":       st.Uploaded,
			"files":          st.Files,
			"files_uploaded": st.FilesUploaded,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}
