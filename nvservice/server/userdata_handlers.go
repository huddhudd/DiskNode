package server

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"os"
)

const maxUserDataPicSize = 1 * 1024 * 1024

type userDataDeleteRequest struct {
	Files []string `json:"files"`
}

func (s *Server) handleUserData(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/UserData")
	rel = strings.TrimPrefix(rel, "/")
	rel = path.Clean(rel)
	if rel == "." {
		http.NotFound(w, r)
		return
	}

	switch {
	case strings.EqualFold(rel, "uploadSave"), strings.EqualFold(rel, "uploadUserSave"):
		s.handleUserDataUploadSave(w, r)
	case strings.EqualFold(rel, "deleteFiles"):
		s.handleUserDataDeleteFiles(w, r)
	case strings.EqualFold(rel, "uploadSavePic"):
		s.handleUserDataUploadSavePic(w, r)
	case strings.EqualFold(rel, "userSaveList"):
		s.handleUserDataList(w, r)
	case strings.EqualFold(rel, "lostFile"):
		s.handleUserDataLostFile(w, r)
	case strings.EqualFold(rel, "clearup"):
		s.handleUserDataClearup(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleUserDataUploadSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	hashParam := strings.ToLower(strings.TrimSpace(q.Get("hash")))
	if len(hashParam) != 40 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}
	if _, err := hex.DecodeString(hashParam); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	uidVal, err := strconv.ParseUint(strings.TrimSpace(q.Get("uid")), 10, 32)
	if err != nil || uidVal == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "invalid params"})
		return
	}
	ridVal, err := strconv.ParseUint(strings.TrimSpace(q.Get("rid")), 10, 32)
	if err != nil || ridVal == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "invalid params"})
		return
	}

	pathParam := q.Get("path")
	if pathParam == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "invalid params"})
		return
	}

	sizeParam := strings.TrimSpace(q.Get("size"))
	var expectedSize int64
	if sizeParam != "" {
		if sizeVal, err := strconv.ParseInt(sizeParam, 10, 64); err == nil && sizeVal >= 0 {
			expectedSize = sizeVal
		} else {
			writeJSON(w, http.StatusOK, map[string]any{"code": 3, "msg": "invalid data len"})
			return
		}
	}

	defer r.Body.Close()

	uid := uint32(uidVal)
	rid := uint32(ridVal)

	tempBase, err := s.userSave.UserTempDir(uid, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	targetDir := tempBase
	if rid != 0 {
		targetDir = filepath.Join(tempBase, strconv.FormatUint(uint64(rid), 10))
	}

	normalized, ok := normalizeUserDataPath(pathParam)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "invalid params"})
		return
	}

	fullPath := filepath.Join(targetDir, normalized)
	cleanTarget := filepath.Clean(targetDir)
	if !strings.HasPrefix(fullPath, cleanTarget+string(os.PathSeparator)) && filepath.Clean(fullPath) != cleanTarget {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "invalid params"})
		return
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	file, err := os.Create(fullPath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	hasher := sha1.New()
	written, err := io.Copy(io.MultiWriter(file, hasher), r.Body)
	if err != nil {
		file.Close()
		_ = os.Remove(fullPath)
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(fullPath)
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	if expectedSize > 0 && written != expectedSize {
		_ = os.Remove(fullPath)
		writeJSON(w, http.StatusOK, map[string]any{"code": 3, "msg": "invalid data len"})
		return
	}

	sum := hex.EncodeToString(hasher.Sum(nil))
	if hashParam != sum {
		_ = os.Remove(fullPath)
		writeJSON(w, http.StatusOK, map[string]any{"code": 4, "msg": "invalid hash"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) handleUserDataDeleteFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uidVal, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("uid")), 10, 32)
	if err != nil || uidVal == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}
	ridVal, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("rid")), 10, 32)
	if err != nil || ridVal == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	var payload userDataDeleteRequest
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Files) == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 2, "msg": "Empty Array"})
		return
	}

	failed, err := s.userSave.DeleteTempFilesWithList(uint32(uidVal), uint32(ridVal), payload.Files)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code":            0,
		"msg":             "ok",
		"TotleFilesCount": len(payload.Files),
		"FailedCount":     failed,
	})
}

func (s *Server) handleUserDataUploadSavePic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	uidVal, err := strconv.ParseUint(strings.TrimSpace(q.Get("uid")), 10, 32)
	if err != nil || uidVal == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}
	ridVal, err := strconv.ParseUint(strings.TrimSpace(q.Get("rid")), 10, 32)
	if err != nil || ridVal == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}
	sizeVal, err := strconv.ParseUint(strings.TrimSpace(q.Get("size")), 10, 64)
	if err != nil || sizeVal == 0 || sizeVal > maxUserDataPicSize {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 3, "msg": "invalid data len"})
		return
	}

	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}
	if uint64(len(data)) != sizeVal {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 3, "msg": "invalid data len"})
		return
	}

	tempDir, err := s.userSave.UserTempDir(uint32(uidVal), true)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	target := filepath.Join(tempDir, fmt.Sprintf("%d.jpg", uint32(ridVal)))
	if err := os.WriteFile(target, data, 0o644); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) handleUserDataList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uidVal, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("uid")), 10, 32)
	if err != nil || uidVal == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}

	ctx := r.Context()
	if result, err := s.userSave.MergeTempFiles(ctx, uint32(uidVal), 0); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	} else if result == 0 {
		if _, err := s.userSave.BuildFilesList(ctx, uint32(uidVal)); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
			return
		}
	}

	listPath := s.userSave.UserListFilePath(uint32(uidVal))
	data, err := os.ReadFile(listPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, http.StatusNotFound, map[string]any{"code": 2, "msg": "Not Found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"code": 5, "msg": "failed"})
		return
	}

	w.Header().Set("Content-Type", "stream/fileslist")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleUserDataLostFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	uidParam := strings.TrimSpace(q.Get("uid"))
	if uidParam != "" {
		uidVal, err := strconv.ParseUint(uidParam, 10, 32)
		if err != nil || uidVal == 0 {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad params"})
			return
		}

		code, err := s.userSave.RefreshUserList(r.Context(), uint32(uidVal))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 3, "msg": "error"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"code": 0,
			"data": map[string]int{strconv.FormatUint(uidVal, 10): code},
		})
		return
	}

	hash := strings.ToLower(strings.TrimSpace(q.Get("hash")))
	if len(hash) != 40 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}
	if _, err := hex.DecodeString(hash); err != nil {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}

	if _, ok := s.storage.ExistsArchive(hash); ok {
		writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "File is exist"})
		return
	}

	deleted, results, err := s.userSave.ProcessLostFile(r.Context(), hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 3, "msg": "sqlite error"})
		return
	}
	if len(results) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"code": 4, "msg": "uid is empty"})
		return
	}

	data := make(map[string]int, len(results)+1)
	data["deldb"] = int(deleted)
	for uid, code := range results {
		data[strconv.FormatUint(uint64(uid), 10)] = code
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": data})
}

func normalizeUserDataPath(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	p = strings.ReplaceAll(p, ":", "$")
	p = strings.ReplaceAll(p, "\\", string(os.PathSeparator))
	p = strings.ReplaceAll(p, "/", string(os.PathSeparator))

	cleaned := filepath.Clean(p)
	cleaned = strings.TrimPrefix(cleaned, string(os.PathSeparator))
	if cleaned == "." || cleaned == "" {
		return "", false
	}
	if strings.Contains(cleaned, "..") {
		parts := strings.Split(cleaned, string(os.PathSeparator))
		for _, part := range parts {
			if part == ".." {
				return "", false
			}
		}
	}
	return cleaned, true
}
func (s *Server) handleUserDataClearup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keepDays := 90
	if param := strings.TrimSpace(r.URL.Query().Get("keep_days")); param != "" {
		if v, err := strconv.Atoi(param); err == nil && v > 0 {
			keepDays = v
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), userSaveRequestTimeout)
	defer cancel()

	if _, err := s.userSave.CleanupArchives(ctx, keepDays); err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			writeJSON(w, http.StatusOK, map[string]any{"code": 2, "msg": "error"})
			return
		}
	}

	s.DiskClearup(keepDays)

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}
