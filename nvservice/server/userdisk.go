package server

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"saveserver/nvservice/listdata"
)

const (
	appIDUserDisk    = 90
	appIDUserDiskExt = 93

	userDiskCacheCtxSize = 48
	windowsEpochDiff     = int64(11644473600)
)

type userDiskInstruction struct {
	Add *userDiskAdd      `json:"add"`
	Del *userDiskDelete   `json:"del"`
	Ren map[string]string `json:"ren"`
}

type userDiskAdd struct {
	Hash string `json:"hash"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	Attr uint32 `json:"attr"`
	Time int64  `json:"time"`
}

type userDiskDelete struct {
	Name string `json:"name"`
}

const maxUint32Value = int64((1 << 32) - 1)

func (a *userDiskAdd) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*a = userDiskAdd{}

	for key, value := range raw {
		switch key {
		case "hash":
			str, err := parseJSONFlexibleString(value)
			if err != nil {
				return err
			}
			a.Hash = str
		case "path":
			str, err := parseJSONFlexibleString(value)
			if err != nil {
				return err
			}
			a.Path = str
		case "size":
			val, err := parseJSONInt64(value)
			if err != nil {
				return err
			}
			a.Size = val
		case "attr":
			val, err := parseJSONUint32(value)
			if err != nil {
				return err
			}
			a.Attr = val
		case "time":
			val, err := parseJSONInt64(value)
			if err != nil {
				return err
			}
			a.Time = val
		}
	}

	return nil
}

func parseJSONFlexibleString(data json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return s, nil
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || strings.EqualFold(trimmed, "null") {
		return "", nil
	}
	if strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"") && len(trimmed) >= 2 {
		return trimmed[1 : len(trimmed)-1], nil
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return "", fmt.Errorf("invalid string value %s", trimmed)
	}
	return trimmed, nil
}

func parseJSONInt64(data json.RawMessage) (int64, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || strings.EqualFold(trimmed, "null") {
		return 0, nil
	}
	if strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"") && len(trimmed) >= 2 {
		trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	if trimmed == "" {
		return 0, nil
	}
	if strings.HasPrefix(trimmed, "+") {
		trimmed = trimmed[1:]
	}
	if val, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return val, nil
	}
	floatVal, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid int64 value %q", trimmed)
	}
	return int64(floatVal), nil
}

func parseJSONUint32(data json.RawMessage) (uint32, error) {
	val, err := parseJSONInt64(data)
	if err != nil {
		return 0, err
	}
	if val < 0 || val > maxUint32Value {
		return 0, fmt.Errorf("value out of range for uint32: %d", val)
	}
	return uint32(val), nil
}

type hashRequest struct {
	Hash string `json:"hash"`
}

type hashRequestWrapper struct {
	Files []hashRequest `json:"files"`
}

type lostFileRequest struct {
	Files []string `json:"files"`
}

func (s *Server) handleUserDiskList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uidParam := strings.TrimSpace(r.URL.Query().Get("uid"))
	if uidParam == "" {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}
	uid, err := parseUint(uidParam)
	if err != nil || uid == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	appID := uint32(appIDUserDisk)
	if strings.TrimSpace(r.URL.Query().Get("doc")) == "1" {
		appID = appIDUserDiskExt
	}

	dir, listPath, listName := s.userListPaths(uid, appID)
	lock := s.getListLock("user:" + listName)
	lock.Lock()
	defer lock.Unlock()

	data, err := os.ReadFile(listPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, http.StatusNotFound, map[string]any{"code": 2, "msg": "Not Found"})
			return
		}
		log.Printf("read user disk list %s: %v", listPath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "read error"})
		return
	}

	w.Header().Set("Content-Type", "stream/fileslist")
	if _, err := w.Write(data); err != nil {
		log.Printf("write response list %s: %v", listPath, err)
	}
	_ = dir
}

func (s *Server) handleUserDiskUploadList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uidParam := strings.TrimSpace(r.URL.Query().Get("uid"))
	if uidParam == "" {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}
	uid, err := parseUint(uidParam)
	if err != nil || uid == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}

	appID := uint32(appIDUserDisk)
	if strings.TrimSpace(r.URL.Query().Get("doc")) == "1" {
		appID = appIDUserDiskExt
	}

	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	sizeParam := strings.TrimSpace(r.URL.Query().Get("size"))
	expectedSize, err := parseUint(sizeParam)
	if err != nil || expectedSize == 0 || expectedSize != uint64(len(data)) {
		log.Printf("user disk upload_list invalid size uid=%d got=%d want=%d", uid, len(data), expectedSize)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 2, "msg": "invalid data len"})
		return
	}

	instructions, err := parseUserDiskInstructions(data)
	if err != nil || len(instructions) == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 4, "msg": "Bad Request"})
		return
	}

	dir, listPath, listName := s.userListPaths(uid, appID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("create user list dir %s: %v", dir, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "mkdir failed"})
		return
	}

	lock := s.getListLock("user:" + listName)
	lock.Lock()
	defer lock.Unlock()

	var existing *listdata.File
	if _, err := os.Stat(listPath); err == nil {
		existing, err = listdata.ParseFile(listPath)
		if err != nil {
			log.Printf("parse existing list %s: %v", listPath, err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 8, "msg": "parse list error"})
			return
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("stat list %s: %v", listPath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "stat failed"})
		return
	}

	entries := make(map[string]*listdata.Entry)
	if existing != nil {
		entries = existing.CloneEntries()
	}

	timestampNow := nowFiletime()
	for _, inst := range instructions {
		if inst.Add != nil {
			applyUserDiskAdd(entries, inst.Add, timestampNow)
			continue
		}
		if inst.Del != nil {
			removePath(entries, inst.Del.Name)
			continue
		}
		if len(inst.Ren) > 0 {
			for from, to := range inst.Ren {
				renamePath(entries, from, to, timestampNow)
				break
			}
		}
	}

	if len(entries) == 0 {
		if err := os.Remove(listPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("remove list %s: %v", listPath, err)
		}
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "empty"})
		return
	}

	template := existing
	if template == nil {
		template = userDiskTemplate(appID)
	}

	listIdentifier := listName
	newFile, err := listdata.Build(listIdentifier, entries, template)
	if err != nil {
		log.Printf("build list %s: %v", listPath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "build list failed"})
		return
	}

	if err := writeBinaryAtomic(listPath, newFile.RawBytes); err != nil {
		log.Printf("write list %s: %v", listPath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "write file error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) handleUserDiskCheckFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sizeParam := strings.TrimSpace(r.URL.Query().Get("size"))
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}
	if sizeParam != "" {
		if expected, err := parseUint(sizeParam); err != nil || expected != uint64(len(body)) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 2, "msg": "invalid data len"})
			return
		}
	}

	requests, err := parseHashRequests(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 4, "msg": "Bad Request"})
		return
	}

	steamCheck := strings.TrimSpace(r.URL.Query().Get("steam")) == "1"
	deepCheck := strings.TrimSpace(r.URL.Query().Get("deep")) == "1"

	missing := make([]map[string]string, 0)
	for _, req := range requests {
		hash := strings.ToLower(strings.TrimSpace(req.Hash))
		if len(hash) != 40 {
			continue
		}
		if _, ok := s.storage.ExistsUserDisk(hash); ok {
			continue
		}
		if steamCheck && s.hasSteamList(hash) {
			continue
		}
		missing = append(missing, map[string]string{"hash": hash})
	}

	if deepCheck && len(missing) > 0 {
		if body, ok := s.forwardToDataCenter(r.Context(), missing, steamCheck); ok {
			w.Header().Set("Content-Type", "application/json;charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok", "files": missing})
}
func (s *Server) handleUserDiskUploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	if len(hash) != 40 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	if chunked := strings.TrimSpace(r.URL.Query().Get("chunked")); chunked != "" {
		bf, err := s.storage.FinalizeChunk(chunked, hash)
		if err != nil {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 11, "msg": "file not found"})
			return
		}
		defer s.storage.CloseBigFile(bf)

		digest, err := bf.ComputeSHA1()
		if err != nil {
			s.storage.DiscardBigFile(bf)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 12, "msg": "get file hash failed"})
			return
		}
		if !strings.EqualFold(hash, hex.EncodeToString(digest[:])) {
			s.storage.DiscardBigFile(bf)
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 14, "msg": "Invalid hash"})
			return
		}
		if _, exists := s.storage.ExistsUserDisk(hash); exists {
			s.storage.DiscardBigFile(bf)
			writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "exist"})
			return
		}
		if _, err := s.storage.MoveUserDiskBigFile(bf, hash); err != nil {
			s.storage.DiscardBigFile(bf)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 13, "msg": "file rename failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	sizeParam := strings.TrimSpace(r.URL.Query().Get("size"))
	expected, err := parseUint(sizeParam)
	if err != nil || expected == 0 || expected != uint64(len(data)) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 2, "msg": "invalid data len"})
		return
	}

	digest := sha1.Sum(data)
	if !strings.EqualFold(hash, hex.EncodeToString(digest[:])) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 4, "msg": "Invalid hash"})
		return
	}
	if _, exists := s.storage.ExistsUserDisk(hash); exists {
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "exist"})
		return
	}
	if _, err := s.storage.SaveUserDiskFile(hash, data); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "Save file failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) handleUserDiskLostFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	var payload lostFileRequest
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Files) == 0 {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 2, "msg": "Empty Array"})
		return
	}

	hashes := make(map[string]struct{}, len(payload.Files))
	for _, h := range payload.Files {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) != 40 {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": 3, "msg": fmt.Sprintf("hash error %d/%d", len(hashes)+1, len(payload.Files))})
			return
		}
		hashes[h] = struct{}{}
	}

	totalRemoved, err := s.cleanupUserLists(hashes)
	if err != nil {
		log.Printf("cleanup user lists: %v", err)
	}

	msg := fmt.Sprintf("complete enum list, DelListItem:%d, files:%d", totalRemoved, len(payload.Files))
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": msg})
}

func (s *Server) userListPaths(uid uint64, appID uint32) (dir string, listPath string, listName string) {
	uidStr := strconv.FormatUint(uid, 10)
	listName = fmt.Sprintf("%s.%d", uidStr, appID)
	dir = filepath.Join(s.userListDir, uidStr)
	listPath = filepath.Join(dir, listName+".list")
	return
}

func userDiskTemplate(appID uint32) *listdata.File {
	tmpl := &listdata.File{}
	tmpl.Header.CBSize = userDiskCacheCtxSize
	tmpl.Header.ChannelSupport = 2
	tmpl.Header.DataProp = 1
	tmpl.Header.SignOrLen = 0x620495FE
	tmpl.Header.AppID = 0x40000000 | appID
	tmpl.Header.FileID = 0
	tmpl.Header.FileSize = uint64(userDiskCacheCtxSize)
	tmpl.Header.SizeOfHeader = userDiskCacheCtxSize
	return tmpl
}

func applyUserDiskAdd(entries map[string]*listdata.Entry, add *userDiskAdd, fallbackTime int64) {
	if add == nil {
		return
	}

	normalized := listdata.NormalizePath(add.Path)
	if normalized == "" {
		return
	}

	key := strings.ToLower(normalized)
	timestamp := add.Time
	if timestamp == 0 {
		timestamp = fallbackTime
	}

	ensureParentDirs(entries, normalized, timestamp)

	if add.Attr&listdata.FileAttributeDirectory != 0 {
		entry := &listdata.Entry{
			Path:         normalized,
			Attributes:   add.Attr,
			CreationTime: timestamp,
		}
		entries[key] = entry
		return
	}

	if len(add.Hash) != 40 {
		return
	}

	attr := add.Attr
	if attr == 0 {
		attr = listdata.FileAttributeArchive
	}
	attr |= listdata.FileAttributeArchive

	decoded, err := hex.DecodeString(strings.ToLower(add.Hash))
	if err != nil || len(decoded) != 20 {
		return
	}

	entry := &listdata.Entry{
		Path:         normalized,
		Attributes:   attr,
		CreationTime: timestamp,
		Size:         add.Size,
	}
	copy(entry.Hash[:], decoded)
	entries[key] = entry
}

func ensureParentDirs(entries map[string]*listdata.Entry, path string, timestamp int64) {
	if path == "" {
		return
	}
	parts := strings.Split(path, "\\")
	if len(parts) <= 1 {
		return
	}
	for i := 1; i < len(parts); i++ {
		segment := strings.Join(parts[:i], "\\")
		norm := listdata.NormalizePath(segment)
		if norm == "" {
			continue
		}
		key := strings.ToLower(norm)
		if _, ok := entries[key]; ok {
			continue
		}
		t := timestamp
		if t == 0 {
			t = nowFiletime()
		}
		entries[key] = &listdata.Entry{
			Path:         norm,
			Attributes:   listdata.FileAttributeDirectory,
			CreationTime: t,
		}
	}
}

func (s *Server) forwardToDataCenter(ctx context.Context, payload []map[string]string, steam bool) ([]byte, bool) {
	if s.httpClient == nil || s.dataCenterURL == "" {
		return nil, false
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	url := s.dataCenterURL
	if steam {
		if strings.Contains(url, "?") {
			url += "&steamfile=1"
		} else {
			url += "?steamfile=1"
		}
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false
	}
	return data, true
}

func removePath(entries map[string]*listdata.Entry, target string) int {
	norm := listdata.NormalizePath(target)
	if norm == "" {
		return 0
	}
	key := strings.ToLower(norm)
	removed := 0
	entry, ok := entries[key]
	if ok {
		removed++
		delete(entries, key)
		if entry.Attributes&listdata.FileAttributeDirectory != 0 {
			prefix := key + "\\"
			for k := range entries {
				if strings.HasPrefix(k, prefix) {
					delete(entries, k)
					removed++
				}
			}
		}
		return removed
	}

	prefix := key + "\\"
	for k := range entries {
		if strings.HasPrefix(k, prefix) {
			delete(entries, k)
			removed++
		}
	}
	return removed
}

func renamePath(entries map[string]*listdata.Entry, from, to string, timestamp int64) {
	fromNorm := listdata.NormalizePath(from)
	toNorm := listdata.NormalizePath(to)
	if fromNorm == "" || toNorm == "" {
		return
	}

	fromKey := strings.ToLower(fromNorm)
	toKey := strings.ToLower(toNorm)
	if fromKey == toKey {
		return
	}

	entry, ok := entries[fromKey]
	if !ok {
		return
	}

	ensureParentDirs(entries, toNorm, timestamp)

	entryCopy := *entry
	entryCopy.Path = toNorm
	delete(entries, fromKey)
	entries[toKey] = &entryCopy

	if entry.Attributes&listdata.FileAttributeDirectory == 0 {
		return
	}

	oldPrefix := fromKey + "\\"
	newPrefix := toKey + "\\"
	type renameUpdate struct {
		oldKey string
		newKey string
		entry  listdata.Entry
	}
	updates := make([]renameUpdate, 0)
	for k, v := range entries {
		if !strings.HasPrefix(k, oldPrefix) {
			continue
		}
		suffix := k[len(oldPrefix):]
		newKey := newPrefix + suffix
		newPath := listdata.NormalizePath(toNorm + "\\" + suffix)
		entryCopy := *v
		entryCopy.Path = newPath
		updates = append(updates, renameUpdate{oldKey: k, newKey: newKey, entry: entryCopy})
	}
	for _, upd := range updates {
		delete(entries, upd.oldKey)
		e := upd.entry
		entries[upd.newKey] = &e
	}
}

func parseUserDiskInstructions(data []byte) ([]userDiskInstruction, error) {
	var arr []userDiskInstruction
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	return nil, errors.New("invalid instruction format")
}

func parseHashRequests(data []byte) ([]hashRequest, error) {
	var arr []hashRequest
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	var wrapper hashRequestWrapper
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Files, nil
}

func (s *Server) hasSteamList(hash string) bool {
	rel := filepath.Join(hash[:2], hash[2:4], hash) + ".cm"
	for _, base := range s.storage.CacheBaseDirs() {
		path := filepath.Join(base, "$filelist", rel)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

func (s *Server) cleanupUserLists(hashes map[string]struct{}) (int, error) {
	dirs, err := os.ReadDir(s.userListDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}

	totalRemoved := 0
	for _, entry := range dirs {
		if !entry.IsDir() {
			continue
		}
		userDir := filepath.Join(s.userListDir, entry.Name())
		files, err := os.ReadDir(userDir)
		if err != nil {
			log.Printf("read user dir %s: %v", userDir, err)
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".list") {
				continue
			}
			listPath := filepath.Join(userDir, f.Name())
			listName := strings.TrimSuffix(f.Name(), ".list")
			lock := s.getListLock("user:" + listName)
			lock.Lock()

			listFile, err := listdata.ParseFile(listPath)
			if err != nil {
				lock.Unlock()
				log.Printf("parse list %s: %v", listPath, err)
				continue
			}
			entries := listFile.CloneEntries()
			removed := removeHashesFromEntries(entries, hashes)
			if removed == 0 {
				lock.Unlock()
				continue
			}

			totalRemoved += removed
			if len(entries) == 0 {
				lock.Unlock()
				if err := os.Remove(listPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					log.Printf("remove list %s: %v", listPath, err)
				}
				continue
			}

			newFile, err := listdata.Build(listName, entries, listFile)
			if err != nil {
				lock.Unlock()
				log.Printf("rebuild list %s: %v", listPath, err)
				continue
			}
			if err := writeBinaryAtomic(listPath, newFile.RawBytes); err != nil {
				lock.Unlock()
				log.Printf("write list %s: %v", listPath, err)
				continue
			}
			lock.Unlock()
		}
	}

	return totalRemoved, nil
}

func removeHashesFromEntries(entries map[string]*listdata.Entry, hashes map[string]struct{}) int {
	removed := 0
	for key, entry := range entries {
		if entry.Attributes&listdata.FileAttributeDirectory != 0 {
			continue
		}
		if _, ok := hashes[hex.EncodeToString(entry.Hash[:])]; ok {
			delete(entries, key)
			removed++
		}
	}
	return removed
}

func (s *Server) DiskClearup(keepDays int) {
	if keepDays <= 0 {
		keepDays = 30
	}
	s.userCleanMu.Lock()
	if s.userCleaning {
		s.userCleanMu.Unlock()
		return
	}
	s.userCleaning = true
	s.userCleanMu.Unlock()

	go s.runUserDiskCleanup(keepDays)
}

func (s *Server) runUserDiskCleanup(keepDays int) {
	defer func() {
		s.userCleanMu.Lock()
		s.userCleaning = false
		s.userCleanMu.Unlock()
	}()

	cutoff := time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour)
	deleted := make(map[string]struct{})

	for _, root := range s.storage.UserDiskDirs() {
		if strings.TrimSpace(root) == "" {
			continue
		}
		if err := s.walkUserDiskDir(root, root, cutoff, deleted); err != nil {
			log.Printf("user disk cleanup walk %s: %v", root, err)
		}
	}

	if len(deleted) == 0 {
		return
	}

	removed, err := s.cleanupUserLists(deleted)
	if err != nil {
		log.Printf("user disk cleanup lists: %v", err)
		return
	}
	log.Printf("user disk cleanup removed %d files, updated %d list items", len(deleted), removed)
}

func (s *Server) walkUserDiskDir(root, base string, cutoff time.Time, deleted map[string]struct{}) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if entry.IsDir() {
			if err := s.walkUserDiskDir(path, base, cutoff, deleted); err != nil {
				log.Printf("user disk cleanup subdir %s: %v", path, err)
			}
			continue
		}
		name := entry.Name()
		if len(name) != 40 || !isHexString(name) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(path); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("remove user disk file %s: %v", path, err)
			}
			continue
		}
		deleted[strings.ToLower(name)] = struct{}{}
	}
	if root != base {
		if children, err := os.ReadDir(root); err == nil && len(children) == 0 {
			_ = os.Remove(root)
		}
	}
	return nil
}

func isHexString(val string) bool {
	if len(val) == 0 {
		return false
	}
	for _, ch := range val {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func nowFiletime() int64 {
	now := time.Now().UTC()
	return (now.Unix()+windowsEpochDiff)*10_000_000 + int64(now.Nanosecond()/100)
}
