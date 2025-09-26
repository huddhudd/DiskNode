package server

import (
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
	"strings"
	"sync"
	"time"

	"saveserver/nvfiles"
	"saveserver/nvservice/listdata"
	"saveserver/nvservice/storage"
	"saveserver/nvservice/usersave"
)

type Server struct {
	store         *nvfiles.Store
	storage       *storage.DataFactory
	baseDir       string
	listDir       string
	userListDir   string
	seatDir       string
	seatsMu       sync.Mutex
	seats         map[string]*seat
	listsMu       sync.Mutex
	listLocks     map[string]*sync.Mutex
	userCleanMu   sync.Mutex
	userCleaning  bool
	dataCenterURL string
	httpClient    *http.Client
	userSave      *usersave.Service
}

type seat struct {
	mu         sync.Mutex
	lastAccess time.Time
}

func New(baseDir string, store *nvfiles.Store, storage *storage.DataFactory) (*Server, error) {
	if store == nil {
		return nil, errors.New("nvfiles store is nil")
	}
	if storage == nil {
		return nil, errors.New("storage is nil")
	}

	listDir := filepath.Join(baseDir, "Data", "NvphLists")
	seatDir := filepath.Join(listDir, "Seats")
	if err := os.MkdirAll(seatDir, 0o755); err != nil {
		return nil, fmt.Errorf("create seat dir: %w", err)
	}
	userListDir := filepath.Join(baseDir, "Data", "UserList")
	if err := os.MkdirAll(userListDir, 0o755); err != nil {
		return nil, fmt.Errorf("create user list dir: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	dataCenterURL := "http://data.yunqidong.com:8866/server/upload/check"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userSaveSvc, err := usersave.New(ctx, baseDir, store, storage)
	if err != nil {
		return nil, fmt.Errorf("create usersave service: %w", err)
	}

	if dataCenterURL != "" && client != nil {
		if downloader, err := usersave.NewDataCenterShareDownloader(dataCenterURL, client, storage); err == nil {
			userSaveSvc.SetShareDownloader(downloader)
		} else {
			log.Printf("usersave share downloader: %v", err)
		}
		if shareClient, err := usersave.NewDataCenterShareClient(dataCenterURL, client, storage); err == nil {
			userSaveSvc.SetShareClient(shareClient)
		} else {
			log.Printf("usersave share client: %v", err)
		}
	}
	return &Server{
		store:         store,
		storage:       storage,
		baseDir:       baseDir,
		listDir:       listDir,
		userListDir:   userListDir,
		seatDir:       seatDir,
		seats:         make(map[string]*seat),
		listLocks:     make(map[string]*sync.Mutex),
		dataCenterURL: dataCenterURL,
		httpClient:    client,
		userSave:      userSaveSvc,
	}, nil
}

func (s *Server) Close() error {
	if s.userSave != nil {
		return s.userSave.Close()
	}
	return nil
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/NvCache/list", s.handleList)
	mux.HandleFunc("/NvCache/upload_list", s.handleUploadList)
	mux.HandleFunc("/NvCache/check_files", s.handleCheckFiles)
	mux.HandleFunc("/NvCache/upload_file", s.handleUploadFile)
	mux.HandleFunc("/upload_file", s.handleChunkUpload)
	mux.HandleFunc("/UserDisk/list", s.handleUserDiskList)
	mux.HandleFunc("/UserDisk/upload_list", s.handleUserDiskUploadList)
	mux.HandleFunc("/UserDisk/check_files", s.handleUserDiskCheckFiles)
	mux.HandleFunc("/UserDisk/upload_file", s.handleUserDiskUploadFile)
	mux.HandleFunc("/UserDisk/lost_file", s.handleUserDiskLostFile)
	mux.HandleFunc("/UserSave/", s.handleUserSave)
	mux.HandleFunc("/UserData/", s.handleUserData)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	seatName, err := sanitizeID(r.URL.Query().Get("seat"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}

	rawListName := strings.TrimSpace(r.URL.Query().Get("name"))
	if rawListName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}

	safeName, err := sanitizeFilename(rawListName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}

	listPath := filepath.Join(s.listDir, safeName+".list")
	queuePath := filepath.Join(s.listDir, safeName+".queue")

	lock := s.getListLock(strings.ToLower(safeName))
	lock.Lock()
	defer lock.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	file, err := s.processQueue(ctx, listPath, queuePath, safeName)
	var raw []byte
	switch {
	case err == nil && file != nil:
		raw = file.RawBytes
	case err == nil && file == nil:
		raw, err = os.ReadFile(listPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeJSON(w, http.StatusNotFound, map[string]any{"code": 2, "msg": "Not Found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "read error"})
			return
		}
		file, err = listdata.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 8, "msg": "parse list error"})
			return
		}
	case errors.Is(err, os.ErrNotExist):
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 2, "msg": "Not Found"})
		return
	default:
		raw, readErr := os.ReadFile(listPath)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				writeJSON(w, http.StatusNotFound, map[string]any{"code": 2, "msg": "Not Found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "read error"})
			return
		}
		file, readErr = listdata.Parse(raw)
		if readErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 8, "msg": "parse list error"})
			return
		}
	}

	if raw == nil {
		raw = file.RawBytes
	}

	st := s.getSeat(seatName)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastAccess = time.Now()

	ctx, cancel = context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	seatPath := filepath.Join(s.seatDir, seatName+".list")
	oldCounts := map[string]int{}
	if oldData, err := os.ReadFile(seatPath); err == nil && len(oldData) > 0 {
		if seatFile, parseErr := listdata.Parse(oldData); parseErr == nil {
			oldCounts = seatFile.Counts()
		}
	}

	delta := diffCounts(file.Counts(), oldCounts)
	if err := s.updateRefCounts(ctx, delta); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 11, "msg": "database failed"})
		return
	}

	if err := writeBinaryAtomic(seatPath, raw); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 6, "msg": "write error"})
		return
	}

	w.Header().Set("Content-Type", "stream/fileslist")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleUploadList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rawName := strings.TrimSpace(r.URL.Query().Get("name"))
	if rawName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad params"})
		return
	}

	safeName, err := sanitizeFilename(rawName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 3, "msg": "Bad params"})
		return
	}

	sizeParam := strings.TrimSpace(r.URL.Query().Get("size"))
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}
	if sizeParam != "" {
		if expected, errConv := parseUint(sizeParam); errConv == nil {
			if expected != uint64(len(body)) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"code": 2, "msg": "invalid data len"})
				return
			}
		}
	}

	lock := s.getListLock(strings.ToLower(safeName))
	lock.Lock()
	defer lock.Unlock()

	if err := os.MkdirAll(s.listDir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 4, "msg": "Internal Server Error"})
		return
	}

	queuePath := filepath.Join(s.listDir, safeName+".queue")
	file, err := os.OpenFile(queuePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 4, "msg": "Internal Server Error"})
		return
	}
	defer file.Close()

	if _, err := file.Write(body); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "Internal Server Error"})
		return
	}
	if _, err := file.WriteString("$\r\n"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "Internal Server Error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) handleCheckFiles(w http.ResponseWriter, r *http.Request) {
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
		if expected, errConv := parseUint(sizeParam); errConv == nil {
			if expected != uint64(len(body)) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"code": 2, "msg": "invalid data len"})
				return
			}
		}
	}

	var payload struct {
		Files []struct {
			Hash string `json:"hash"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &payload.Files); err != nil {
		if err := json.Unmarshal(body, &payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 4, "msg": "Bad Request"})
			return
		}
	}
	missing := make([]map[string]string, 0)
	for _, f := range payload.Files {
		fid := strings.TrimSpace(f.Hash)
		if len(fid) != 40 {
			continue
		}
		if _, ok := s.storage.Exists(fid); ok {
			continue
		}
		missing = append(missing, map[string]string{"hash": strings.ToLower(fid)})
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok", "files": missing})
}

func (s *Server) handleChunkUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Body == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	lenParam := strings.TrimSpace(r.URL.Query().Get("len"))
	offParam := strings.TrimSpace(r.URL.Query().Get("off"))
	sizeParam := strings.TrimSpace(r.URL.Query().Get("size"))
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	chunked := strings.TrimSpace(r.URL.Query().Get("chunked"))

	chunkLen, err := parseUint(lenParam)
	if err != nil || chunkLen == 0 || chunkLen > 512*1024*1024 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 2, "msg": "invalid data len"})
		return
	}
	offset, err := parseUint(offParam)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 2, "msg": "invalid data len"})
		return
	}
	totalSize, err := parseUint(sizeParam)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 2, "msg": "invalid data len"})
		return
	}
	if name == "" || chunked == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 3, "msg": "invalid file name"})
		return
	}

	reader := io.LimitReader(r.Body, int64(chunkLen))
	if err := s.storage.WriteChunk(chunked, name, int64(offset), int64(chunkLen), int64(totalSize), reader); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": err.Error()})
		return
	}
	io.Copy(io.Discard, r.Body)

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	if len(hash) != 40 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}

	if chunked := strings.TrimSpace(r.URL.Query().Get("chunked")); chunked != "" {
		bf, err := s.storage.FinalizeChunk(chunked, hash)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 11, "msg": "file not found"})
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
		if _, exists := s.storage.Exists(hash); exists {
			s.storage.DiscardBigFile(bf)
			writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "exist"})
			return
		}
		if _, err := s.storage.MoveBigFile(bf, hash); err != nil {
			s.storage.DiscardBigFile(bf)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 13, "msg": "file rename failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
		return
	}

	sizeParam := strings.TrimSpace(r.URL.Query().Get("size"))
	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1, "msg": "Bad Request"})
		return
	}
	if sizeParam != "" {
		if expected, errConv := parseUint(sizeParam); errConv == nil {
			if expected != uint64(len(data)) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"code": 2, "msg": "invalid data len"})
				return
			}
		}
	}
	digest := sha1.Sum(data)
	if !strings.EqualFold(hash, hex.EncodeToString(digest[:])) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 4, "msg": "Invalid hash"})
		return
	}
	if _, exists := s.storage.Exists(hash); exists {
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "exist"})
		return
	}
	if _, err := s.storage.SaveFile(hash, data); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 5, "msg": "Save file failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok"})
}

func (s *Server) getListLock(name string) *sync.Mutex {
	s.listsMu.Lock()
	defer s.listsMu.Unlock()
	if lock, ok := s.listLocks[name]; ok {
		return lock
	}
	lock := &sync.Mutex{}
	s.listLocks[name] = lock
	return lock
}

func (s *Server) getSeat(name string) *seat {
	safe, err := sanitizeID(name)
	if err != nil {
		return &seat{}
	}
	s.seatsMu.Lock()
	defer s.seatsMu.Unlock()
	st, ok := s.seats[safe]
	if !ok {
		st = &seat{}
		s.seats[safe] = st
	}
	return st
}

func sanitizeID(val string) (string, error) {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return "", errors.New("empty")
	}
	trimmed = strings.ToLower(trimmed)
	for _, r := range trimmed {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", fmt.Errorf("invalid character %q", r)
	}
	return trimmed, nil
}

func sanitizeFilename(val string) (string, error) {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return "", errors.New("empty")
	}
	if strings.ContainsAny(trimmed, `/\\`) {
		return "", errors.New("invalid name")
	}
	return trimmed, nil
}

func parseUint(val string) (uint64, error) {
	if strings.TrimSpace(val) == "" {
		return 0, nil
	}
	var out uint64
	if _, err := fmt.Sscan(val, &out); err != nil {
		return 0, err
	}
	return out, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
