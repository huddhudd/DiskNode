package usersave

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	taskStatusPending = 0
	taskStatusRunning = 1
	taskStatusSuccess = 2
	taskStatusFailed  = 3
)

type taskKind int

const (
	taskKindSave taskKind = iota
	taskKindUnsave
	taskKindUse
	taskKindShare
)

const (
	maxTaskWorkers = 5
	taskQueueSize  = 32
)

type task struct {
	ID            string
	Kind          taskKind
	UID           uint32
	RID           uint32
	UseID         int64
	ShareID       int64
	HistoryID     int64
	Params        string
	Token         string
	Status        int
	Message       string
	Name          string
	Comment       string
	Capture       string
	Add           string
	Size          int64
	Version       int64
	RecTime       int64
	Uploaded      int64
	FilesTotal    int64
	FilesUploaded int64
	CreatedAt     time.Time
	CompletedAt   time.Time
}

type TaskStatus struct {
	ID            string
	Kind          taskKind
	UID           uint32
	RID           uint32
	UseID         int64
	ShareID       int64
	HistoryID     int64
	Version       int64
	RecTime       int64
	Name          string
	Size          int64
	Capture       string
	Comment       string
	Add           string
	Uploaded      int64
	Files         int64
	FilesUploaded int64
	Status        int
	Err           string
}

var (
	errTaskManagerClosed  = errors.New("usersave task manager closed")
	errTaskAlreadyPending = errors.New("task already pending")
)

func IsTaskAlreadyPending(err error) bool {
	return errors.Is(err, errTaskAlreadyPending)
}

type taskOptions struct {
	RID       uint32
	UseID     int64
	ShareID   int64
	HistoryID int64
	Params    string
	Token     string
}

func (t *task) resetForReuse(opts taskOptions) {
	if t == nil {
		return
	}
	t.RID = opts.RID
	t.UseID = opts.UseID
	t.ShareID = opts.ShareID
	t.HistoryID = opts.HistoryID
	t.Params = opts.Params
	t.Token = opts.Token
	t.Name = ""
	t.Comment = ""
	t.Capture = ""
	t.Add = ""
	t.Size = 0
	t.Version = 0
	t.RecTime = 0
	t.Uploaded = 0
	t.FilesTotal = 0
	t.FilesUploaded = 0
}

func (s *Service) StartUse(uid uint32, id, sid int64, token string) (string, bool, error) {
	var opts taskOptions
	if id > 0 {
		opts.UseID = id
	}
	if sid > 0 {
		opts.ShareID = sid
	}
	opts.Token = token
	return s.startTask(taskKindUse, uid, opts)
}

func (s *Service) StartShare(uid uint32, rid uint32, historyID, sid int64, token string, params string) (string, bool, error) {
	return s.startTask(taskKindShare, uid, taskOptions{
		RID:       rid,
		HistoryID: historyID,
		ShareID:   sid,
		Token:     token,
		Params:    params,
	})
}

func (s *Service) initTaskManager() {
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	if s.taskQueue != nil {
		return
	}
	s.tasks = make(map[string]*task)
	s.taskQueue = make(chan *task, taskQueueSize)
	s.taskStopCh = make(chan struct{})
	for i := 0; i < maxTaskWorkers; i++ {
		s.taskWG.Add(1)
		go s.taskWorker()
	}
	s.taskWG.Add(1)
	go s.taskCleanupLoop()
}

func (s *Service) shutdownTaskManager() {
	s.taskMu.Lock()
	if s.taskQueue == nil && s.taskStopCh == nil {
		s.taskMu.Unlock()
		return
	}
	queue := s.taskQueue
	stopCh := s.taskStopCh
	s.taskQueue = nil
	s.taskStopCh = nil
	s.tasks = nil
	s.taskMu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	if queue != nil {
		close(queue)
	}
	s.taskWG.Wait()
}

func (s *Service) StartSave(uid, rid uint32) (string, bool, error) {
	return s.startTask(taskKindSave, uid, taskOptions{RID: rid})
}

func (s *Service) StartUnsave(uid, rid uint32) (string, bool, error) {
	return s.startTask(taskKindUnsave, uid, taskOptions{RID: rid})
}

func (s *Service) SaveTaskStatuses(uid uint32, taskID string) []TaskStatus {
	return s.taskStatuses(uid, taskID, taskKindSave, taskKindUnsave)
}

func (s *Service) UseTaskStatuses(uid uint32, taskID string) []TaskStatus {
	return s.taskStatuses(uid, taskID, taskKindUse)
}

func (s *Service) ShareTaskStatuses(uid uint32, taskID string) []TaskStatus {
	return s.taskStatuses(uid, taskID, taskKindShare)
}

func (s *Service) startTask(kind taskKind, uid uint32, opts taskOptions) (string, bool, error) {
	if uid == 0 {
		return "", false, errors.New("uid is zero")
	}

	now := s.now()

	s.taskMu.Lock()
	s.cleanupExpiredTasksLocked(now)
	if s.taskQueue == nil {
		s.taskMu.Unlock()
		return "", false, errTaskManagerClosed
	}

	for id, existing := range s.tasks {
		if existing == nil {
			delete(s.tasks, id)
			continue
		}
		if !existing.matches(kind, uid, opts) {
			continue
		}
		switch existing.Status {
		case taskStatusFailed, taskStatusSuccess:
			existing.Status = taskStatusPending
			existing.Message = ""
			existing.CompletedAt = time.Time{}
			existing.CreatedAt = now
			existing.resetForReuse(opts)
			s.taskMu.Unlock()
			if err := s.enqueueTask(existing); err != nil {
				return "", false, err
			}
			return existing.ID, true, nil
		case taskStatusRunning:
			taskID := existing.ID
			s.taskMu.Unlock()
			return taskID, false, nil
		case taskStatusPending:
			taskID := existing.ID
			s.taskMu.Unlock()
			return taskID, false, errTaskAlreadyPending
		default:
			taskID := existing.ID
			s.taskMu.Unlock()
			return taskID, false, errors.New("invalid task status")
		}
	}

	taskID := uuid.NewString()
	t := &task{
		ID:        taskID,
		Kind:      kind,
		UID:       uid,
		RID:       opts.RID,
		UseID:     opts.UseID,
		ShareID:   opts.ShareID,
		HistoryID: opts.HistoryID,
		Params:    opts.Params,
		Token:     opts.Token,
		Status:    taskStatusPending,
		CreatedAt: now,
	}
	s.tasks[taskID] = t
	s.taskMu.Unlock()

	if err := s.enqueueTask(t); err != nil {
		return "", false, err
	}
	return taskID, false, nil
}

func (s *Service) enqueueTask(t *task) error {
	s.taskMu.Lock()
	queue := s.taskQueue
	stopCh := s.taskStopCh
	s.taskMu.Unlock()

	if queue == nil {
		return errTaskManagerClosed
	}

	select {
	case queue <- t:
		return nil
	case <-stopCh:
		return errTaskManagerClosed
	}
}

func (s *Service) taskWorker() {
	defer s.taskWG.Done()
	for {
		select {
		case <-s.taskStopCh:
			return
		case t, ok := <-s.taskQueue:
			if !ok {
				return
			}
			if t == nil {
				continue
			}
			s.executeTask(t)
		}
	}
}

func (s *Service) taskCleanupLoop() {
	defer s.taskWG.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.taskStopCh:
			return
		case <-ticker.C:
			s.taskMu.Lock()
			s.cleanupExpiredTasksLocked(s.now())
			s.taskMu.Unlock()
		}
	}
}

func (s *Service) executeTask(t *task) {
	s.taskMu.Lock()
	if s.taskQueue == nil {
		s.taskMu.Unlock()
		return
	}
	t.Status = taskStatusRunning
	t.Message = ""
	s.taskMu.Unlock()

	status := taskStatusSuccess
	message := ""

	switch t.Kind {
	case taskKindSave:
		result, err := s.MergeTempFiles(context.Background(), t.UID, t.RID)
		if err != nil || result < 0 {
			status = taskStatusFailed
			message = "\u4fdd\u5b58\u5931\u8d25! 0x1"
			break
		}
		if result == 0 {
			if _, err := s.BuildFilesList(context.Background(), t.UID); err != nil {
				status = taskStatusFailed
				message = "\u4fdd\u5b58\u5931\u8d25! 0x2"
			}
		}
	case taskKindUnsave:
		if err := s.DeleteTempFiles(t.UID, t.RID); err != nil {
			status = taskStatusFailed
			message = "\u5220\u9664\u5931\u8d25! 0x3"
		}
	case taskKindUse:
		status, message = s.runUseTask(t)
	case taskKindShare:
		status, message = s.runShareTask(t)
	default:
		status = taskStatusFailed
		message = "unknown task kind"
	}

	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	if s.taskQueue == nil {
		return
	}
	t.Status = status
	t.Message = message
	t.CompletedAt = s.now()
}

func (s *Service) taskStatuses(uid uint32, taskID string, kinds ...taskKind) []TaskStatus {
	now := s.now()

	kindSet := make(map[taskKind]struct{}, len(kinds))
	for _, k := range kinds {
		kindSet[k] = struct{}{}
	}

	s.taskMu.Lock()
	s.cleanupExpiredTasksLocked(now)
	defer s.taskMu.Unlock()

	matchesKind := func(k taskKind) bool {
		if len(kindSet) == 0 {
			return true
		}
		_, ok := kindSet[k]
		return ok
	}

	buildStatus := func(t *task) TaskStatus {
		return TaskStatus{
			ID:            t.ID,
			Kind:          t.Kind,
			UID:           t.UID,
			RID:           t.RID,
			UseID:         t.UseID,
			ShareID:       t.ShareID,
			HistoryID:     t.HistoryID,
			Version:       t.Version,
			RecTime:       t.RecTime,
			Name:          t.Name,
			Size:          t.Size,
			Capture:       t.Capture,
			Comment:       t.Comment,
			Add:           t.Add,
			Uploaded:      t.Uploaded,
			Files:         t.FilesTotal,
			FilesUploaded: t.FilesUploaded,
			Status:        t.Status,
			Err:           t.Message,
		}
	}

	var out []TaskStatus
	if taskID != "" {
		if t, ok := s.tasks[taskID]; ok && t != nil {
			if matchesKind(t.Kind) && (uid == 0 || t.UID == uid) {
				out = append(out, buildStatus(t))
			}
		}
		return out
	}

	for _, t := range s.tasks {
		if t == nil || !matchesKind(t.Kind) {
			continue
		}
		if uid != 0 && t.UID != uid {
			continue
		}
		out = append(out, buildStatus(t))
	}
	return out
}

func (t *task) matches(kind taskKind, uid uint32, opts taskOptions) bool {
	if t.Kind != kind || t.UID != uid {
		return false
	}
	switch kind {
	case taskKindSave, taskKindUnsave:
		return t.RID == opts.RID
	case taskKindUse:
		return t.UseID == opts.UseID && t.RID == opts.RID && t.ShareID == opts.ShareID
	case taskKindShare:
		if opts.HistoryID != 0 && t.HistoryID != 0 {
			return t.HistoryID == opts.HistoryID
		}
		return t.ShareID == opts.ShareID
	default:
		return false
	}
}
func (s *Service) cleanupExpiredTasksLocked(now time.Time) {
	if s.tasks == nil {
		return
	}
	for id, t := range s.tasks {
		if t == nil {
			delete(s.tasks, id)
			continue
		}
		if (t.Status == taskStatusSuccess || t.Status == taskStatusFailed) && !t.CompletedAt.IsZero() {
			if now.Sub(t.CompletedAt) > taskKeepTime {
				delete(s.tasks, id)
			}
		}
	}
}
