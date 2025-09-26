package usersave

import (
	"context"
)

type TaskFailure struct {
	Message string
	Err     error
}

func (e *TaskFailure) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *TaskFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type ShareClient interface {
	Share(ctx context.Context, req *ShareRequest) error
}

type ShareDownloader interface {
	Download(ctx context.Context, req *DownloadShareRequest) (*DownloadShareResult, error)
}

type ShareRequest struct {
	UID       uint32
	ShareID   int64
	HistoryID int64
	RID       uint32
	Token     string
	Info      ShareInfo
	Files     []ShareFile
	Progress  func(uploaded int64, filesUploaded int64)
}

type ShareInfo struct {
	Name    string
	Comment string
	Add     string
	Size    int64
	Version int64
	RecTime int64
	Capture string
}

type ShareFile struct {
	Path     string
	Size     int64
	Hash     string
	Attr     uint32
	Creation int64
	Ver      int64
	RecTime  int64
}

type DownloadShareRequest struct {
	UID     uint32
	ShareID int64
	Token   string
}

type DownloadShareResult struct {
	Info  ShareInfo
	RID   uint32
	Files []DownloadShareFile
}

type DownloadShareFile struct {
	Path     string
	Size     int64
	Hash     string
	Attr     uint32
	Creation int64
	RecTime  int64
}

type NoopShareClient struct{}

func (NoopShareClient) Share(ctx context.Context, req *ShareRequest) error {
	return nil
}
