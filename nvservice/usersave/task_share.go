package usersave

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

func (s *Service) runShareTask(t *task) (int, string) {
	if t.UID == 0 {
		return taskStatusFailed, "参数错误"
	}

	if s.shareClient == nil {
		return taskStatusFailed, "共享上传失败! 0x101"
	}

	ctx := context.Background()

	data, err := s.loadShareData(ctx, t)
	if err != nil {
		return taskStatusFailed, taskMessage(err, "共享上传失败! 0x101")
	}

	t.HistoryID = data.HistoryID
	t.RID = data.RID
	t.Name = data.Info.Name
	t.Comment = data.Info.Comment
	t.Add = data.Info.Add
	t.Capture = data.Info.Capture
	t.Version = data.Info.Version
	t.RecTime = data.Info.RecTime
	t.Size = data.Info.Size
	t.FilesTotal = int64(len(data.Files))
	t.FilesUploaded = 0
	t.Uploaded = 0

	req := &ShareRequest{
		UID:       t.UID,
		ShareID:   t.ShareID,
		HistoryID: data.HistoryID,
		RID:       data.RID,
		Token:     t.Token,
		Info:      data.Info,
		Files:     data.Files,
	}

	var uploadedTotal int64
	req.Progress = func(uploaded, files int64) {
		s.taskMu.Lock()
		t.Uploaded = uploaded
		t.FilesUploaded = files
		s.taskMu.Unlock()
		uploadedTotal = uploaded
	}

	if err := s.shareClient.Share(ctx, req); err != nil {
		return taskStatusFailed, taskMessage(err, "共享上传失败! 0x101")
	}

	if req.ShareID > 0 {
		t.ShareID = req.ShareID
	}

	t.Uploaded = uploadedTotal
	t.FilesUploaded = t.FilesTotal

	return taskStatusSuccess, ""
}

type shareData struct {
	HistoryID int64
	RID       uint32
	Info      ShareInfo
	Files     []ShareFile
}

func (s *Service) loadShareData(ctx context.Context, t *task) (*shareData, error) {
	historyID := t.HistoryID
	if historyID == 0 {
		if t.RID == 0 {
			return nil, &TaskFailure{Message: "该存档不存在!"}
		}
		id, err := s.LatestHistoryID(ctx, t.UID, t.RID)
		if err != nil {
			return nil, &TaskFailure{Message: "数据库错误, 0x1", Err: err}
		}
		if id == 0 {
			return nil, &TaskFailure{Message: "该存档不存在!"}
		}
		historyID = id
		t.HistoryID = id
	}

	db, err := s.dbConn()
	if err != nil {
		return nil, &TaskFailure{Message: "数据库错误, 0x1", Err: err}
	}

	row := db.QueryRowContext(ctx, `SELECT rid, ver, rec_time, name, size, capture, comment, "add" FROM history WHERE uid=? AND id=?`, t.UID, historyID)
	var (
		rid     uint32
		ver     int64
		recTime int64
		name    sql.NullString
		size    sql.NullInt64
		capture sql.NullString
		comment sql.NullString
		extra   sql.NullString
	)
	if scanErr := row.Scan(&rid, &ver, &recTime, &name, &size, &capture, &comment, &extra); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, &TaskFailure{Message: "该存档不存在!"}
		}
		return nil, &TaskFailure{Message: "数据库错误, 0x1", Err: scanErr}
	}

	info := ShareInfo{
		Name:    name.String,
		Comment: comment.String,
		Add:     extra.String,
		Capture: capture.String,
		Version: ver,
		RecTime: recTime,
	}
	if size.Valid {
		info.Size = size.Int64
	}

	rows, queryErr := db.QueryContext(ctx, `SELECT file, size, hash, creation, attr, rec_time FROM files WHERE uid=? AND rid=? AND ver=?`, t.UID, rid, ver)
	if queryErr != nil {
		return nil, &TaskFailure{Message: "数据库错误, 0x3", Err: queryErr}
	}
	defer rows.Close()

	files := make([]ShareFile, 0)
	for rows.Next() {
		var (
			path        string
			fsize       int64
			hash        sql.NullString
			creation    int64
			attr        uint32
			fileRecTime sql.NullInt64
		)
		if err := rows.Scan(&path, &fsize, &hash, &creation, &attr, &fileRecTime); err != nil {
			return nil, &TaskFailure{Message: "数据库错误, 0x3", Err: err}
		}
		files = append(files, ShareFile{
			Path:     path,
			Size:     fsize,
			Hash:     strings.ToLower(hash.String),
			Attr:     attr,
			Creation: creation,
			Ver:      ver,
			RecTime:  chooseRecTime(fileRecTime.Int64, recTime),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, &TaskFailure{Message: "数据库错误, 0x3", Err: err}
	}

	info = applyShareOverrides(info, t.Params)
	if info.Size == 0 {
		var total int64
		for _, f := range files {
			total += f.Size
		}
		info.Size = total
	}

	return &shareData{
		HistoryID: historyID,
		RID:       rid,
		Info:      info,
		Files:     files,
	}, nil
}

func applyShareOverrides(info ShareInfo, raw string) ShareInfo {
	if strings.TrimSpace(raw) == "" {
		return info
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return info
	}
	if v, ok := payload["name"].(string); ok && strings.TrimSpace(v) != "" {
		info.Name = v
	}
	if v, ok := payload["comment"].(string); ok {
		info.Comment = v
	}
	if v, ok := payload["add"].(string); ok {
		info.Add = v
	}
	return info
}

func (s *Service) LatestHistoryID(ctx context.Context, uid, rid uint32) (int64, error) {
	if uid == 0 || rid == 0 {
		return 0, nil
	}
	db, err := s.dbConn()
	if err != nil {
		return 0, err
	}
	row := db.QueryRowContext(ctx, `SELECT id FROM history WHERE uid=? AND rid=? AND inuse=1 ORDER BY ver DESC LIMIT 1`, uid, rid)
	var id int64
	switch err := row.Scan(&id); {
	case err == nil:
		return id, nil
	case errors.Is(err, sql.ErrNoRows):
		return 0, nil
	default:
		return 0, err
	}
}
