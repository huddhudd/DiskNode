package usersave

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

func (s *Service) runUseTask(t *task) (int, string) {
	if t.UID == 0 {
		return taskStatusFailed, "参数错误"
	}

	ctx := context.Background()

	if _, err := s.MergeTempFiles(ctx, t.UID, 0); err != nil {
		return taskStatusFailed, taskMessage(err, "拉取存档失败，请稍候再试！0x6")
	}

	if t.UseID > 0 {
		t.HistoryID = t.UseID
		if err := s.useHistory(ctx, t.UID, t.UseID); err != nil {
			return taskStatusFailed, taskMessage(err, "应用存档失败，请稍候再试！0x1")
		}
		return taskStatusSuccess, ""
	}

	if t.ShareID > 0 {
		if s.shareDownloader == nil {
			return taskStatusFailed, "拉取存档失败，请稍候再试！0x1"
		}
		historyID, err := s.downloadShared(ctx, t.UID, t.ShareID, t.Token)
		if err != nil {
			return taskStatusFailed, taskMessage(err, "拉取存档失败，请稍候再试！0x1")
		}
		t.HistoryID = historyID
		if err := s.useHistory(ctx, t.UID, historyID); err != nil {
			return taskStatusFailed, taskMessage(err, "拉取存档失败，请稍候再试！0x6")
		}
		return taskStatusSuccess, ""
	}

	return taskStatusFailed, "参数错误"
}

func (s *Service) useHistory(ctx context.Context, uid uint32, id int64) error {
	if uid == 0 || id <= 0 {
		return &TaskFailure{Message: "参数错误"}
	}

	var rid uint32
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT rid FROM history WHERE id=? AND uid=?`, id, uid)
		switch scanErr := row.Scan(&rid); {
		case scanErr == nil:
		case errors.Is(scanErr, sql.ErrNoRows):
			return &TaskFailure{Message: "该存档不存在！0x6"}
		default:
			return &TaskFailure{Message: "应用存档失败，请稍候再试！0x1", Err: scanErr}
		}

		var current sql.NullInt64
		row = tx.QueryRowContext(ctx, `SELECT id FROM history WHERE uid=? AND rid=? AND inuse=1`, uid, rid)
		if scanErr := row.Scan(&current); scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
			return &TaskFailure{Message: "拉取存档失败，请稍候再试！0x3", Err: scanErr}
		}

		if current.Valid && current.Int64 == id {
			return nil
		}

		if current.Valid && current.Int64 != 0 {
			if _, execErr := tx.ExecContext(ctx, `UPDATE history SET inuse=0 WHERE id=?`, current.Int64); execErr != nil {
				return &TaskFailure{Message: "拉取存档失败，请稍候再试！0x4", Err: execErr}
			}
		}

		if _, execErr := tx.ExecContext(ctx, `UPDATE history SET inuse=1 WHERE id=?`, id); execErr != nil {
			return &TaskFailure{Message: "拉取存档失败，请稍候再试！0x5", Err: execErr}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if _, err := s.BuildFilesList(ctx, uid); err != nil {
		return &TaskFailure{Message: "拉取存档失败，请稍候再试！0x6", Err: err}
	}
	return nil
}

func (s *Service) downloadShared(ctx context.Context, uid uint32, shareID int64, token string) (int64, error) {
	if s.shareDownloader == nil {
		return 0, &TaskFailure{Message: "拉取存档失败，请稍候再试！0x1"}
	}

	res, err := s.shareDownloader.Download(ctx, &DownloadShareRequest{UID: uid, ShareID: shareID, Token: token})
	if err != nil {
		return 0, err
	}
	if res == nil {
		return 0, &TaskFailure{Message: "拉取存档失败，请稍候再试！0x1"}
	}

	rid := res.RID
	if rid == 0 {
		return 0, &TaskFailure{Message: "该存档不存在！0x6"}
	}

	timestamp := s.now().UnixMilli()
	recTime := res.Info.RecTime
	if recTime == 0 {
		recTime = timestamp
	}

	totalSize := res.Info.Size
	if totalSize == 0 {
		for _, f := range res.Files {
			totalSize += f.Size
		}
	}

	info := res.Info
	info.Size = totalSize
	info.Version = timestamp
	if info.RecTime == 0 {
		info.RecTime = recTime
	}

	var historyID int64
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		resExec, execErr := tx.ExecContext(ctx, `INSERT INTO history (uid, rid, ver, rec_time, name, size, capture, comment, "add", inuse) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
			uid,
			rid,
			info.Version,
			info.RecTime,
			info.Name,
			info.Size,
			nullableString(info.Capture),
			nullableString(info.Comment),
			nullableString(info.Add),
		)
		if execErr != nil {
			return &TaskFailure{Message: "拉取存档失败，请稍候再试！0x7", Err: execErr}
		}
		newID, idErr := resExec.LastInsertId()
		if idErr != nil {
			return &TaskFailure{Message: "拉取存档失败，请稍候再试！0x8", Err: idErr}
		}
		historyID = newID

		for _, file := range res.Files {
			hash := strings.ToLower(file.Hash)
			if _, execErr := tx.ExecContext(ctx, `INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				uid,
				rid,
				file.Path,
				file.Size,
				hash,
				file.Creation,
				file.Attr,
				info.Version,
				chooseRecTime(file.RecTime, info.RecTime),
			); execErr != nil {
				return &TaskFailure{Message: "拉取存档失败，请稍候再试！0x4", Err: execErr}
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	return historyID, nil
}

func chooseRecTime(values ...int64) int64 {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func nullableString(val string) sql.NullString {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: trimmed, Valid: true}
}

func taskMessage(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	var tf *TaskFailure
	if errors.As(err, &tf) && tf.Message != "" {
		return tf.Message
	}
	if fallback != "" {
		return fallback
	}
	return err.Error()
}
