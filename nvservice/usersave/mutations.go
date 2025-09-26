package usersave

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	errHistoryNotFound = errors.New("history record not found")
)

func (s *Service) DeleteHistoryRecord(ctx context.Context, uid uint32, id int64) (uint32, int64, error) {
	if uid == 0 || id <= 0 {
		return 0, 0, errors.New("invalid parameters")
	}

	var rid uint32
	var ver int64

	err := s.withTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT rid, ver FROM history WHERE uid=? AND id=?`, uid, id)
		if err := row.Scan(&rid, &ver); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errHistoryNotFound
			}
			return err
		}

		if _, err := tx.ExecContext(ctx, `DELETE FROM history WHERE uid=? AND id=?`, uid, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE uid=? AND rid=? AND ver=?`, uid, rid, ver); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	picture := filepath.Join(s.userListDir, fmt.Sprint(uid), fmt.Sprintf("%d.%d.jpg", rid, ver))
	_ = os.Remove(picture)

	return rid, ver, nil
}

func (s *Service) RenameHistoryRecord(ctx context.Context, uid uint32, id int64, name string) error {
	if uid == 0 || id <= 0 {
		return errors.New("invalid parameters")
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("empty name")
	}

	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE history SET name=? WHERE uid=? AND id=?`, trimmed, uid, id)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return errHistoryNotFound
		}
		return nil
	})
}

func (s *Service) ErrHistoryNotFound() error {
	return errHistoryNotFound
}
