package usersave

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
)

func (s *Service) ProcessLostFile(ctx context.Context, hash string) (int64, map[uint32]int, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) != 40 {
		return 0, nil, errors.New("invalid hash length")
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return 0, nil, err
	}

	var (
		uids    []uint32
		deleted int64
	)

	if err := s.withTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT uid FROM files WHERE hash=?`, hash)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var uid uint32
			if scanErr := rows.Scan(&uid); scanErr != nil {
				return scanErr
			}
			if uid != 0 {
				uids = append(uids, uid)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}

		res, err := tx.ExecContext(ctx, `DELETE FROM files WHERE hash=?`, hash)
		if err != nil {
			return err
		}
		if res != nil {
			deleted, _ = res.RowsAffected()
		}
		return nil
	}); err != nil {
		return 0, nil, err
	}

	results := make(map[uint32]int, len(uids))
	for _, uid := range uids {
		code, err := s.RefreshUserList(ctx, uid)
		if err != nil {
			results[uid] = -3
			continue
		}
		results[uid] = code
	}

	return deleted, results, nil
}

func (s *Service) RefreshUserList(ctx context.Context, uid uint32) (int, error) {
	if uid == 0 {
		return -1, errors.New("uid is zero")
	}

	if _, err := s.pruneMissingArchiveEntries(ctx, uid); err != nil {
		return -3, err
	}

	built, err := s.BuildFilesList(ctx, uid)
	if err != nil {
		return -3, err
	}
	if !built {
		return 2, nil
	}
	return 0, nil
}

func (s *Service) pruneMissingArchiveEntries(ctx context.Context, uid uint32) (int, error) {
	if uid == 0 {
		return 0, errors.New("uid is zero")
	}
	if s.storage == nil {
		return 0, nil
	}

	db, err := s.dbConn()
	if err != nil {
		return 0, err
	}

	rows, err := db.QueryContext(ctx, `SELECT DISTINCT hash FROM files WHERE uid=? AND hash<>''`, uid)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	missing := make(map[string]struct{})
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return 0, err
		}
		hash = strings.ToLower(strings.TrimSpace(hash))
		if len(hash) != 40 {
			continue
		}
		if _, err := hex.DecodeString(hash); err != nil {
			continue
		}
		if _, ok := s.storage.ExistsArchive(hash); ok {
			continue
		}
		if _, ok := s.storage.Exists(hash); ok {
			continue
		}
		missing[hash] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if len(missing) == 0 {
		return 0, nil
	}

	if err := s.withTx(ctx, func(tx *sql.Tx) error {
		for hash := range missing {
			if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE uid=? AND hash=?`, uid, hash); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}

	return len(missing), nil
}
