package usersave

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type archivePlanEntry struct {
	path     string
	hash     string
	deleteDB bool
	records  []archiveRecord
}

type archiveRecord struct {
	uid  uint32
	rid  uint32
	ver  int64
	file string
	size int64
}

type pictureKey struct {
	uid uint32
	rid uint32
	ver int64
}

func (s *Service) CleanupArchives(ctx context.Context, keepDays int) (int, error) {
	if keepDays <= 0 {
		keepDays = 90
	}

	dirs := s.storage.ArchiveDirs()
	if len(dirs) == 0 {
		return 0, nil
	}

	minAge := keepDays - 7
	if minAge < 0 {
		minAge = 0
	}

	minAgeDuration := time.Duration(minAge) * 24 * time.Hour
	maxAgeDuration := time.Duration(keepDays) * 24 * time.Hour
	now := s.now()

	var plan []archivePlanEntry
	removed := 0
	uidsToRefresh := make(map[uint32]struct{})
	pictureTargets := make(map[pictureKey]struct{})

	for _, dir := range dirs {
		if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}
			age := now.Sub(info.ModTime())
			if age < minAgeDuration {
				return nil
			}

			hash := strings.ToLower(filepath.Base(path))
			if len(hash) != 40 {
				if rmErr := os.Remove(path); rmErr == nil || errors.Is(rmErr, os.ErrNotExist) {
					removed++
				}
				return nil
			}

			records, err := s.archiveRecords(ctx, hash)
			if err != nil {
				return err
			}
			if len(records) == 0 {
				plan = append(plan, archivePlanEntry{path: path, hash: hash})
				return nil
			}
			if age <= maxAgeDuration {
				return nil
			}

			entry := archivePlanEntry{
				path:     path,
				hash:     hash,
				deleteDB: true,
				records:  records,
			}
			plan = append(plan, entry)
			for _, rec := range records {
				uidsToRefresh[rec.uid] = struct{}{}
				pictureTargets[pictureKey{uid: rec.uid, rid: rec.rid, ver: rec.ver}] = struct{}{}
			}
			return nil
		}); err != nil {
			if errors.Is(err, context.Canceled) {
				return removed, err
			}
			return removed, err
		}
	}

	for _, entry := range plan {
		if rmErr := os.Remove(entry.path); rmErr == nil || errors.Is(rmErr, os.ErrNotExist) {
			removed++
		}
	}

	if err := s.removeArchiveDbEntries(ctx, plan); err != nil {
		return removed, err
	}

	for key := range pictureTargets {
		picture := filepath.Join(s.userListDir, fmt.Sprint(key.uid), fmt.Sprintf("%d.%d.jpg", key.rid, key.ver))
		_ = os.Remove(picture)
	}

	for uid := range uidsToRefresh {
		if _, err := s.BuildFilesList(ctx, uid); err != nil {
			if errors.Is(err, context.Canceled) {
				return removed, err
			}
			return removed, err
		}
	}

	return removed, nil
}

func (s *Service) archiveRecords(ctx context.Context, hash string) ([]archiveRecord, error) {
	db, err := s.dbConn()
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `SELECT uid, rid, ver, file, size FROM files WHERE hash=?`, strings.ToLower(hash))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []archiveRecord
	for rows.Next() {
		var rec archiveRecord
		if err := rows.Scan(&rec.uid, &rec.rid, &rec.ver, &rec.file, &rec.size); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Service) removeArchiveDbEntries(ctx context.Context, plan []archivePlanEntry) error {
	hasWork := false
	for _, entry := range plan {
		if entry.deleteDB && len(entry.records) > 0 {
			hasWork = true
			break
		}
	}

	return s.withTx(ctx, func(tx *sql.Tx) error {
		nowMillis := s.now().UnixMilli()
		expire := nowMillis - int64(60*24)*int64(time.Hour/time.Millisecond)

		if hasWork {
			for _, entry := range plan {
				if !entry.deleteDB || len(entry.records) == 0 {
					continue
				}
				for _, rec := range entry.records {
					if _, err := tx.ExecContext(ctx, `INSERT INTO DelRecord (hash, file, size, time, uid, rid) VALUES (?, ?, ?, ?, ?, ?)`,
						entry.hash, rec.file, rec.size, nowMillis, rec.uid, rec.rid); err != nil {
						return err
					}
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE hash=?`, entry.hash); err != nil {
					return err
				}
			}
		}

		if _, err := tx.ExecContext(ctx, `DELETE FROM DelRecord WHERE time < ?`, expire); err != nil {
			return err
		}
		return nil
	})
}
