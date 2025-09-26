package usersave

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"saveserver/nvservice/listdata"
)

const appIDSavedata = 92

func (s *Service) BuildFilesList(ctx context.Context, uid uint32) (bool, error) {
	if uid == 0 {
		return false, errors.New("uid is zero")
	}

	db, err := s.dbConn()
	if err != nil {
		return false, err
	}

	const filesQuery = `SELECT f.file, f.size, f.hash, f.creation, f.attr
FROM files f
JOIN history h ON f.uid=h.uid AND f.rid=h.rid AND f.ver=h.ver
WHERE h.inuse=1 AND f.uid=?
ORDER BY f.rid ASC, f.file ASC`

	rows, err := db.QueryContext(ctx, filesQuery, uid)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	hasFiles := false
	entries := make(map[string]*listdata.Entry)

	for rows.Next() {
		var (
			rawPath  string
			size     int64
			hashStr  sql.NullString
			creation int64
			attr     uint32
		)
		if err := rows.Scan(&rawPath, &size, &hashStr, &creation, &attr); err != nil {
			return false, err
		}

		path := listdata.NormalizePath(rawPath)
		if path == "" {
			continue
		}

		entry := &listdata.Entry{
			Path:         path,
			Attributes:   attr,
			CreationTime: creation,
			Size:         size,
		}

		if attr&listdata.FileAttributeDirectory == 0 {
			hasFiles = true
			if !hashStr.Valid || len(hashStr.String) != 40 {
				entry.Hash = [20]byte{}
			} else if decoded, err := hex.DecodeString(strings.ToLower(hashStr.String)); err == nil && len(decoded) == 20 {
				copy(entry.Hash[:], decoded)
			}
		}

		entries[strings.ToLower(path)] = entry
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	const emptyDirsQuery = `SELECT rid FROM history h WHERE uid=? AND inuse=1 AND NOT EXISTS (SELECT 1 FROM files WHERE uid=h.uid AND rid=h.rid AND ver=h.ver LIMIT 1)`

	dirRows, err := db.QueryContext(ctx, emptyDirsQuery, uid)
	if err != nil {
		return false, err
	}
	defer dirRows.Close()

	for dirRows.Next() {
		var rid uint32
		if err := dirRows.Scan(&rid); err != nil {
			return false, err
		}
		path := fmt.Sprintf("%d", rid)
		key := strings.ToLower(path)
		if _, ok := entries[key]; ok {
			continue
		}
		entries[key] = &listdata.Entry{
			Path:         path,
			Attributes:   listdata.FileAttributeDirectory,
			CreationTime: nowFiletime(),
		}
	}
	if err := dirRows.Err(); err != nil {
		return false, err
	}

	listPath := s.userListPath(uid)
	if !hasFiles {
		if err := os.Remove(listPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		s.removeArchivePictures(uid)
		return false, nil
	}

	var template *listdata.File
	if existing, err := listdata.ParseFile(listPath); err == nil {
		template = existing
	}

	listName := fmt.Sprintf("%d.%d", uid, appIDSavedata)
	newFile, err := listdata.Build(listName, entries, template)
	if err != nil {
		return false, err
	}

	if err := os.MkdirAll(filepath.Dir(listPath), 0o755); err != nil {
		return false, err
	}

	if err := writeBinaryAtomic(listPath, newFile.RawBytes); err != nil {
		return false, err
	}

	return true, nil
}

func (s *Service) userListPath(uid uint32) string {
	dir := filepath.Join(s.userListDir, fmt.Sprint(uid))
	fileName := fmt.Sprintf("%d.%d.list", uid, appIDSavedata)
	return filepath.Join(dir, fileName)
}

func (s *Service) removeArchivePictures(uid uint32) {
	dir := filepath.Join(s.userListDir, fmt.Sprint(uid))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".jpg") {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}

func writeBinaryAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-usersave-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
