package usersave

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	errTempDirMissing    = errors.New("temp dir missing")
	errHistoryQuery      = errors.New("history query failed")
	errHistoryFilesQuery = errors.New("history files query failed")
)

type SaveListItem struct {
	RID     uint32
	Size    int64
	Version int64
	RecTime int64
}

type HistoryRecord struct {
	ID      int64
	UID     uint32
	RID     uint32
	Version int64
	RecTime int64
	Name    string
	Size    int64
	Capture string
	Comment string
	Add     string
	InUse   int
	Files   []HistoryFile
}

type HistoryFile struct {
	Path string
	Size int64
	Time int64
}

type UnsaveDetails struct {
	TotalSize  int64
	TotalFiles int64
	Files      map[uint32][]TempFileInfo
	DelFiles   map[string][]string
}

func (s *Service) ListSaves(ctx context.Context, uid uint32) ([]SaveListItem, error) {
	if uid == 0 {
		return nil, errors.New("uid is zero")
	}
	db, err := s.dbConn()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT rid, size, ver, rec_time FROM history WHERE inuse=1 AND uid=? ORDER BY rid ASC`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SaveListItem
	for rows.Next() {
		var item SaveListItem
		if err := rows.Scan(&item.RID, &item.Size, &item.Version, &item.RecTime); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) HistoryRecords(ctx context.Context, uid, rid uint32, includeFiles bool) ([]HistoryRecord, error) {
	if uid == 0 || rid == 0 {
		return nil, errors.New("uid or rid zero")
	}
	db, err := s.dbConn()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT id,ver,rec_time,name,size,capture,comment,"add",inuse FROM history WHERE uid=? AND rid=? ORDER BY ver DESC`, uid, rid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errHistoryQuery, err)
	}
	defer rows.Close()

	var out []HistoryRecord
	for rows.Next() {
		var rec HistoryRecord
		rec.UID = uid
		rec.RID = rid
		var capture sql.NullString
		var comment sql.NullString
		var extra sql.NullString
		if err := rows.Scan(&rec.ID, &rec.Version, &rec.RecTime, &rec.Name, &rec.Size, &capture, &comment, &extra, &rec.InUse); err != nil {
			return nil, err
		}
		if capture.Valid {
			rec.Capture = capture.String
		}
		if comment.Valid {
			rec.Comment = comment.String
		}
		if extra.Valid {
			rec.Add = extra.String
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if includeFiles {
		for i := range out {
			files, err := s.historyFiles(ctx, db, uid, rid, out[i].Version)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", errHistoryFilesQuery, err)
			}
			out[i].Files = files
		}
	}

	return out, nil
}

func (s *Service) historyFiles(ctx context.Context, db *sql.DB, uid, rid uint32, ver int64) ([]HistoryFile, error) {
	rows, err := db.QueryContext(ctx, `SELECT file,size,creation FROM files WHERE uid=? AND rid=? AND ver=?`, uid, rid, ver)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []HistoryFile
	for rows.Next() {
		var (
			path     string
			size     int64
			creation int64
		)
		if err := rows.Scan(&path, &size, &creation); err != nil {
			return nil, err
		}
		files = append(files, HistoryFile{
			Path: path,
			Size: size,
			Time: filetimeToUnixSeconds(creation),
		})
	}
	return files, rows.Err()
}

func (s *Service) UnsaveInfo(ctx context.Context, uid, rid uint32) (*UnsaveDetails, error) {
	baseDir, err := s.getUserTempDir(uid, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errTempDirMissing
		}
		return nil, err
	}
	if baseDir == "" {
		return nil, errTempDirMissing
	}

	targetDir := baseDir
	if rid != 0 {
		targetDir = filepath.Join(baseDir, fmt.Sprintf("%d", rid))
	}

	entries, err := tempFilesFromDir(targetDir, rid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			entries = nil
		} else {
			return nil, err
		}
	}

	filesByRid := make(map[uint32][]TempFileInfo)
	var totalFiles int64
	var totalSize int64
	for _, entry := range entries {
		filesByRid[entry.RID] = append(filesByRid[entry.RID], entry)
		totalFiles++
		totalSize += entry.Size
	}

	delFiles := make(map[string][]string)
	reqDelPaths := collectReqDelPaths(baseDir, rid)
	for _, path := range reqDelPaths {
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		items, err := readReqDel(path)
		if err != nil {
			continue
		}
		if len(items) == 0 {
			continue
		}
		delFiles[name] = items
	}

	return &UnsaveDetails{
		TotalFiles: totalFiles,
		TotalSize:  totalSize,
		Files:      filesByRid,
		DelFiles:   delFiles,
	}, nil
}

func collectReqDelPaths(baseDir string, rid uint32) []string {
	var paths []string
	if rid != 0 {
		paths = append(paths, filepath.Join(baseDir, fmt.Sprintf("%d%s", rid, deleteRequestExt)))
		return paths
	}
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return paths
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), deleteRequestExt) {
			continue
		}
		paths = append(paths, filepath.Join(baseDir, name))
	}
	sort.Strings(paths)
	return paths
}

func (d *UnsaveDetails) isEmpty() bool {
	return d == nil || (d.TotalFiles == 0 && len(d.Files) == 0 && len(d.DelFiles) == 0)
}

func (s *Service) ErrTempDirMissing() error {
	return errTempDirMissing
}

func (s *Service) ErrHistoryQuery() error {
	return errHistoryQuery
}

func (s *Service) ErrHistoryFilesQuery() error {
	return errHistoryFilesQuery
}
