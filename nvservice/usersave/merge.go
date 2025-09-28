package usersave

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"saveserver/nvservice/storage"
)

const (
	emptySHA1            = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	fileAttributeArchive = 0x20
)

type tempEntry struct {
	rid      uint32
	dbPath   string
	size     int64
	hash     string
	creation int64
	attr     uint32
}

type mergePlan struct {
	entries             []tempEntry
	ridSet              map[uint32]struct{}
	reqDelFiles         map[uint32]string
	pictureSources      map[uint32]string
	pictureDestinations map[uint32]string
}

func (s *Service) MergeTempFiles(ctx context.Context, uid, rid uint32) (int, error) {
	baseTemp, err := s.storage.UserTempDir(uid, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 1, nil
		}
		return -1, err
	}

	targetTemp := baseTemp
	if rid != 0 {
		targetTemp = filepath.Join(baseTemp, strconv.FormatUint(uint64(rid), 10))
	}

	info, err := os.Stat(targetTemp)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if rid == 0 {
				return 1, nil
			}
			reqDelPath := filepath.Join(baseTemp, fmt.Sprintf("%d%s", rid, deleteRequestExt))
			if _, statErr := os.Stat(reqDelPath); statErr != nil {
				if errors.Is(statErr, os.ErrNotExist) {
					return 1, nil
				}
				return -1, statErr
			}
			timestamp := s.now().UnixMilli()
			plan := &mergePlan{
				ridSet:              map[uint32]struct{}{rid: {}},
				reqDelFiles:         map[uint32]string{rid: reqDelPath},
				pictureSources:      map[uint32]string{rid: filepath.Join(baseTemp, fmt.Sprintf("%d.jpg", rid))},
				pictureDestinations: map[uint32]string{rid: s.pictureDestination(uid, rid, timestamp)},
			}
			if err := s.executeMergePlan(ctx, uid, baseTemp, timestamp, plan); err != nil {
				return -1, err
			}
			return 0, nil
		}
		return -1, err
	}

	if !info.IsDir() {
		return -1, fmt.Errorf("temp path %s is not directory", targetTemp)
	}

	timestamp := s.now().UnixMilli()
	archiveRoot := filepath.Join(filepath.Dir(filepath.Dir(baseTemp)), storage.ArchiveDirName)

	plan, err := s.buildMergePlan(uid, targetTemp, baseTemp, archiveRoot, rid, timestamp)
	if err != nil {
		return -1, err
	}
	if len(plan.ridSet) == 0 {
		return 1, nil
	}

	if err := s.executeMergePlan(ctx, uid, baseTemp, timestamp, plan); err != nil {
		return -1, err
	}

	renamed := false
	newName := fmt.Sprintf("%s.del.%d", targetTemp, timestamp)
	if err := os.Rename(targetTemp, newName); err == nil {
		renamed = true
	}
	if renamed {
		_ = os.RemoveAll(newName)
	} else {
		_ = os.RemoveAll(targetTemp)
	}

	return 0, nil
}

func (s *Service) executeMergePlan(ctx context.Context, uid uint32, tempBase string, timestamp int64, plan *mergePlan) error {
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		for _, entry := range plan.entries {
			if err := insertFileRecord(ctx, tx, uid, entry, timestamp); err != nil {
				return err
			}
		}
		if err := s.generalNewVersion(ctx, tx, uid, tempBase, timestamp, plan); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	for rid, src := range plan.pictureSources {
		dst := plan.pictureDestinations[rid]
		if err := copyFile(src, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return s.cleanupHistory(ctx, uid, tempBase, plan)
}

func (s *Service) buildMergePlan(uid uint32, root, baseTemp, archiveRoot string, ridFilter uint32, timestamp int64) (*mergePlan, error) {
	plan := &mergePlan{
		ridSet:              make(map[uint32]struct{}),
		reqDelFiles:         make(map[uint32]string),
		pictureSources:      make(map[uint32]string),
		pictureDestinations: make(map[uint32]string),
	}

	if ridFilter != 0 {
		candidate := filepath.Join(baseTemp, fmt.Sprintf("%d%s", ridFilter, deleteRequestExt))
		if _, err := os.Stat(candidate); err == nil {
			plan.reqDelFiles[ridFilter] = candidate
		}
		plan.ridSet[ridFilter] = struct{}{}
		plan.pictureSources[ridFilter] = filepath.Join(baseTemp, fmt.Sprintf("%d.jpg", ridFilter))
		plan.pictureDestinations[ridFilter] = s.pictureDestination(uid, ridFilter, timestamp)
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		if strings.HasSuffix(rel, deleteRequestExt) {
			ridVal, parseErr := parseRID(rel)
			if parseErr != nil {
				return nil
			}
			plan.ridSet[ridVal] = struct{}{}
			plan.reqDelFiles[ridVal] = path
			return nil
		}

		if strings.HasSuffix(rel, ".del") {
			return nil
		}

		entry, ridVal, err := s.convertToEntry(path, rel, baseTemp, archiveRoot, ridFilter)
		if err != nil {
			return err
		}
		if ridVal == 0 {
			return nil
		}
		plan.entries = append(plan.entries, entry)
		plan.ridSet[ridVal] = struct{}{}
		plan.pictureSources[ridVal] = filepath.Join(baseTemp, fmt.Sprintf("%d.jpg", ridVal))
		plan.pictureDestinations[ridVal] = s.pictureDestination(uid, ridVal, timestamp)
		return nil
	})
	if err != nil {
		return nil, err
	}

	for rid := range plan.ridSet {
		if _, ok := plan.reqDelFiles[rid]; !ok {
			candidate := filepath.Join(baseTemp, fmt.Sprintf("%d%s", rid, deleteRequestExt))
			if _, err := os.Stat(candidate); err == nil {
				plan.reqDelFiles[rid] = candidate
			}
		}
		if _, ok := plan.pictureSources[rid]; !ok {
			plan.pictureSources[rid] = filepath.Join(baseTemp, fmt.Sprintf("%d.jpg", rid))
		}
		if _, ok := plan.pictureDestinations[rid]; !ok {
			plan.pictureDestinations[rid] = s.pictureDestination(uid, rid, timestamp)
		}
	}

	sort.Slice(plan.entries, func(i, j int) bool {
		if plan.entries[i].rid == plan.entries[j].rid {
			return plan.entries[i].dbPath < plan.entries[j].dbPath
		}
		return plan.entries[i].rid < plan.entries[j].rid
	})

	return plan, nil
}

func (s *Service) convertToEntry(path, rel, baseTemp, archiveRoot string, ridFilter uint32) (tempEntry, uint32, error) {
	entry := tempEntry{}

	fi, err := os.Stat(path)
	if err != nil {
		return entry, 0, err
	}
	if fi.IsDir() {
		return entry, 0, nil
	}

	ridVal := ridFilter
	relative := rel
	if ridFilter == 0 {
		parts := strings.SplitN(rel, string(os.PathSeparator), 2)
		if len(parts) < 2 {
			return entry, 0, nil
		}
		ridParsed, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return entry, 0, nil
		}
		ridVal = uint32(ridParsed)
		relative = parts[1]
	}

	windowsPath := toWindowsPath(relative)
	dbPath := fmt.Sprintf("%d\\%s", ridVal, windowsPath)

	attr, attrErr := fileAttributes(path)
	if attrErr != nil {
		attr = fileAttributeArchive
	}
	hashHex, err := hashFileSHA1(path)
	if err != nil {
		return entry, 0, err
	}

	if hashHex == "" {
		hashHex = emptySHA1
	}

	dest := filepath.Join(archiveRoot, hashHex[:2], hashHex[2:4], hashHex)
	if _, err := os.Stat(dest); err == nil {
		_ = os.Remove(path)
	} else {
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return entry, 0, err
		}
		if err := os.Rename(path, dest); err != nil {
			if copyErr := copyFile(path, dest); copyErr != nil {
				return entry, 0, copyErr
			}
			_ = os.Remove(path)
		}
	}

	entry = tempEntry{
		rid:      ridVal,
		dbPath:   dbPath,
		size:     fi.Size(),
		hash:     hashHex,
		creation: timeToFiletime(fi.ModTime()),
		attr:     attr,
	}
	return entry, ridVal, nil
}

func hashFileSHA1(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func insertFileRecord(ctx context.Context, tx *sql.Tx, uid uint32, entry tempEntry, timestamp int64) error {
	const query = `INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(uid, file, ver) DO UPDATE SET
size=excluded.size,
hash=excluded.hash,
creation=excluded.creation,
attr=excluded.attr,
rec_time=excluded.rec_time`

	_, err := tx.ExecContext(ctx, query,
		uid,
		entry.rid,
		entry.dbPath,
		entry.size,
		entry.hash,
		entry.creation,
		entry.attr,
		timestamp,
		timestamp,
	)
	return err
}

func (s *Service) generalNewVersion(ctx context.Context, tx *sql.Tx, uid uint32, tempBase string, timestamp int64, plan *mergePlan) error {
	for rid := range plan.ridSet {
		var oldID sql.NullInt64
		var oldVer sql.NullInt64
		var oldName sql.NullString
		row := tx.QueryRowContext(ctx, `SELECT id, ver, name FROM history WHERE uid=? AND rid=? AND inuse=1 LIMIT 1`, uid, rid)
		if err := row.Scan(&oldID, &oldVer, &oldName); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		if oldVer.Valid {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time)
SELECT uid, rid, file, size, hash, creation, attr, ?, rec_time FROM files WHERE uid=? AND rid=? AND ver=?`, timestamp, uid, rid, oldVer.Int64); err != nil {
				return err
			}
		}

		if path, ok := plan.reqDelFiles[rid]; ok {
			names, err := readReqDel(path)
			if err != nil {
				return err
			}
			for _, name := range names {
				full := fmt.Sprintf("%d\\%s", rid, name)
				if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE uid=? AND rid=? AND ver=? AND rec_time!=? AND file = ? COLLATE NOCASE`, uid, rid, timestamp, timestamp, full); err != nil {
					return err
				}
			}
		}

		if oldID.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE history SET inuse=0 WHERE id=?`, oldID.Int64); err != nil {
				return err
			}
		}

		var totalSize sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT IFNULL(SUM(size),0) FROM files WHERE uid=? AND rid=? AND ver=?`, uid, rid, timestamp).Scan(&totalSize); err != nil {
			return err
		}

		name := ""
		if oldName.Valid {
			name = oldName.String
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO history (uid, rid, ver, rec_time, name, size, inuse)
VALUES (?, ?, ?, ?, ?, ?, 1)`, uid, rid, timestamp, timestamp, name, totalSize.Int64); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) cleanupHistory(ctx context.Context, uid uint32, tempBase string, plan *mergePlan) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		for rid := range plan.ridSet {
			versions, err := selectPrunableVersions(ctx, tx, uid, rid)
			if err != nil {
				return err
			}
			for _, ver := range versions {
				if _, err := tx.ExecContext(ctx, `DELETE FROM history WHERE uid=? AND rid=? AND ver=?`, uid, rid, ver); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE uid=? AND rid=? AND ver=?`, uid, rid, ver); err != nil {
					return err
				}
				picture := filepath.Join(s.userListDir, fmt.Sprint(uid), fmt.Sprintf("%d.%d.jpg", rid, ver))
				_ = os.Remove(picture)
			}
			reqDel := filepath.Join(tempBase, fmt.Sprintf("%d%s", rid, deleteRequestExt))
			_ = os.Remove(reqDel)
			tempPic := filepath.Join(tempBase, fmt.Sprintf("%d.jpg", rid))
			_ = os.Remove(tempPic)
		}
		return nil
	})
}

func selectPrunableVersions(ctx context.Context, tx *sql.Tx, uid, rid uint32) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT ver FROM history WHERE uid=? AND rid=? AND inuse!=1 ORDER BY ver DESC LIMIT -1 OFFSET 9`, uid, rid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []int64
	for rows.Next() {
		var ver int64
		if err := rows.Scan(&ver); err != nil {
			return nil, err
		}
		versions = append(versions, ver)
	}
	return versions, rows.Err()
}

func readReqDel(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	parts := strings.Split(string(data), "|\r\n")
	seen := make(map[string]string)
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = trimmed
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func parseRID(name string) (uint32, error) {
	base := name
	if idx := strings.IndexRune(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	v, err := strconv.ParseUint(base, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

func (s *Service) pictureDestination(uid, rid uint32, timestamp int64) string {
	dir := filepath.Join(s.userListDir, fmt.Sprint(uid))
	return filepath.Join(dir, fmt.Sprintf("%d.%d.jpg", rid, timestamp))
}
