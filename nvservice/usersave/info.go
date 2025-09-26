package usersave

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type saveInfo struct {
	LastVersion map[string]*lastVersion `json:"lastVersion"`
	History     historyInfo             `json:"history"`
}

type lastVersion struct {
	Version    int64      `json:"version"`
	Files      []lastFile `json:"files"`
	TotalSize  int64      `json:"total_size"`
	TotalFiles int64      `json:"total_files"`
}

type lastFile struct {
	File string `json:"file"`
	Size int64  `json:"size"`
	Time int64  `json:"time"`
}

type historyInfo struct {
	Versions      map[string][]historyVersion `json:"versions"`
	TotalVersions int64                       `json:"total_versions"`
	TotalFiles    int64                       `json:"total_files"`
}

type historyVersion struct {
	ID   int64 `json:"id"`
	Ver  int64 `json:"ver"`
	Size int64 `json:"size"`
	Time int64 `json:"time"`
}

func (s *Service) GetSaveInfo(ctx context.Context, uid, rid uint32) ([]byte, error) {
	if uid == 0 {
		return nil, errors.New("uid is zero")
	}

	db, err := s.dbConn()
	if err != nil {
		return nil, err
	}

	query := `SELECT rid, ver FROM history WHERE uid=? AND inuse=1`
	var args []any
	args = append(args, uid)
	if rid != 0 {
		query += ` AND rid=?`
		args = append(args, rid)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type ridVersion struct {
		name string
		rid  uint32
		ver  int64
	}

	var ridVersions []ridVersion
	for rows.Next() {
		var rv ridVersion
		if err := rows.Scan(&rv.rid, &rv.ver); err != nil {
			return nil, err
		}
		rv.name = fmt.Sprintf("%d", rv.rid)
		ridVersions = append(ridVersions, rv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	info := saveInfo{
		LastVersion: make(map[string]*lastVersion),
		History: historyInfo{
			Versions: make(map[string][]historyVersion),
		},
	}

	filesStmt, err := db.PrepareContext(ctx, `SELECT file,size,creation FROM files WHERE uid=? AND rid=? AND ver=?`)
	if err != nil {
		return nil, err
	}
	defer filesStmt.Close()

	historyStmt, err := db.PrepareContext(ctx, `SELECT id,ver,size,rec_time FROM history WHERE uid=? AND rid=? ORDER BY ver DESC`)
	if err != nil {
		return nil, err
	}
	defer historyStmt.Close()

	for _, rv := range ridVersions {
		lv := &lastVersion{Version: rv.ver}

		fileRows, err := filesStmt.QueryContext(ctx, uid, rv.rid, rv.ver)
		if err != nil {
			return nil, err
		}
		for fileRows.Next() {
			var (
				path     string
				size     int64
				creation int64
			)
			if err := fileRows.Scan(&path, &size, &creation); err != nil {
				fileRows.Close()
				return nil, err
			}
			trimmed := trimRidPrefix(path)
			lv.Files = append(lv.Files, lastFile{
				File: trimmed,
				Size: size,
				Time: filetimeToUnixSeconds(creation),
			})
			lv.TotalFiles++
			lv.TotalSize += size
		}
		fileRows.Close()

		info.LastVersion[rv.name] = lv
		info.History.TotalFiles += lv.TotalFiles

		hRows, err := historyStmt.QueryContext(ctx, uid, rv.rid)
		if err != nil {
			return nil, err
		}
		for hRows.Next() {
			var item historyVersion
			var ms int64
			if err := hRows.Scan(&item.ID, &item.Ver, &item.Size, &ms); err != nil {
				hRows.Close()
				return nil, err
			}
			item.Time = ms / 1000
			info.History.Versions[rv.name] = append(info.History.Versions[rv.name], item)
			info.History.TotalVersions++
		}
		hRows.Close()
	}

	return json.Marshal(info)
}

func trimRidPrefix(path string) string {
	if idx := strings.IndexRune(path, '\\'); idx >= 0 && idx+1 < len(path) {
		return path[idx+1:]
	}
	return path
}
