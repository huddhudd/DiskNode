package usersave

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type TempFileInfo struct {
	Size int64
	Time int64
	RID  uint32
	Path string
}

func (s *Service) getUserTempDir(uid uint32, ensure bool) (string, error) {
	dir, err := s.storage.UserTempDir(uid, ensure)
	if err != nil {
		return "", err
	}
	return dir, nil
}

func tempFilesFromDir(root string, rid uint32) ([]TempFileInfo, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("temp root is not a directory")
	}

	var results []TempFileInfo
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
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

		currentRID := rid
		relPath := rel
		if currentRID == 0 {
			parts := strings.SplitN(rel, string(os.PathSeparator), 2)
			if len(parts) < 2 {
				return nil
			}
			ridVal, err := strconv.ParseUint(parts[0], 10, 32)
			if err != nil {
				return nil
			}
			currentRID = uint32(ridVal)
			relPath = parts[1]
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}
		size := fi.Size()
		modTime := fi.ModTime().UTC().Unix()

		windowsPath := toWindowsPath(relPath)

		results = append(results, TempFileInfo{
			Size: size,
			Time: modTime,
			RID:  currentRID,
			Path: windowsPath,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}

func toWindowsPath(path string) string {
	if os.PathSeparator == '\\' {
		return path
	}
	return strings.ReplaceAll(path, string(os.PathSeparator), "\\")
}

func fromWindowsPath(path string) string {
	if os.PathSeparator == '\\' {
		return path
	}
	return strings.ReplaceAll(path, "\\", string(os.PathSeparator))
}
