package usersave

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func (s *Service) DeleteTempFiles(uid, rid uint32) error {
	dir, err := s.storage.UserTempDir(uid, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	target := dir
	if rid != 0 {
		target = filepath.Join(dir, strconv.FormatUint(uint64(rid), 10))
	}

	if err := os.RemoveAll(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if rid != 0 {
		pic := filepath.Join(dir, fmt.Sprintf("%d.jpg", rid))
		_ = os.Remove(pic)

		reqdel := filepath.Join(dir, fmt.Sprintf("%d%s", rid, deleteRequestExt))
		_ = os.Remove(reqdel)
	}

	return nil
}

func (s *Service) DeleteTempFilesWithList(uid, rid uint32, files []string) (uint32, error) {
	if len(files) == 0 {
		return 0, nil
	}

	base, err := s.storage.UserTempDir(uid, true)
	if err != nil {
		return 0, err
	}

	targetDir := filepath.Join(base, strconv.FormatUint(uint64(rid), 10))
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return 0, err
	}

	var failed uint32
	builder := make([]byte, 0, 256)
	now := time.Now().Unix()

	for _, name := range files {
		if name == "" {
			continue
		}
		builder = append(builder, []byte(name)...)
		builder = append(builder, '|', '\r', '\n')

		localPath := filepath.Join(targetDir, fromWindowsPath(name))
		delName := fmt.Sprintf("%s.del.%d", filepath.Join(base, filepath.Base(localPath)), now)
		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			failed++
			continue
		}

		if err := os.Rename(localPath, delName); err != nil {
			if removeErr := os.Remove(localPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				failed++
			}
		} else {
			_ = os.Remove(delName)
		}
	}

	reqdelPath := filepath.Join(base, fmt.Sprintf("%d%s", rid, deleteRequestExt))
	s.reqdelMu.Lock()
	defer s.reqdelMu.Unlock()

	f, err := os.OpenFile(reqdelPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return failed, err
	}
	defer f.Close()

	if _, err := f.Write(builder); err != nil {
		return failed, err
	}

	return failed, nil
}
