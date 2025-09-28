//go:build !windows

package storage

import "golang.org/x/sys/unix"

func freeBytes(path string) (uint64, uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	blockSize := uint64(stat.Bsize)
	free := blockSize * uint64(stat.Bavail)
	total := blockSize * uint64(stat.Blocks)
	return free, total, nil
}
