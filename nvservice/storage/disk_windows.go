//go:build windows

package storage

import "golang.org/x/sys/windows"

func freeBytes(path string) (uint64, uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var available, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &available, &totalBytes, &totalFree); err != nil {
		return 0, 0, err
	}
	return available, totalBytes, nil
}
