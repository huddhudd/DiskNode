//go:build windows

package usersave

import "golang.org/x/sys/windows"

func fileAttributes(path string) (uint32, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return 0, err
	}
	return uint32(attrs), nil
}
