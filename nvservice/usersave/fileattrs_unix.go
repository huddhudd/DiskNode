//go:build !windows

package usersave

func fileAttributes(path string) (uint32, error) {
	return fileAttributeArchive, nil
}
