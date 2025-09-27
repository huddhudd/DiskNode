//go:build !windows

package usersave

func fileAttributes(string) (uint32, error) {
	return fileAttributeArchive, nil
}
