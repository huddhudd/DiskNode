package storage

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type hashArea int

const (
	hashAreaNvCache hashArea = iota
	hashAreaUserDisk
	hashAreaArchive
)

const (
	UserTmpDirName = "TmpData"
	ArchiveDirName = "ArchData"
)

type DataFactory struct {
	mu       sync.Mutex
	roots    []*cacheRoot
	bigFiles map[string]*bigFile
}

type cacheRoot struct {
	basePath     string // e.g. D:\\CloudDiskCache
	nvPath       string // e.g. D:\\CloudDiskCache\\NvphData
	archivePath  string // e.g. D:\\CloudDiskCache\\ArchData
	userDiskPath string // e.g. D:\\CloudDiskCache\\UserDisk
	uploadDir    string // e.g. D:\\CloudDiskCache\\upload_big
}

type bigFile struct {
	file      *os.File
	path      string
	root      *cacheRoot
	size      int64
	lastWrite time.Time
}

func NewDataFactory(cacheDirs []string) (*DataFactory, error) {
	if len(cacheDirs) == 0 {
		return nil, errors.New("no cache directories configured")
	}
	roots := make([]*cacheRoot, 0, len(cacheDirs))
	for _, raw := range cacheDirs {
		cleaned := strings.TrimSpace(raw)
		if cleaned == "" {
			continue
		}
		base := filepath.Join(cleaned, "CloudDiskCache")
		nv := filepath.Join(base, "NvphData")
		if err := os.MkdirAll(nv, 0o755); err != nil {
			return nil, fmt.Errorf("create nv cache dir %q: %w", nv, err)
		}
		arch := filepath.Join(base, ArchiveDirName)
		if err := os.MkdirAll(arch, 0o755); err != nil {
			return nil, fmt.Errorf("create archive dir %q: %w", arch, err)
		}
		userDisk := filepath.Join(base, "UserDisk")
		if err := os.MkdirAll(userDisk, 0o755); err != nil {
			return nil, fmt.Errorf("create user disk dir %q: %w", userDisk, err)
		}
		upload := filepath.Join(base, "upload_big")
		if err := os.MkdirAll(upload, 0o755); err != nil {
			return nil, fmt.Errorf("create upload dir %q: %w", upload, err)
		}
		roots = append(roots, &cacheRoot{basePath: base, nvPath: nv, archivePath: arch, userDiskPath: userDisk, uploadDir: upload})
	}
	if len(roots) == 0 {
		return nil, errors.New("no usable cache roots after validation")
	}
	return &DataFactory{roots: roots, bigFiles: make(map[string]*bigFile)}, nil
}

func (df *DataFactory) SaveFile(hash string, data []byte) (string, error) {
	return df.saveTo(hashAreaNvCache, hash, data)
}

func (df *DataFactory) SaveUserDiskFile(hash string, data []byte) (string, error) {
	return df.saveTo(hashAreaUserDisk, hash, data)
}

func (df *DataFactory) SaveArchiveFile(hash string, data []byte) (string, error) {
	return df.saveTo(hashAreaArchive, hash, data)
}

func (df *DataFactory) saveTo(area hashArea, hash string, data []byte) (string, error) {
	df.mu.Lock()
	root, err := df.selectRootLocked()
	df.mu.Unlock()
	if err != nil {
		return "", err
	}
	cleanHash, err := normalizeHash(hash)
	if err != nil {
		return "", err
	}
	targetDir := root.hashDir(area, cleanHash)
	if targetDir == "" {
		return "", fmt.Errorf("hash area %d not configured", area)
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", fmt.Errorf("create hash directory: %w", err)
	}
	finalPath := filepath.Join(targetDir, cleanHash)
	tmpPath, err := makeTempPath(finalPath)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("rename temp file: %w", err)
	}
	return finalPath, nil
}

func (df *DataFactory) existsIn(area hashArea, hash string) (string, bool) {
	cleanHash, err := normalizeHash(hash)
	if err != nil {
		return "", false
	}
	roots := df.snapshotRoots()
	for _, root := range roots {
		path := root.hashPath(area, cleanHash)
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true
		}
	}
	return "", false
}

func (df *DataFactory) Exists(hash string) (string, bool) {
	return df.existsIn(hashAreaNvCache, hash)
}

func (df *DataFactory) ExistsUserDisk(hash string) (string, bool) {
	return df.existsIn(hashAreaUserDisk, hash)
}

func (df *DataFactory) ExistsArchive(hash string) (string, bool) {
	return df.existsIn(hashAreaArchive, hash)
}

func (df *DataFactory) Delete(hash string) error {
	return df.deleteIn(hashAreaNvCache, hash)
}

func (df *DataFactory) DeleteUserDisk(hash string) error {
	return df.deleteIn(hashAreaUserDisk, hash)
}

func (df *DataFactory) DeleteArchive(hash string) error {
	return df.deleteIn(hashAreaArchive, hash)
}

func (df *DataFactory) deleteIn(area hashArea, hash string) error {
	cleanHash, err := normalizeHash(hash)
	if err != nil {
		return err
	}
	df.mu.Lock()
	defer df.mu.Unlock()
	var firstErr error
	for _, root := range df.roots {
		path := root.hashPath(area, cleanHash)
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return nil
	}
	if firstErr != nil {
		return firstErr
	}
	return os.ErrNotExist
}

// WriteChunk stores a chunk for a staged upload identified by chunked/name.
func (df *DataFactory) WriteChunk(chunked, name string, offset, length, totalSize int64, r io.Reader) error {
	if offset < 0 || length < 0 {
		return errors.New("negative offset or length")
	}
	key := buildBigFileKey(chunked, name)

	df.mu.Lock()
	bf, ok := df.bigFiles[key]
	if !ok {
		root, err := df.selectRootLocked()
		if err != nil {
			df.mu.Unlock()
			return err
		}
		path := filepath.Join(root.uploadDir, key)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			df.mu.Unlock()
			return fmt.Errorf("open chunk file: %w", err)
		}
		if totalSize > 0 {
			if err := file.Truncate(totalSize); err != nil {
				file.Close()
				df.mu.Unlock()
				return fmt.Errorf("preallocate chunk file: %w", err)
			}
		}
		bf = &bigFile{file: file, path: path, root: root, size: totalSize, lastWrite: time.Now()}
		df.bigFiles[key] = bf
	}
	df.mu.Unlock()

	limited := io.LimitReader(r, length)
	buf := make([]byte, 1<<20)
	remaining := length
	writeOffset := offset
	for remaining > 0 {
		chunk := int64(len(buf))
		if chunk > remaining {
			chunk = remaining
		}
		n, err := io.ReadFull(limited, buf[:chunk])
		if err != nil {
			return fmt.Errorf("read chunk data: %w", err)
		}
		if _, err := bf.file.WriteAt(buf[:n], writeOffset); err != nil {
			return fmt.Errorf("write chunk: %w", err)
		}
		remaining -= int64(n)
		writeOffset += int64(n)
	}

	df.mu.Lock()
	if bf.size > 0 && offset+length > bf.size {
		bf.size = offset + length
	}
	bf.lastWrite = time.Now()
	df.mu.Unlock()
	return nil
}

// FinalizeChunk removes the staged upload and returns it for verification.
func (df *DataFactory) FinalizeChunk(chunked, hash string) (*bigFile, error) {
	key := buildBigFileKey(chunked, hash)
	df.mu.Lock()
	bf, ok := df.bigFiles[key]
	if !ok {
		df.mu.Unlock()
		return nil, os.ErrNotExist
	}
	delete(df.bigFiles, key)
	df.mu.Unlock()
	return bf, nil
}

func (df *DataFactory) CloseBigFile(bf *bigFile) {
	if bf == nil || bf.file == nil {
		return
	}
	bf.file.Close()
}

func (df *DataFactory) DiscardBigFile(bf *bigFile) {
	if bf == nil {
		return
	}
	if bf.file != nil {
		bf.file.Close()
		bf.file = nil
	}
	_ = os.Remove(bf.path)
}
func (df *DataFactory) MoveBigFile(bf *bigFile, hash string) (string, error) {
	return df.moveBigFileToArea(bf, hashAreaNvCache, hash)
}

func (df *DataFactory) MoveUserDiskBigFile(bf *bigFile, hash string) (string, error) {
	return df.moveBigFileToArea(bf, hashAreaUserDisk, hash)
}

func (df *DataFactory) moveBigFileToArea(bf *bigFile, area hashArea, hash string) (string, error) {
	cleanHash, err := normalizeHash(hash)
	if err != nil {
		return "", err
	}
	targetDir := bf.root.hashDir(area, cleanHash)
	if targetDir == "" {
		return "", fmt.Errorf("hash area %d not configured", area)
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", fmt.Errorf("create hash directory: %w", err)
	}
	if bf.file != nil {
		bf.file.Close()
		bf.file = nil
	}
	finalPath := filepath.Join(targetDir, cleanHash)
	if err := os.Rename(bf.path, finalPath); err != nil {
		return "", fmt.Errorf("rename staged file: %w", err)
	}
	return finalPath, nil
}

func (bf *bigFile) ComputeSHA1() ([20]byte, error) {
	var digest [20]byte
	if _, err := bf.file.Seek(0, io.SeekStart); err != nil {
		return digest, err
	}
	h := sha1.New()
	if _, err := io.Copy(h, bf.file); err != nil {
		return digest, err
	}
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func buildBigFileKey(chunked, name string) string {
	return strings.ToLower(strings.TrimSpace(chunked)) + "_" + strings.ToLower(strings.TrimSpace(name))
}

func (df *DataFactory) selectRootLocked() (*cacheRoot, error) {
	var best *cacheRoot
	var bestFree uint64
	for _, root := range df.roots {
		free, _, err := freeBytes(root.basePath)
		if err != nil {
			continue
		}
		if best == nil || free > bestFree {
			best = root
			bestFree = free
		}
	}
	if best == nil {
		return nil, errors.New("no cache root with available space")
	}
	return best, nil
}

func (df *DataFactory) snapshotRoots() []*cacheRoot {
	df.mu.Lock()
	defer df.mu.Unlock()
	out := make([]*cacheRoot, len(df.roots))
	copy(out, df.roots)
	return out
}

func (df *DataFactory) CacheBaseDirs() []string {
	roots := df.snapshotRoots()
	dirs := make([]string, 0, len(roots))
	for _, root := range roots {
		dirs = append(dirs, root.basePath)
	}
	return dirs
}

func (df *DataFactory) UserTempDir(uid uint32, create bool) (string, error) {
	if uid == 0 {
		return "", errors.New("uid is zero")
	}

	roots := df.snapshotRoots()
	if len(roots) == 0 {
		return "", errors.New("no cache roots configured")
	}

	uidStr := strconv.FormatUint(uint64(uid), 10)
	var candidate string

	for _, root := range roots {
		if root == nil || root.basePath == "" {
			continue
		}
		dir := filepath.Join(root.basePath, UserTmpDirName, uidStr)
		info, err := os.Stat(dir)
		if err == nil {
			if info.IsDir() {
				return dir, nil
			}
			_ = os.Remove(dir)
			continue
		}
		if !os.IsNotExist(err) {
			continue
		}
		if create && candidate == "" {
			candidate = dir
		}
	}

	if !create {
		return "", os.ErrNotExist
	}

	if candidate == "" {
		candidate = filepath.Join(roots[0].basePath, UserTmpDirName, uidStr)
	}

	if err := os.MkdirAll(candidate, 0o755); err != nil {
		return "", err
	}

	return candidate, nil
}
func (df *DataFactory) UserDiskDirs() []string {
	roots := df.snapshotRoots()
	dirs := make([]string, 0, len(roots))
	for _, root := range roots {
		if root.userDiskPath != "" {
			dirs = append(dirs, root.userDiskPath)
		}
	}
	return dirs
}

func (df *DataFactory) ArchiveDirs() []string {
	roots := df.snapshotRoots()
	dirs := make([]string, 0, len(roots))
	for _, root := range roots {
		if root.archivePath != "" {
			dirs = append(dirs, root.archivePath)
		}
	}
	return dirs
}

func (r *cacheRoot) hashDir(area hashArea, cleanHash string) string {
	base := r.hashBase(area)
	if base == "" || len(cleanHash) < 4 {
		return ""
	}
	return filepath.Join(base, cleanHash[:2], cleanHash[2:4])
}

func (r *cacheRoot) hashPath(area hashArea, cleanHash string) string {
	dir := r.hashDir(area, cleanHash)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, cleanHash)
}

func (r *cacheRoot) hashBase(area hashArea) string {
	switch area {
	case hashAreaNvCache:
		return r.nvPath
	case hashAreaUserDisk:
		return r.userDiskPath
	case hashAreaArchive:
		return r.archivePath
	default:
		return ""
	}
}

func normalizeHash(hash string) (string, error) {
	h := strings.TrimSpace(strings.ToLower(hash))
	if len(h) != 40 {
		return "", fmt.Errorf("invalid hash length: %d", len(h))
	}
	for _, r := range h {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", fmt.Errorf("hash contains non-hex characters: %q", hash)
		}
	}
	return h, nil
}

func makeTempPath(base string) (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate temp suffix: %w", err)
	}
	return base + "." + hex.EncodeToString(buf) + ".tmp", nil
}
