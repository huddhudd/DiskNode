package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"saveserver/nvservice/listdata"
	"saveserver/nvservice/storage"
)

type queueItem struct {
	Add *queueAdd `json:"add"`
	Del *queueDel `json:"del"`
}

type queueAdd struct {
	Hash string `json:"hash"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	Attr uint32 `json:"attr"`
	Time int64  `json:"time"`
}

type queueDel struct {
	Name string `json:"name"`
}

func (s *Server) processQueue(ctx context.Context, listPath, queuePath, listName string) (*listdata.File, error) {
	data, err := os.ReadFile(queuePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.loadList(listPath)
		}
		return nil, fmt.Errorf("read queue: %w", err)
	}
	defer os.Remove(queuePath)

	queueData := string(data)
	for strings.HasSuffix(queueData, "$\r\n") {
		queueData = queueData[:len(queueData)-3]
	}
	if strings.TrimSpace(queueData) == "" {
		return s.loadList(listPath)
	}

	queueData = strings.ReplaceAll(queueData, "]$\r\n[", ",")

	var items []queueItem
	if err := json.Unmarshal([]byte(queueData), &items); err != nil {
		return nil, fmt.Errorf("parse queue json: %w", err)
	}

	existing, err := s.loadList(listPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	entries := make(map[string]*listdata.Entry)
	oldCounts := map[string]int{}
	var template *listdata.File
	if existing != nil {
		entries = existing.CloneEntries()
		oldCounts = existing.Counts()
		template = existing
	}

	if !applyQueueEntries(entries, items, s.storage) {
		if existing != nil {
			return existing, nil
		}
		return nil, os.ErrNotExist
	}

	newFile, err := listdata.Build(listName, entries, template)
	if err != nil {
		return nil, err
	}

	delta := diffCounts(newFile.Counts(), oldCounts)
	if err := s.updateRefCounts(ctx, delta); err != nil {
		return nil, err
	}

	if err := writeBinaryAtomic(listPath, newFile.RawBytes); err != nil {
		return nil, err
	}

	return newFile, nil
}

func applyQueueEntries(entries map[string]*listdata.Entry, items []queueItem, store *storage.DataFactory) bool {
	modified := false
	for _, item := range items {
		if item.Add != nil {
			if applyAdd(entries, item.Add, store) {
				modified = true
			}
			continue
		}
		if item.Del != nil {
			if applyDel(entries, item.Del.Name) {
				modified = true
			}
		}
	}
	return modified
}

func applyAdd(entries map[string]*listdata.Entry, add *queueAdd, store *storage.DataFactory) bool {
	if add == nil {
		return false
	}
	path := listdata.NormalizePath(add.Path)
	if path == "" {
		return false
	}
	key := strings.ToLower(path)

	attr := add.Attr
	if attr == 0 {
		attr = listdata.FileAttributeArchive
	}

	if attr&listdata.FileAttributeDirectory != 0 {
		entries[key] = &listdata.Entry{
			Path:         path,
			Attributes:   attr,
			CreationTime: add.Time,
		}
		return true
	}

	hash := strings.ToLower(strings.TrimSpace(add.Hash))
	if len(hash) != 40 {
		return false
	}
	if _, ok := store.Exists(hash); !ok {
		return false
	}

	decoded, err := hex.DecodeString(hash)
	if err != nil {
		return false
	}
	var hashBytes [20]byte
	copy(hashBytes[:], decoded)

	entries[key] = &listdata.Entry{
		Path:         path,
		Attributes:   attr | listdata.FileAttributeArchive,
		CreationTime: add.Time,
		Size:         add.Size,
		Hash:         hashBytes,
	}
	return true
}

func applyDel(entries map[string]*listdata.Entry, name string) bool {
	normalized := listdata.NormalizePath(name)
	if normalized == "" {
		return false
	}
	key := strings.ToLower(normalized)
	if _, ok := entries[key]; ok {
		delete(entries, key)
		return true
	}
	return false
}

func diffCounts(newCounts, oldCounts map[string]int) map[string]int64 {
	delta := make(map[string]int64)
	for hash, n := range newCounts {
		delta[hash] = int64(n - oldCounts[hash])
	}
	for hash, n := range oldCounts {
		if _, ok := newCounts[hash]; !ok {
			delta[hash] -= int64(n)
		}
	}
	for hash, v := range delta {
		if v == 0 {
			delete(delta, hash)
		}
	}
	return delta
}

func (s *Server) updateRefCounts(ctx context.Context, delta map[string]int64) error {
	if len(delta) == 0 {
		return nil
	}

	ensure := make([]string, 0, len(delta))
	for hash, change := range delta {
		if change > 0 {
			ensure = append(ensure, hash)
		}
	}
	if len(ensure) > 0 {
		if err := s.store.Ensure(ctx, ensure, time.Now()); err != nil {
			return err
		}
	}
	return s.store.UpdateRefCounts(ctx, delta)
}

func (s *Server) loadList(path string) (*listdata.File, error) {
	file, err := listdata.ParseFile(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func writeBinaryAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
