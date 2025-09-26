package usersave

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTempFilesFromDirWithRid(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	ridDir := filepath.Join(root, "123")
	if err := os.MkdirAll(ridDir, 0o755); err != nil {
		t.Fatalf("mkdir rid: %v", err)
	}

	filePath := filepath.Join(ridDir, "save.dat")
	data := []byte("hello")
	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	infos, err := tempFilesFromDir(root, 0)
	if err != nil {
		t.Fatalf("collect temp files: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(infos))
	}
	info := infos[0]
	if info.RID != 123 {
		t.Fatalf("unexpected rid: %d", info.RID)
	}
	if info.Path != "save.dat" {
		t.Fatalf("unexpected path: %s", info.Path)
	}
	if info.Size != int64(len(data)) {
		t.Fatalf("unexpected size: %d", info.Size)
	}
	if info.Time <= 0 || info.Time > time.Now().UTC().Unix()+1 {
		t.Fatalf("unexpected time: %d", info.Time)
	}
}

func TestTempFilesFromDirRidFilter(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	ridDir := filepath.Join(root, "456")
	if err := os.MkdirAll(ridDir, 0o755); err != nil {
		t.Fatalf("mkdir rid: %v", err)
	}

	path := filepath.Join(root, "file.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	infos, err := tempFilesFromDir(root, 789)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if infos[0].RID != 789 {
		t.Fatalf("unexpected rid %d", infos[0].RID)
	}
	if infos[0].Path != "file.bin" {
		t.Fatalf("unexpected path %s", infos[0].Path)
	}
}
