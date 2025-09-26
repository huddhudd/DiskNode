package usersave

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"saveserver/nvfiles"
	"saveserver/nvservice/storage"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	base := t.TempDir()
	df, err := storage.NewDataFactory([]string{base})
	if err != nil {
		t.Fatalf("new data factory: %v", err)
	}
	ctx := context.Background()
	store, err := nvfiles.Open(ctx, filepath.Join(base, "NvFiles.db"))
	if err != nil {
		t.Fatalf("open nvfiles: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc, err := New(ctx, base, store, df)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func TestDeleteTempFiles(t *testing.T) {
	svc := newTestService(t)
	uid := uint32(10)

	dir, err := svc.storage.UserTempDir(uid, true)
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	rid := uint32(5)
	ridDir := filepath.Join(dir, "5")
	if err := os.MkdirAll(ridDir, 0o755); err != nil {
		t.Fatalf("mkdir rid: %v", err)
	}
	filePath := filepath.Join(ridDir, "data.bin")
	if err := os.WriteFile(filePath, []byte("content"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	pic := filepath.Join(dir, "5.jpg")
	if err := os.WriteFile(pic, []byte("jpg"), 0o644); err != nil {
		t.Fatalf("write pic: %v", err)
	}

	if err := svc.DeleteTempFiles(uid, rid); err != nil {
		t.Fatalf("delete temp files: %v", err)
	}

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("file still exists after delete: %v", err)
	}
	if _, err := os.Stat(pic); !os.IsNotExist(err) {
		t.Fatalf("pic still exists after delete: %v", err)
	}
}

func TestDeleteTempFilesWithList(t *testing.T) {
	svc := newTestService(t)
	uid := uint32(20)
	rid := uint32(7)

	base, err := svc.storage.UserTempDir(uid, true)
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	target := filepath.Join(base, "7", "folder")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	path := filepath.Join(target, "file.txt")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	failed, err := svc.DeleteTempFilesWithList(uid, rid, []string{"folder\\file.txt"})
	if err != nil {
		t.Fatalf("delete with list: %v", err)
	}
	if failed != 0 {
		t.Fatalf("unexpected failed count %d", failed)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected file removed: %v", err)
	}

	reqdel := filepath.Join(base, "7"+deleteRequestExt)
	data, err := os.ReadFile(reqdel)
	if err != nil {
		t.Fatalf("read reqdel: %v", err)
	}
	if string(data) != "folder\\file.txt|\r\n" {
		t.Fatalf("unexpected reqdel content: %q", string(data))
	}
}
