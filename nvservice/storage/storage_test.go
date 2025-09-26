package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUserTempDir(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	other := t.TempDir()

	df, err := NewDataFactory([]string{base, other})
	if err != nil {
		t.Fatalf("new data factory: %v", err)
	}

	uid := uint32(42)

	if _, err := df.UserTempDir(uid, false); !os.IsNotExist(err) {
		t.Fatalf("expected not exist error, got %v", err)
	}

	dir, err := df.UserTempDir(uid, true)
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	expected := filepath.Join(base, "CloudDiskCache", UserTmpDirName, "42")
	if dir != expected {
		t.Fatalf("unexpected dir: got %q want %q", dir, expected)
	}

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("temp dir not created: %v", err)
	}

	// Request existing should return same path without error.
	dirAgain, err := df.UserTempDir(uid, false)
	if err != nil {
		t.Fatalf("existing temp dir lookup: %v", err)
	}
	if dirAgain != expected {
		t.Fatalf("existing dir mismatch: %q != %q", dirAgain, expected)
	}
}
