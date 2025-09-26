package nvfiles

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreLifecycle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "NvFiles.db")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	store, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	fid1 := "0123456789abcdef0123456789abcdef01234567"
	fid2 := "fedcba9876543210fedcba9876543210fedcba98"

	if err := store.Ensure(ctx, []string{fid1, fid2, fid1}, time.Unix(1234, 0)); err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}

	if count, ok, err := store.GetRefCount(ctx, fid1); err != nil || !ok || count != 0 {
		t.Fatalf("unexpected refcount for fid1 after ensure: count=%d ok=%v err=%v", count, ok, err)
	}

	if err := store.UpdateRefCounts(ctx, map[string]int64{fid1: 2, fid2: 1}); err != nil {
		t.Fatalf("UpdateRefCounts increment failed: %v", err)
	}

	if count, _, err := store.GetRefCount(ctx, fid1); err != nil || count != 2 {
		t.Fatalf("increment refcount mismatch for fid1: count=%d err=%v", count, err)
	}
	if count, _, err := store.GetRefCount(ctx, fid2); err != nil || count != 1 {
		t.Fatalf("increment refcount mismatch for fid2: count=%d err=%v", count, err)
	}

	if err := store.UpdateRefCounts(ctx, map[string]int64{fid1: -1, fid2: -1}); err != nil {
		t.Fatalf("UpdateRefCounts decrement failed: %v", err)
	}

	if count, _, err := store.GetRefCount(ctx, fid1); err != nil || count != 1 {
		t.Fatalf("decrement refcount mismatch for fid1: count=%d err=%v", count, err)
	}

	if count, _, err := store.GetRefCount(ctx, fid2); err != nil || count != 0 {
		t.Fatalf("decrement refcount mismatch for fid2: count=%d err=%v", count, err)
	}

	zeros, err := store.ZeroRefFIDs(ctx)
	if err != nil {
		t.Fatalf("ZeroRefFIDs failed: %v", err)
	}
	if len(zeros) != 1 || zeros[0] != fid2 {
		t.Fatalf("expected fid2 in zero ref list, got %v", zeros)
	}

	if err := store.DeleteZeroRefFIDs(ctx, []string{fid2}); err != nil {
		t.Fatalf("DeleteZeroRefFIDs failed: %v", err)
	}

	if _, ok, err := store.GetRefCount(ctx, fid2); err != nil || ok {
		t.Fatalf("expected fid2 to be gone, ok=%v err=%v", ok, err)
	}

	zeros, err = store.ZeroRefFIDs(ctx)
	if err != nil {
		t.Fatalf("ZeroRefFIDs after delete failed: %v", err)
	}
	if len(zeros) != 0 {
		t.Fatalf("expected zero-length zero ref list, got %v", zeros)
	}
}

func TestNormalizeFIDValidation(t *testing.T) {
	if _, err := normalizeFID("  abc "); err == nil {
		t.Fatal("expected error for short fid")
	}
	if _, err := normalizeFID(strings.Repeat("g", 40)); err == nil {
		t.Fatal("expected error for non-hex fid")
	}
	fid, err := normalizeFID("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
	if err != nil {
		t.Fatalf("normalize valid fid failed: %v", err)
	}
	if fid != "abcdef0123456789abcdef0123456789abcdef01" {
		t.Fatalf("normalize fid mismatch: %s", fid)
	}
}
