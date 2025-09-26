package usersave

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"saveserver/nvfiles"
	"saveserver/nvservice/storage"
)

func TestNewInitialisesDatabase(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()

	df, err := storage.NewDataFactory([]string{baseDir})
	if err != nil {
		t.Fatalf("new data factory: %v", err)
	}

	dbPath := filepath.Join(baseDir, "NvFiles.db")
	ctx := context.Background()
	store, err := nvfiles.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open nvfiles: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc, err := New(ctx, baseDir, store, df)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

	if _, err := os.Stat(svc.archDBPath); err != nil {
		t.Fatalf("archive db not created: %v", err)
	}

	svc.mu.RLock()
	db := svc.db
	svc.mu.RUnlock()
	if db == nil {
		t.Fatal("database not initialised")
	}

	assertTable := func(name string) {
		t.Helper()
		row := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", name)
		var tableName string
		if err := row.Scan(&tableName); err != nil {
			if err == sql.ErrNoRows {
				t.Fatalf("table %s not found", name)
			}
			t.Fatalf("inspect table %s: %v", name, err)
		}
	}

	assertTable("DelRecord")
	assertTable("files")
	assertTable("history")
}
