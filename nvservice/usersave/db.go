package usersave

import (
	"context"
	"database/sql"
	"fmt"
)

const (
	pragmaSynchronous = `PRAGMA synchronous = NORMAL;`
	pragmaJournalMode = `PRAGMA journal_mode = WAL;`
)

var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS "DelRecord" (
"id"  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
"rid"  INTEGER NOT NULL,
"uid"  INTEGER NOT NULL,
"hash"  TEXT,
"file"  TEXT,
"size"  INTEGER,
"time"  INTEGER
);

CREATE INDEX IF NOT EXISTS "timeIdx"
ON "DelRecord" ("time" ASC);`,
	`CREATE TABLE IF NOT EXISTS "files" (
"id"  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
"rid"  INTEGER NOT NULL,
"uid"  INTEGER NOT NULL,
"file"  TEXT,
"size"  INTEGER,
"hash"  TEXT,
"creation"  INTEGER,
"attr"  INTEGER,
"ver"  INTEGER,
"rec_time"  INTEGER,
CONSTRAINT "files_unique_uid_file_ver" UNIQUE ("uid", "file", "ver")
);

CREATE INDEX IF NOT EXISTS "rid_idx"
ON "files" ("rid" ASC);

CREATE INDEX IF NOT EXISTS "uid_idx"
ON "files" ("uid" ASC);

CREATE INDEX IF NOT EXISTS "ver_idx"
ON "files" ("ver" ASC);`,
	`CREATE TABLE IF NOT EXISTS "history" (
"id"  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
"rid"  INTEGER  NOT NULL,
"uid"  INTEGER  NOT NULL,
"ver"  INTEGER,
"rec_time"  INTEGER,
"name"  TEXT,
"size"  INTEGER,
"capture"  TEXT,
"comment"  TEXT,
"add"  TEXT,
"inuse"  INTEGER,
CONSTRAINT "history_unique" UNIQUE ("uid", "rid", "ver")
);

CREATE INDEX IF NOT EXISTS "uid_hidx"
ON "history" ("uid" ASC);

CREATE INDEX IF NOT EXISTS "ver_hidx"
ON "history" ("ver" ASC);`,
}

func applyPragmas(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, pragmaSynchronous); err != nil {
		return fmt.Errorf("set synchronous pragma: %w", err)
	}
	if _, err := db.ExecContext(ctx, pragmaJournalMode); err != nil {
		return fmt.Errorf("enable WAL: %w", err)
	}
	return nil
}

func ensureSchema(ctx context.Context, db *sql.DB) error {
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("exec schema stmt: %w", err)
		}
	}
	return nil
}
