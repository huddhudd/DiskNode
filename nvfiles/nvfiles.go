package nvfiles

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	createTableSQL = `CREATE TABLE IF NOT EXISTS "NvFiles" (
"Fid"  TEXT NOT NULL,
"RefCount"  INTEGER NOT NULL,
"aTime"  INTEGER NOT NULL
);`
	createIndexSQL   = `CREATE UNIQUE INDEX IF NOT EXISTS "fid_idx" ON "NvFiles" ("Fid" ASC);`
	insertRowSQL     = `INSERT OR IGNORE INTO "NvFiles" ("Fid","RefCount","aTime") VALUES (?,?,?);`
	updateRefSQL     = `UPDATE "NvFiles" SET "RefCount"="RefCount"+? WHERE "Fid"=?;`
	selectZeroRefSQL = `SELECT "Fid" FROM "NvFiles" WHERE "RefCount" <= 0;`
	deleteZeroRefSQL = `DELETE FROM "NvFiles" WHERE "RefCount" <= 0 AND "Fid" = ?;`
	selectRefSQL     = `SELECT "RefCount" FROM "NvFiles" WHERE "Fid" = ?;`
)

// Store wraps the NvFiles reference-count database used by the legacy C++ server.
type Store struct {
	db *sql.DB
}

// Open opens (and if needed creates) the NvFiles database at dbPath using the same
// schema and pragmas as the C++ implementation.
func Open(ctx context.Context, dbPath string) (*Store, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("db path is empty")
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create nvfiles dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := applyPragmas(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if err := initSchema(ctx, db); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close releases the underlying database resources.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// WithTx executes fn inside a database transaction. If fn returns an error the
// transaction is rolled back.
func (s *Store) WithTx(ctx context.Context, fn func(*sql.Tx) error) error {
	if s == nil || s.db == nil {
		return errors.New("store is not initialized")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Ensure inserts missing records for the provided fid hashes, initialising their
// reference count to zero and setting the access time. Duplicate values are ignored.
func (s *Store) Ensure(ctx context.Context, fids []string, at time.Time) error {
	if len(fids) == 0 {
		return nil
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		return ensureEntries(ctx, tx, fids, at)
	})
}

// UpdateRefCounts adjusts the reference count for each fid by the provided delta.
// Positive deltas increment the count, negative values decrement it.
func (s *Store) UpdateRefCounts(ctx context.Context, deltas map[string]int64) error {
	if len(deltas) == 0 {
		return nil
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		return updateRefCounts(ctx, tx, deltas)
	})
}

// ZeroRefFIDs returns every fid whose reference count is zero or negative.
func (s *Store) ZeroRefFIDs(ctx context.Context) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("store is not initialized")
	}

	rows, err := s.db.QueryContext(ctx, selectZeroRefSQL)
	if err != nil {
		return nil, fmt.Errorf("query zero ref fids: %w", err)
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var fid string
		if err := rows.Scan(&fid); err != nil {
			return nil, fmt.Errorf("scan zero ref fid: %w", err)
		}
		result = append(result, fid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zero ref fids: %w", err)
	}
	return result, nil
}

// DeleteZeroRefFIDs removes the supplied fids if their stored reference count is
// already non-positive, mirroring the guarded delete used by the C++ service.
func (s *Store) DeleteZeroRefFIDs(ctx context.Context, fids []string) error {
	if len(fids) == 0 {
		return nil
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, deleteZeroRefSQL)
		if err != nil {
			return fmt.Errorf("prepare delete: %w", err)
		}
		defer stmt.Close()

		for _, raw := range fids {
			fid, err := normalizeFID(raw)
			if err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, fid); err != nil {
				return fmt.Errorf("delete fid %s: %w", fid, err)
			}
		}
		return nil
	})
}

// GetRefCount fetches the stored reference count for a fid. The boolean reports
// whether a row existed.
func (s *Store) GetRefCount(ctx context.Context, fid string) (int64, bool, error) {
	if s == nil || s.db == nil {
		return 0, false, errors.New("store is not initialized")
	}
	fid, err := normalizeFID(fid)
	if err != nil {
		return 0, false, err
	}

	var count int64
	err = s.db.QueryRowContext(ctx, selectRefSQL, fid).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("query ref count: %w", err)
	}
	return count, true, nil
}

func applyPragmas(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `PRAGMA synchronous = NORMAL;`); err != nil {
		return fmt.Errorf("set synchronous pragma: %w", err)
	}
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode = WAL;`).Scan(&mode); err != nil {
		return fmt.Errorf("enable WAL: %w", err)
	}
	return nil
}

func initSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, createTableSQL); err != nil {
		return fmt.Errorf("create NvFiles table: %w", err)
	}
	if _, err := db.ExecContext(ctx, createIndexSQL); err != nil {
		return fmt.Errorf("create NvFiles index: %w", err)
	}
	return nil
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
}

func ensureEntries(ctx context.Context, ex execer, fids []string, at time.Time) error {
	if len(fids) == 0 {
		return nil
	}

	timestamp := at
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	epoch := timestamp.Unix()

	stmt, err := ex.PrepareContext(ctx, insertRowSQL)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	seen := make(map[string]struct{}, len(fids))
	for _, raw := range fids {
		fid, err := normalizeFID(raw)
		if err != nil {
			return err
		}
		if _, ok := seen[fid]; ok {
			continue
		}
		seen[fid] = struct{}{}
		if _, err := stmt.ExecContext(ctx, fid, 0, epoch); err != nil {
			return fmt.Errorf("insert fid %s: %w", fid, err)
		}
	}
	return nil
}

func updateRefCounts(ctx context.Context, ex execer, deltas map[string]int64) error {
	if len(deltas) == 0 {
		return nil
	}

	stmt, err := ex.PrepareContext(ctx, updateRefSQL)
	if err != nil {
		return fmt.Errorf("prepare update: %w", err)
	}
	defer stmt.Close()

	for raw, delta := range deltas {
		if delta == 0 {
			continue
		}
		fid, err := normalizeFID(raw)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, delta, fid); err != nil {
			return fmt.Errorf("update fid %s: %w", fid, err)
		}
	}
	return nil
}

func normalizeFID(fid string) (string, error) {
	fid = strings.TrimSpace(fid)
	if fid == "" {
		return "", errors.New("fid is empty")
	}
	fid = strings.ToLower(fid)
	if len(fid) != 40 {
		return "", fmt.Errorf("invalid fid length %d", len(fid))
	}
	for _, ch := range fid {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return "", fmt.Errorf("fid %q contains non-hex characters", fid)
		}
	}
	return fid, nil
}
