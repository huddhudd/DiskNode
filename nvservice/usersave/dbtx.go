package usersave

import (
	"context"
	"database/sql"
)

func (s *Service) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	db, err := s.dbConn()
	if err != nil {
		return err
	}

	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return nil
}
