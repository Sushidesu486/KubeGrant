package storage

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// Backup creates a consistent snapshot including committed WAL transactions.
// The destination must be new. The operator must copy it outside the cluster.
func (s *Store) Backup(ctx context.Context, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		os.Remove(abs)
		return err
	}
	if _, err = s.db.ExecContext(ctx, `VACUUM INTO ?`, abs); err != nil {
		os.Remove(abs)
		return err
	}
	return nil
}

func (s *Store) ClearSessions(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return err
	}
	if err = audit(ctx, tx, now, "operator", "session.reset", "all"); err != nil {
		return err
	}
	return tx.Commit()
}
