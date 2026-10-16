package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/identity"
)

func TestPersistentIdentitySessionsGrantsAndBackup(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	profile := identity.Profile{Provider: "freeipa", Issuer: "dc=example,dc=com", Subject: "uuid-one", Username: "alice", DisplayName: "Alice", Administrator: true}
	session, token, err := s.StartSession(ctx, profile, now, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = s.db.QueryRow(`SELECT token_hash FROM sessions`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == token || hash != tokenHash(token) {
		t.Fatal("session token must only be stored hashed")
	}
	profile.Username = "renamed-alice"
	renamed, secondToken, err := s.StartSession(ctx, profile, now, now.Add(time.Hour), token)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Member.ID != session.Member.ID {
		t.Fatal("renaming must preserve member identity")
	}
	if _, err = s.Session(ctx, token, now); !errors.Is(err, ErrNotFound) {
		t.Fatal("login must rotate the previous session")
	}
	profile.Subject = "uuid-two"
	different, _, err := s.StartSession(ctx, profile, now, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if different.Member.ID == session.Member.ID {
		t.Fatal("same username with a different subject must not inherit identity")
	}
	g, err := s.CreateGrant(ctx, session.Member.ID, session.Member.ID, "cluster", "existing", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateGrant(ctx, session.Member.ID, "missing", "cluster", "existing", now, now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown members must be rejected")
	}
	items, err := s.Grants(ctx, different.Member.ID)
	if err != nil || len(items) != 0 {
		t.Fatal("member filter leaked another member's grant")
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err = s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err = s.Backup(ctx, backup); err == nil {
		t.Fatal("backup must never overwrite existing files")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, secondToken, now); err != nil {
		t.Fatal("session did not survive reopen:", err)
	}
	if _, err = s.Session(ctx, secondToken, now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expiry boundary must invalidate session")
	}
	if err = s.RevokeGrant(ctx, session.Member.ID, g.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeGrant(ctx, session.Member.ID, g.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	items, err = s.Grants(ctx, session.Member.ID)
	if err != nil || len(items) != 1 || items[0].ActiveAt(now.Add(3*time.Minute)) {
		t.Fatal("revocation did not persist")
	}
	events, err := s.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	revocations := 0
	for _, e := range events {
		if e.Action == "grant.revoked" {
			revocations++
		}
	}
	if revocations != 1 {
		t.Fatal("idempotent revocation must produce one audit event")
	}
	copy, err := Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	backed, err := copy.Grants(ctx, session.Member.ID)
	if err != nil || len(backed) != 1 || backed[0].RevokedAt != nil {
		t.Fatal("backup is not a consistent earlier snapshot")
	}
	info, err := os.Stat(backup)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup must have private permissions")
	}
	if err = s.EndSession(ctx, secondToken, session.Member.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, secondToken, now); !errors.Is(err, ErrNotFound) {
		t.Fatal("logout did not invalidate session")
	}
	if err = s.ClearSessions(ctx, now); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil || count != 0 {
		t.Fatal("operator reset did not clear every session")
	}
}
