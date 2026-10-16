package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/identity"
)

func TestImportStableIdentityIdempotenceAndNoImplicitAccess(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	admin := identity.Profile{Provider: "freeipa", Issuer: "dc=example,dc=com", Subject: "admin-uuid", Username: "admin", Administrator: true}
	session, token, err := s.StartSession(ctx, admin, now, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	existing, err := s.CreateGrant(ctx, session.Member.ID, session.Member.ID, "cluster", "role", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	profiles := []identity.Profile{admin, {Provider: "freeipa", Issuer: admin.Issuer, Subject: "bob-uuid", Username: "bob", Administrator: true}}
	result, err := s.ImportMembers(ctx, token, profiles, now)
	if err != nil || result.Created != 1 || result.Unchanged != 1 {
		t.Fatal("import failed", result, err)
	}
	result, err = s.ImportMembers(ctx, token, profiles, now)
	if err != nil || result.Unchanged != 2 || result.Created != 0 {
		t.Fatal("repeat import duplicated identities", result, err)
	}
	var sessions, grants int
	s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions)
	s.db.QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&grants)
	if sessions != 1 || grants != 1 {
		t.Fatal("import created implicit session or grant")
	}
	profiles[0].Username = "renamed-admin"
	if _, err = s.ImportMembers(ctx, token, profiles, now); err != nil {
		t.Fatal(err)
	}
	after, _, err := s.StartSession(ctx, profiles[0], now, now.Add(time.Hour), "")
	if err != nil || after.Member.ID != session.Member.ID {
		t.Fatal("import/login identity diverged", err)
	}
	g, err := s.Grant(ctx, existing.ID)
	if err != nil || g.MemberID != session.Member.ID {
		t.Fatal("import modified existing grant")
	}
	profiles[0].Subject = "new-admin-uuid"
	if _, err = s.ImportMembers(ctx, token, profiles, now); err != nil {
		t.Fatal(err)
	}
	different, _, err := s.StartSession(ctx, profiles[0], now, now.Add(time.Hour), "")
	if err != nil || different.Member.ID == session.Member.ID {
		t.Fatal("recreated username inherited identity")
	}
	inherited, err := s.Grants(ctx, different.Member.ID)
	if err != nil || len(inherited) != 0 {
		t.Fatal("recreated username inherited grants")
	}
	if _, err = s.ImportMembers(ctx, token, profiles, now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired administrator completed import", err)
	}
	if _, err = s.ImportMembers(ctx, token, append(profiles, profiles[0]), now); err == nil {
		t.Fatal("duplicate directory accepted")
	}
	// A DB failure midway through a valid snapshot must roll back both newly
	// inserted identities and their audit events.
	if _, err = s.db.Exec(`CREATE TRIGGER import_failure BEFORE INSERT ON identities WHEN NEW.subject='reject-me' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	batch := []identity.Profile{{Provider: "freeipa", Issuer: "issuer", Subject: "rollback-first", Username: "rollback-first"}, {Provider: "freeipa", Issuer: "issuer", Subject: "reject-me", Username: "reject-me"}}
	if _, err = s.ImportMembers(ctx, token, batch, now); err == nil {
		t.Fatal("mid-import DB failure accepted")
	}
	page, err := s.Users(ctx, "rollback-first", 20, 0, now)
	if err != nil || page.Total != 0 {
		t.Fatal("partial database import survived rollback", err)
	}
	if err = s.ClearSessions(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ImportMembers(ctx, token, profiles, now); !errors.Is(err, ErrNotFound) {
		t.Fatal("cleared administrator completed import")
	}
}
func TestUserPaginationSearchAndPermissionIsolation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := identity.Profile{Provider: "freeipa", Issuer: "issuer", Subject: "admin", Username: "admin", Administrator: true}
	admin, token, err := s.StartSession(ctx, p, now, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	profiles := []identity.Profile{}
	for i := 0; i < 507; i++ {
		profiles = append(profiles, identity.Profile{Provider: "freeipa", Issuer: "issuer", Subject: fmt.Sprint(i), Username: fmt.Sprintf("member_%03d", i)})
	}
	if _, err = s.ImportMembers(ctx, token, profiles, now); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for offset := 0; offset < 508; offset += 100 {
		page, err := s.Users(ctx, "", 100, offset, now)
		if err != nil || page.Total != 508 {
			t.Fatal("wrong total", err)
		}
		for _, u := range page.Items {
			if ids[u.ID] {
				t.Fatal("duplicate page identity")
			}
			ids[u.ID] = true
		}
	}
	if len(ids) != 508 {
		t.Fatal("users truncated at 500")
	}
	page, err := s.Users(ctx, "member_506", 20, 0, now)
	if err != nil || page.Total != 1 || page.Items[0].LastLogin != nil {
		t.Fatal("search or imported login status incorrect", err)
	}
	target := page.Items[0]
	if _, err = s.CreateGrant(ctx, admin.Member.ID, target.ID, "cluster", "role", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err := s.UserGrants(ctx, target.ID, 20, 0)
	if err != nil || rows.Total != 1 || rows.Items[0].MemberID != target.ID {
		t.Fatal("target permissions unavailable", err)
	}
	rows, err = s.UserGrants(ctx, admin.Member.ID, 20, 0)
	if err != nil || rows.Total != 0 {
		t.Fatal("member permissions leaked")
	}
	page, err = s.Users(ctx, "%", 20, 0, now)
	if err != nil || page.Total != 0 {
		t.Fatal("search wildcard was not escaped")
	}
}
