package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/credential"
	"github.com/Sushidesu486/KubeGrant/internal/identity"
)

func TestMigrateV1PreservesFiniteGrantsSessionsAndAudit(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(schemaV1); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO members VALUES('m','alice','Alice'); INSERT INTO identities VALUES('ipa','issuer','subject','m'); INSERT INTO audit_events(at,actor_id,action,target_id) VALUES(1,'m','grant.created','g')`); err != nil {
		t.Fatal(err)
	}
	token := "a-session-token-with-sufficient-length"
	if _, err = db.Exec(`INSERT INTO sessions VALUES(?,?,1,?)`, tokenHash(token), "m", now.Add(time.Hour).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO grants VALUES('g','m','cluster','role',?,?,NULL)`, now.Add(-time.Minute).UnixNano(), now.Add(time.Hour).UnixNano()); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g, err := s.Grant(ctx, "g")
	if err != nil || g.Permanent || g.Policy() != "standard" || !g.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatal("migration changed existing access", err)
	}
	if _, err = s.Session(ctx, token, now); err != nil {
		t.Fatal("migration invalidated session", err)
	}
	events, err := s.Audit(ctx)
	if err != nil || len(events) != 1 {
		t.Fatal("migration lost audit", err)
	}
	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 2 {
		t.Fatal("wrong schema version")
	}
	backup := filepath.Join(t.TempDir(), "backup")
	if err = s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	copy, err := Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if _, err = copy.Session(ctx, token, now); err != nil {
		t.Fatal("v2 backup did not preserve data")
	}
}

func TestPermanentGrantAndCredentialTransactions(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	session, token, err := s.StartSession(ctx, identity.Profile{Provider: "ipa", Issuer: "issuer", Subject: "alice", Username: "alice"}, now, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	g, err := s.CreateGrantWithPolicy(ctx, "admin", NewGrant{MemberID: session.Member.ID, ClusterID: "cluster", PermissionRef: "role", Policy: "operations", Permanent: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	var expiry sql.NullInt64
	s.db.QueryRow(`SELECT expires_at FROM grants WHERE id=?`, g.ID).Scan(&expiry)
	if expiry.Valid {
		t.Fatal("permanent expiry must be SQL NULL")
	}
	if !g.ActiveAt(now.Add(10 * 365 * 24 * time.Hour)) {
		t.Fatal("long term grant expired")
	}
	if err = s.SetExecution(ctx, g.ID, "applied", "uid", "", now); err != nil {
		t.Fatal(err)
	}
	record, err := s.Grant(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(record)
	var wire map[string]any
	json.Unmarshal(data, &wire)
	if wire["expires_at"] != nil || wire["username"] != "alice" || wire["execution"] == nil || wire["credential_policy"] != "operations" {
		t.Fatalf("incomplete grant response: %s", data)
	}
	p, err := credential.Operations.New(g, session.Member.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.QueueCredential(ctx, p.PublicRequest(), now); err != nil {
		t.Fatal(err)
	}
	p2, err := credential.Operations.New(g, session.Member.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.QueueCredential(ctx, p2.PublicRequest(), now); !errors.Is(err, ErrBusy) {
		t.Fatal("unbounded concurrent issuance")
	}
	if err = s.SetCSRUID(ctx, p.PublicRequest().ID, "original"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetCSRUID(ctx, p.PublicRequest().ID, "replacement"); !errors.Is(err, ErrNotFound) {
		t.Fatal("changed CSR UID accepted")
	}
	// A second process sees revocation and cannot publish a stale success.
	worker, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	if err = s.RevokeGrant(ctx, "admin", g.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = worker.SetExecution(ctx, g.ID, "applied", "uid", "", now.Add(2*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale applied result survived revocation", err)
	}
	if err = worker.CompleteCredential(ctx, p.PublicRequest().ID, []byte("public certificate"), now.Add(time.Hour), now.Add(2*time.Second)); err == nil {
		t.Fatal("revoked request became issued")
	}
	c, err := s.Credential(ctx, p.PublicRequest().ID)
	if err != nil || c.State != "abandoned" {
		t.Fatal("revoked request not ended", err)
	}
	if err = s.PrepareDownload(ctx, token, p.PublicRequest().ID, now.Add(2*time.Second)); err == nil {
		t.Fatal("revoked credential prepared for delivery")
	}
}

func TestControllerPaginationIncludesMoreThanFiveHundredGrants(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	session, _, err := s.StartSession(ctx, identity.Profile{Provider: "ipa", Issuer: "issuer", Subject: "alice", Username: "alice"}, now, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 507; n++ {
		if _, err = s.CreateGrant(ctx, "admin", session.Member.ID, "cluster", "role", now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	count := 0
	after := ""
	for {
		page, err := s.ControllerGrants(ctx, "cluster", after, true, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		count += len(page)
		after = page[len(page)-1].ID
	}
	if count != 507 {
		t.Fatal("controller skipped grants beyond UI cap", count)
	}
	count = 0
	after = ""
	for {
		page, err := s.ControllerGrants(ctx, "cluster", after, false, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		count += len(page)
		after = page[len(page)-1].ID
	}
	if count != 507 {
		t.Fatal("expiry sweep skipped old grants", count)
	}
}

func TestUnknownSchemaIsNotDowngraded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`PRAGMA user_version=999`); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("unknown schema accepted")
	}
	var version int
	db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 999 {
		t.Fatal("unknown schema was modified")
	}
}
