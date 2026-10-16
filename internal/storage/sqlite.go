package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/grant"
	"github.com/Sushidesu486/KubeGrant/internal/identity"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("record not found")

type Member struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type Session struct {
	Member        Member    `json:"member"`
	Administrator bool      `json:"administrator"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type GrantRecord struct {
	grant.Grant
	Username  string    `json:"username"`
	Execution Execution `json:"execution"`
}

type AuditEvent struct {
	ID            int64     `json:"id"`
	At            time.Time `json:"at"`
	ActorID       string    `json:"actor_id"`
	Action        string    `json:"action"`
	TargetID      string    `json:"target_id"`
	ActorUsername string    `json:"actor_username"`
	TargetLabel   string    `json:"target_label"`
}

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	query := url.Values{"_txlock": {"immediate"}, "_pragma": {"foreign_keys(1)", "busy_timeout(5000)"}}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: query.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func randomID() string { return rand.Text() }
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func audit(ctx context.Context, tx *sql.Tx, now time.Time, actor, action, target string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(at,actor_id,action,target_id) VALUES(?,?,?,?)`, now.UnixNano(), actor, action, target)
	return err
}

func (s *Store) StartSession(ctx context.Context, p identity.Profile, now, expires time.Time, oldToken string) (Session, string, error) {
	if p.Provider == "" || p.Issuer == "" || p.Subject == "" || p.Username == "" || !expires.After(now) {
		return Session{}, "", errors.New("invalid identity or session expiry")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, "", err
	}
	defer tx.Rollback()
	var member Member
	err = tx.QueryRowContext(ctx, `SELECT m.id FROM members m JOIN identities i ON i.member_id=m.id WHERE i.provider=? AND i.issuer=? AND i.subject=?`, p.Provider, p.Issuer, p.Subject).Scan(&member.ID)
	if errors.Is(err, sql.ErrNoRows) {
		member.ID = randomID()
		if _, err = tx.ExecContext(ctx, `INSERT INTO members(id,username,display_name) VALUES(?,?,?)`, member.ID, p.Username, p.DisplayName); err != nil {
			return Session{}, "", err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO identities(provider,issuer,subject,member_id) VALUES(?,?,?,?)`, p.Provider, p.Issuer, p.Subject, member.ID); err != nil {
			return Session{}, "", err
		}
	} else if err != nil {
		return Session{}, "", err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE members SET username=?,display_name=? WHERE id=?`, p.Username, p.DisplayName, member.ID); err != nil {
		return Session{}, "", err
	}
	member.Username, member.DisplayName = p.Username, p.DisplayName
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=? OR token_hash=?`, now.UnixNano(), tokenHash(oldToken)); err != nil {
		return Session{}, "", err
	}
	token := randomID() + randomID()
	if _, err = tx.ExecContext(ctx, `INSERT INTO sessions(token_hash,member_id,administrator,expires_at) VALUES(?,?,?,?)`, tokenHash(token), member.ID, p.Administrator, expires.UnixNano()); err != nil {
		return Session{}, "", err
	}
	if err = audit(ctx, tx, now, member.ID, "session.login", member.ID); err != nil {
		return Session{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, "", err
	}
	return Session{Member: member, Administrator: p.Administrator, ExpiresAt: expires}, token, nil
}

func (s *Store) Session(ctx context.Context, token string, now time.Time) (Session, error) {
	if len(token) < 32 || len(token) > 128 {
		return Session{}, ErrNotFound
	}
	var result Session
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT m.id,m.username,m.display_name,s.administrator,s.expires_at FROM sessions s JOIN members m ON m.id=s.member_id WHERE s.token_hash=? AND s.expires_at>?`, tokenHash(token), now.UnixNano()).Scan(&result.Member.ID, &result.Member.Username, &result.Member.DisplayName, &result.Administrator, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	result.ExpiresAt = time.Unix(0, expires).UTC()
	return result, err
}

func (s *Store) EndSession(ctx context.Context, token, actor string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash(token)); err != nil {
		return err
	}
	if err = audit(ctx, tx, now, actor, "session.logout", actor); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Members(ctx context.Context) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username,display_name FROM members ORDER BY username LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.ID, &m.Username, &m.DisplayName); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

func (s *Store) RevokeGrant(ctx context.Context, actor, id string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revoked sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT revoked_at FROM grants WHERE id=?`, id).Scan(&revoked); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if revoked.Valid {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE grants SET revoked_at=? WHERE id=?`, now.UnixNano(), id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO grant_execution(grant_id,state,checked_at,error_code,binding_uid) VALUES(?,'revoking',0,'','') ON CONFLICT(grant_id) DO UPDATE SET state='revoking',checked_at=0,error_code=''`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE credential_requests SET state='abandoned',error_code='grant_inactive' WHERE grant_id=? AND state='pending'`, id); err != nil {
		return err
	}
	if err = audit(ctx, tx, now, actor, "grant.revoked", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Audit(ctx context.Context) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.at,a.actor_id,a.action,a.target_id,COALESCE(m.username,a.actor_id),COALESCE(gm.username || ' / ' || g.cluster_id,tm.username,a.target_id) FROM audit_events a LEFT JOIN members m ON m.id=a.actor_id LEFT JOIN grants g ON g.id=a.target_id LEFT JOIN members gm ON gm.id=g.member_id LEFT JOIN members tm ON tm.id=a.target_id ORDER BY a.id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.ActorID, &e.Action, &e.TargetID, &e.ActorUsername, &e.TargetLabel); err != nil {
			return nil, err
		}
		e.At = time.Unix(0, at).UTC()
		result = append(result, e)
	}
	return result, rows.Err()
}
