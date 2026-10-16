package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/identity"
)

// Import only identity metadata: never sessions, platform-admin flags or grants.
type ImportResult struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
	Total     int `json:"total"`
}

func upsertMember(ctx context.Context, tx *sql.Tx, p identity.Profile) (Member, string, error) {
	var m Member
	err := tx.QueryRowContext(ctx, `SELECT m.id,m.username,m.display_name FROM members m JOIN identities i ON i.member_id=m.id WHERE i.provider=? AND i.issuer=? AND i.subject=?`, p.Provider, p.Issuer, p.Subject).Scan(&m.ID, &m.Username, &m.DisplayName)
	if errors.Is(err, sql.ErrNoRows) {
		m = Member{ID: randomID(), Username: p.Username, DisplayName: p.DisplayName}
		if _, err = tx.ExecContext(ctx, `INSERT INTO members(id,username,display_name) VALUES(?,?,?)`, m.ID, m.Username, m.DisplayName); err != nil {
			return Member{}, "", err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO identities(provider,issuer,subject,member_id) VALUES(?,?,?,?)`, p.Provider, p.Issuer, p.Subject, m.ID)
		return m, "created", err
	}
	if err != nil {
		return Member{}, "", err
	}
	if m.Username == p.Username && m.DisplayName == p.DisplayName {
		return m, "unchanged", nil
	}
	m.Username, m.DisplayName = p.Username, p.DisplayName
	_, err = tx.ExecContext(ctx, `UPDATE members SET username=?,display_name=? WHERE id=?`, m.Username, m.DisplayName, m.ID)
	return m, "updated", err
}

// Recheck the administrator session after the directory read, inside the write
// transaction. An expired/reset session cannot finish an import.
func (s *Store) ImportMembers(ctx context.Context, token string, profiles []identity.Profile, now time.Time) (ImportResult, error) {
	if len(profiles) == 0 || len(profiles) > 10000 {
		return ImportResult{}, errors.New("invalid directory size")
	}
	seen := map[string]bool{}
	for _, p := range profiles {
		key := p.Provider + "\x00" + p.Issuer + "\x00" + p.Subject
		if p.Provider != "freeipa" || p.Issuer == "" || p.Subject == "" || p.Username == "" || len(p.Username) > 64 || len(p.DisplayName) > 1024 || strings.ContainsAny(p.Subject+p.Issuer+p.Username, "\x00\r\n") || seen[key] {
			return ImportResult{}, errors.New("invalid or duplicate directory identity")
		}
		seen[key] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ImportResult{}, err
	}
	defer tx.Rollback()
	var actor string
	if err = tx.QueryRowContext(ctx, `SELECT member_id FROM sessions WHERE token_hash=? AND administrator=1 AND expires_at>?`, tokenHash(token), now.UnixNano()).Scan(&actor); errors.Is(err, sql.ErrNoRows) {
		return ImportResult{}, ErrNotFound
	} else if err != nil {
		return ImportResult{}, err
	}
	result := ImportResult{Total: len(profiles)}
	for _, p := range profiles {
		m, state, e := upsertMember(ctx, tx, p)
		if e != nil {
			return ImportResult{}, e
		}
		switch state {
		case "created":
			result.Created++
			err = audit(ctx, tx, now, actor, "member.imported", m.ID)
		case "updated":
			result.Updated++
			err = audit(ctx, tx, now, actor, "member.updated", m.ID)
		default:
			result.Unchanged++
		}
		if err != nil {
			return ImportResult{}, err
		}
	}
	if err = audit(ctx, tx, now, actor, "directory.imported", actor); err != nil {
		return ImportResult{}, err
	}
	return result, tx.Commit()
}

type UserSummary struct {
	Member
	Sources      string     `json:"sources"`
	LastLogin    *time.Time `json:"last_login"`
	ActiveGrants int        `json:"active_grants"`
}
type UserPage struct {
	Items  []UserSummary `json:"items"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

func (s *Store) Users(ctx context.Context, query string, limit, offset int, now time.Time) (UserPage, error) {
	result := UserPage{Items: []UserSummary{}, Limit: limit, Offset: offset}
	pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(query) + "%"
	where := ` WHERE m.username LIKE ? ESCAPE '!' OR m.display_name LIKE ? ESCAPE '!'`
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM members m`+where, pattern, pattern).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.id,m.username,m.display_name,COALESCE((SELECT group_concat(DISTINCT provider) FROM identities i WHERE i.member_id=m.id),''),(SELECT MAX(at) FROM audit_events a WHERE a.actor_id=m.id AND a.action='session.login'),(SELECT COUNT(*) FROM grants g WHERE g.member_id=m.id AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>?)) FROM members m`+where+` ORDER BY m.username,m.id LIMIT ? OFFSET ?`, now.UnixNano(), pattern, pattern, limit, offset)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item UserSummary
		var login sql.NullInt64
		if err = rows.Scan(&item.ID, &item.Username, &item.DisplayName, &item.Sources, &login, &item.ActiveGrants); err != nil {
			return result, err
		}
		if login.Valid {
			v := time.Unix(0, login.Int64).UTC()
			item.LastLogin = &v
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

type GrantPage struct {
	Items  []GrantRecord `json:"items"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

func (s *Store) UserGrants(ctx context.Context, member string, limit, offset int) (GrantPage, error) {
	result := GrantPage{Items: []GrantRecord{}, Limit: limit, Offset: offset}
	var found int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM members WHERE id=?`, member).Scan(&found); errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	} else if err != nil {
		return result, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM grants WHERE member_id=?`, member).Scan(&result.Total); err != nil {
		return result, err
	}
	items, err := s.queryGrants(ctx, grantSelect+` WHERE g.member_id=? ORDER BY g.created_at DESC,g.id LIMIT ? OFFSET ?`, member, limit, offset)
	result.Items = items
	return result, err
}

func (s *Store) MatchesIdentity(ctx context.Context, member string, p identity.Profile) (bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT member_id FROM identities WHERE provider=? AND issuer=? AND subject=?`, p.Provider, p.Issuer, p.Subject).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return id == member && err == nil, err
}
