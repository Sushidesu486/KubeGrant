package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/grant"
)

type Execution struct {
	State      string     `json:"state"`
	CheckedAt  *time.Time `json:"checked_at"`
	ErrorCode  string     `json:"error_code,omitempty"`
	BindingUID string     `json:"-"`
}

func (g GrantRecord) MarshalJSON() ([]byte, error) {
	type plainGrant grant.Grant
	value := plainGrant(g.Grant)
	value.CredentialPolicy = g.Policy()
	var expiry *time.Time
	if !g.Permanent {
		expiry = &g.ExpiresAt
	}
	return json.Marshal(struct {
		plainGrant
		ExpiresAt *time.Time `json:"expires_at"`
		Username  string     `json:"username"`
		Execution Execution  `json:"execution"`
	}{value, expiry, g.Username, g.Execution})
}

type NewGrant struct {
	MemberID, ClusterID, PermissionRef, Policy string
	ExpiresAt                                  time.Time
	Permanent                                  bool
}

func (s *Store) CreateGrant(ctx context.Context, actor, member, cluster, permission string, now, expires time.Time) (grant.Grant, error) {
	return s.CreateGrantWithPolicy(ctx, actor, NewGrant{MemberID: member, ClusterID: cluster, PermissionRef: permission, Policy: "standard", ExpiresAt: expires}, now)
}

func (s *Store) CreateGrantWithPolicy(ctx context.Context, actor string, in NewGrant, now time.Time) (grant.Grant, error) {
	g := grant.Grant{ID: randomID(), MemberID: in.MemberID, ClusterID: in.ClusterID, PermissionRef: in.PermissionRef, CredentialPolicy: in.Policy, CreatedAt: now, ExpiresAt: in.ExpiresAt, Permanent: in.Permanent}
	if err := g.Validate(); err != nil {
		return grant.Grant{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return grant.Grant{}, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM members WHERE id=?`, g.MemberID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return grant.Grant{}, ErrNotFound
	} else if err != nil {
		return grant.Grant{}, err
	}
	var expiry any
	if !g.Permanent {
		expiry = g.ExpiresAt.UnixNano()
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO grants(id,member_id,cluster_id,permission_ref,credential_policy,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, g.ID, g.MemberID, g.ClusterID, g.PermissionRef, g.Policy(), now.UnixNano(), expiry); err != nil {
		return grant.Grant{}, err
	}
	if err = audit(ctx, tx, now, actor, "grant.created", g.ID); err != nil {
		return grant.Grant{}, err
	}
	return g, tx.Commit()
}

const grantSelect = `SELECT g.id,g.member_id,g.cluster_id,g.permission_ref,g.credential_policy,g.created_at,g.expires_at,g.revoked_at,m.username,COALESCE(e.state,'pending'),COALESCE(e.checked_at,0),COALESCE(e.error_code,''),COALESCE(e.binding_uid,'') FROM grants g JOIN members m ON m.id=g.member_id LEFT JOIN grant_execution e ON e.grant_id=g.id`

type rowScanner interface{ Scan(...any) error }

func scanGrant(row rowScanner) (GrantRecord, error) {
	var g GrantRecord
	var created, checked int64
	var expires, revoked sql.NullInt64
	err := row.Scan(&g.ID, &g.MemberID, &g.ClusterID, &g.PermissionRef, &g.CredentialPolicy, &created, &expires, &revoked, &g.Username, &g.Execution.State, &checked, &g.Execution.ErrorCode, &g.Execution.BindingUID)
	if errors.Is(err, sql.ErrNoRows) {
		return g, ErrNotFound
	}
	if err != nil {
		return g, err
	}
	g.CreatedAt = time.Unix(0, created).UTC()
	g.Permanent = !expires.Valid
	if expires.Valid {
		g.ExpiresAt = time.Unix(0, expires.Int64).UTC()
	}
	if revoked.Valid {
		at := time.Unix(0, revoked.Int64).UTC()
		g.RevokedAt = &at
	}
	if checked != 0 {
		at := time.Unix(0, checked).UTC()
		g.Execution.CheckedAt = &at
	}
	return g, nil
}

func (s *Store) Grant(ctx context.Context, id string) (GrantRecord, error) {
	return scanGrant(s.db.QueryRowContext(ctx, grantSelect+` WHERE g.id=?`, id))
}

func (s *Store) Grants(ctx context.Context, member string) ([]GrantRecord, error) {
	query := grantSelect
	args := []any{}
	if member != "" {
		query += ` WHERE g.member_id=?`
		args = append(args, member)
	}
	return s.queryGrants(ctx, query+` ORDER BY g.created_at DESC,g.id LIMIT 500`, args...)
}

// ControllerGrants deliberately does not reuse the UI's 500-row cap.
func (s *Store) ControllerGrants(ctx context.Context, cluster, after string, active bool, now time.Time) ([]GrantRecord, error) {
	predicate := `g.revoked_at IS NULL AND g.created_at<=? AND (g.expires_at IS NULL OR g.expires_at>?)`
	if !active {
		predicate = `NOT (` + predicate + `)`
	}
	return s.queryGrants(ctx, grantSelect+` WHERE g.cluster_id=? AND g.id>? AND (`+predicate+`) ORDER BY g.id LIMIT 100`, cluster, after, now.UnixNano(), now.UnixNano())
}

func (s *Store) queryGrants(ctx context.Context, q string, args ...any) ([]GrantRecord, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []GrantRecord{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, g)
	}
	return result, rows.Err()
}

// SetExecution refuses a stale 'applied' result after concurrent revocation.
func (s *Store) SetExecution(ctx context.Context, id, state, uid, code string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT state FROM grant_execution WHERE grant_id=g.id),'pending') FROM grants g WHERE g.id=?`, id).Scan(&previous); err != nil {
		return err
	}
	if state == "applied" {
		var valid int
		if err = tx.QueryRowContext(ctx, `SELECT 1 FROM grants WHERE id=? AND revoked_at IS NULL AND created_at<=? AND (expires_at IS NULL OR expires_at>?)`, id, now.UnixNano(), now.UnixNano()).Scan(&valid); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO grant_execution(grant_id,state,checked_at,error_code,binding_uid) VALUES(?,?,?,?,?) ON CONFLICT(grant_id) DO UPDATE SET state=excluded.state,checked_at=excluded.checked_at,error_code=excluded.error_code,binding_uid=excluded.binding_uid`, id, state, now.UnixNano(), code, uid); err != nil {
		return err
	}
	if previous != state {
		if err = audit(ctx, tx, now, "controller", "grant.execution."+state, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Heartbeat(ctx context.Context, cluster, role string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO controller_heartbeat(cluster_id,permission_ref,ready_at) VALUES(?,?,?) ON CONFLICT(cluster_id) DO UPDATE SET permission_ref=excluded.permission_ref,ready_at=excluded.ready_at`, cluster, role, now.UnixNano())
	return err
}

func (s *Store) ControllerReady(ctx context.Context, cluster, role string, now time.Time) bool {
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT ready_at FROM controller_heartbeat WHERE cluster_id=? AND permission_ref=?`, cluster, role).Scan(&at)
	return err == nil && at <= now.UnixNano() && now.Sub(time.Unix(0, at)) < 30*time.Second
}
