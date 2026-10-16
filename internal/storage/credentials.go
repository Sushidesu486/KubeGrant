package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/credential"
)

var ErrBusy = errors.New("credential request already pending")

type CredentialRecord struct {
	Request                  credential.Request
	State, CSRUID, ErrorCode string
	Certificate              []byte
	ExpiresAt                *time.Time
	WaitUntil                time.Time
}

type CredentialSummary struct {
	ID          string            `json:"id"`
	GrantID     string            `json:"grant_id"`
	MemberID    string            `json:"member_id"`
	Username    string            `json:"username"`
	Policy      credential.Policy `json:"credential_policy"`
	Fingerprint string            `json:"public_key_sha256"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at"`
	State       string            `json:"state"`
	ErrorCode   string            `json:"error_code,omitempty"`
}

func (s *Store) QueueCredential(ctx context.Context, r credential.Request, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := scanGrant(tx.QueryRowContext(ctx, grantSelect+` WHERE g.id=?`, r.GrantID))
	if err != nil {
		return err
	}
	if _, err = credential.Policy(g.Policy()).ValidateRequest(r, g.Grant, now); err != nil {
		return err
	}
	if g.Execution.State != "applied" || g.Execution.CheckedAt == nil || now.Before(*g.Execution.CheckedAt) || now.Sub(*g.Execution.CheckedAt) >= 30*time.Second {
		return credential.ErrAuthorization
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM credential_requests WHERE member_id=? AND state='pending' AND wait_until>?`, r.MemberID, now.UnixNano()).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrBusy
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO credential_requests(id,grant_id,member_id,request_json,state,created_at,wait_until,not_after) VALUES(?,?,?,?,'pending',?,?,?)`, r.ID, r.GrantID, r.MemberID, body, r.CreatedAt.UnixNano(), now.Add(20*time.Second).UnixNano(), r.NotAfter.UnixNano()); err != nil {
		return err
	}
	if err = audit(ctx, tx, now, r.MemberID, "credential.requested", r.GrantID); err != nil {
		return err
	}
	return tx.Commit()
}

const credentialSelect = `SELECT request_json,state,csr_uid,certificate,expires_at,error_code,wait_until FROM credential_requests`

func scanCredential(row rowScanner) (CredentialRecord, error) {
	var c CredentialRecord
	var data []byte
	var expiry sql.NullInt64
	var until int64
	if err := row.Scan(&data, &c.State, &c.CSRUID, &c.Certificate, &expiry, &c.ErrorCode, &until); errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	} else if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c.Request); err != nil {
		return c, err
	}
	if expiry.Valid {
		t := time.Unix(0, expiry.Int64).UTC()
		c.ExpiresAt = &t
	}
	c.WaitUntil = time.Unix(0, until).UTC()
	return c, nil
}

func (s *Store) Credential(ctx context.Context, id string) (CredentialRecord, error) {
	return scanCredential(s.db.QueryRowContext(ctx, credentialSelect+` WHERE id=?`, id))
}

func (s *Store) PendingCredentials(ctx context.Context, after string) ([]CredentialRecord, error) {
	rows, err := s.db.QueryContext(ctx, credentialSelect+` WHERE state='pending' AND id>? ORDER BY id LIMIT 100`, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []CredentialRecord{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (s *Store) SetCSRUID(ctx context.Context, id, uid string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE credential_requests SET csr_uid=? WHERE id=? AND state='pending' AND (csr_uid='' OR csr_uid=?)`, uid, id, uid)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrNotFound
	}
	return err
}

// CompleteCredential checks authorization and the request again while holding
// the SQLite write lock; a concurrent revoke cannot leave an issued result.
func (s *Store) CompleteCredential(ctx context.Context, id string, cert []byte, expires, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	c, err := scanCredential(tx.QueryRowContext(ctx, credentialSelect+` WHERE id=?`, id))
	if err != nil {
		return err
	}
	if c.State != "pending" || !now.Before(c.WaitUntil) {
		return ErrNotFound
	}
	g, err := scanGrant(tx.QueryRowContext(ctx, grantSelect+` WHERE g.id=?`, c.Request.GrantID))
	if err != nil {
		return err
	}
	if _, err = credential.Policy(g.Policy()).ValidateRequest(c.Request, g.Grant, now); err != nil {
		return err
	}
	if len(cert) == 0 || !expires.After(now) || expires.After(c.Request.NotAfter) || g.Execution.State != "applied" {
		return credential.ErrCertificate
	}
	if _, err = tx.ExecContext(ctx, `UPDATE credential_requests SET state='issued',certificate=?,expires_at=? WHERE id=?`, cert, expires.UnixNano(), id); err != nil {
		return err
	}
	if err = audit(ctx, tx, now, "controller", "credential.issued", c.Request.GrantID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) EndCredential(ctx context.Context, id, state, code string, now time.Time) error {
	if state != "failed" && state != "abandoned" {
		return errors.New("invalid terminal state")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	c, err := scanCredential(tx.QueryRowContext(ctx, credentialSelect+` WHERE id=?`, id))
	if err != nil {
		return err
	}
	if c.State != "pending" {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE credential_requests SET state=?,error_code=? WHERE id=? AND state='pending'`, state, code, id); err != nil {
		return err
	}
	if err = audit(ctx, tx, now, "controller", "credential."+state, c.Request.GrantID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CredentialSummaries(ctx context.Context, member string, now time.Time) ([]CredentialSummary, error) {
	q := `SELECT c.request_json,c.state,c.expires_at,c.error_code,m.username,g.revoked_at,g.expires_at FROM credential_requests c JOIN members m ON m.id=c.member_id JOIN grants g ON g.id=c.grant_id`
	args := []any{}
	if member != "" {
		q += ` WHERE c.member_id=?`
		args = append(args, member)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY c.created_at DESC,c.id LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []CredentialSummary{}
	for rows.Next() {
		var data []byte
		var state, code, user string
		var expiry, revoked, grantExpiry sql.NullInt64
		if err := rows.Scan(&data, &state, &expiry, &code, &user, &revoked, &grantExpiry); err != nil {
			return nil, err
		}
		var r credential.Request
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		item := CredentialSummary{ID: r.ID, GrantID: r.GrantID, MemberID: r.MemberID, Username: user, Policy: r.Policy, Fingerprint: r.Fingerprint, CreatedAt: r.CreatedAt, State: state, ErrorCode: code}
		if expiry.Valid {
			t := time.Unix(0, expiry.Int64).UTC()
			item.ExpiresAt = &t
		}
		if state == "issued" {
			if revoked.Valid || (grantExpiry.Valid && grantExpiry.Int64 <= now.UnixNano()) {
				item.State = "grant_inactive"
			} else if expiry.Valid && expiry.Int64 <= now.UnixNano() {
				item.State = "expired"
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) PrepareDownload(ctx context.Context, token, requestID string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var actor, grantID string
	err = tx.QueryRowContext(ctx, `SELECT c.member_id,c.grant_id FROM credential_requests c JOIN grants g ON g.id=c.grant_id JOIN sessions s ON s.member_id=c.member_id JOIN grant_execution e ON e.grant_id=g.id WHERE c.id=? AND c.state='issued' AND c.expires_at>? AND s.token_hash=? AND s.expires_at>? AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>?) AND e.state='applied' AND e.checked_at>?`, requestID, now.UnixNano(), tokenHash(token), now.UnixNano(), now.UnixNano(), now.Add(-30*time.Second).UnixNano()).Scan(&actor, &grantID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err = audit(ctx, tx, now, actor, "credential.prepared", grantID); err != nil {
		return err
	}
	return tx.Commit()
}
