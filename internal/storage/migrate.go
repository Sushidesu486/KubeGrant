package storage

import (
	"context"
	"database/sql"
	"errors"
)

func migrate(db *sql.DB) error {
	ctx := context.Background()
	c, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err = c.ExecContext(ctx, `PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; BEGIN IMMEDIATE;`); err != nil {
		return err
	}
	defer c.ExecContext(ctx, `ROLLBACK`)
	var version int
	if err = c.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version < 0 || version > 2 {
		return errors.New("unsupported database schema version")
	}
	if version == 0 {
		if _, err = c.ExecContext(ctx, schemaV1); err != nil {
			return err
		}
		version = 1
	}
	if version == 1 {
		if _, err = c.ExecContext(ctx, schemaV2); err != nil {
			return err
		}
	}
	_, err = c.ExecContext(ctx, `COMMIT`)
	return err
}

const schemaV1 = `
CREATE TABLE members (id TEXT PRIMARY KEY, username TEXT NOT NULL, display_name TEXT NOT NULL);
CREATE TABLE identities (provider TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, member_id TEXT NOT NULL REFERENCES members(id), PRIMARY KEY(provider,issuer,subject));
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id), administrator INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE grants (id TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id), cluster_id TEXT NOT NULL, permission_ref TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE INDEX grants_member ON grants(member_id,created_at);
CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT NOT NULL);
PRAGMA user_version=1;`

const schemaV2 = `
ALTER TABLE grants RENAME TO grants_v1;
CREATE TABLE grants (id TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id), cluster_id TEXT NOT NULL, permission_ref TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, revoked_at INTEGER, credential_policy TEXT NOT NULL DEFAULT 'standard' CHECK(credential_policy IN ('standard','operations')));
INSERT INTO grants(id,member_id,cluster_id,permission_ref,created_at,expires_at,revoked_at) SELECT id,member_id,cluster_id,permission_ref,created_at,expires_at,revoked_at FROM grants_v1;
DROP TABLE grants_v1;
CREATE INDEX grants_member ON grants(member_id,created_at);
CREATE TABLE grant_execution (grant_id TEXT PRIMARY KEY REFERENCES grants(id), state TEXT NOT NULL CHECK(state IN ('pending','applied','revoking','revoked','expired','error')), checked_at INTEGER NOT NULL, error_code TEXT NOT NULL, binding_uid TEXT NOT NULL);
CREATE TABLE credential_requests (id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id), member_id TEXT NOT NULL REFERENCES members(id), request_json BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','issued','failed','abandoned')), created_at INTEGER NOT NULL, wait_until INTEGER NOT NULL, not_after INTEGER NOT NULL, csr_uid TEXT NOT NULL DEFAULT '', certificate BLOB, expires_at INTEGER, error_code TEXT NOT NULL DEFAULT '');
CREATE INDEX credential_queue ON credential_requests(state,created_at);
CREATE INDEX credential_member ON credential_requests(member_id,created_at);
CREATE TABLE controller_heartbeat (cluster_id TEXT PRIMARY KEY, permission_ref TEXT NOT NULL, ready_at INTEGER NOT NULL);
PRAGMA user_version=2;`
