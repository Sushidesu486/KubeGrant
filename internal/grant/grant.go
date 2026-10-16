package grant

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Grant records an administrator's authorization. It contains no credentials.
// PermissionRef identifies an existing permission set; it does not define RBAC rules.
type Grant struct {
	ID               string     `json:"id"`
	MemberID         string     `json:"member_id"`
	ClusterID        string     `json:"cluster_id"`
	PermissionRef    string     `json:"permission_ref"`
	CredentialPolicy string     `json:"credential_policy"`
	Permanent        bool       `json:"permanent"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

func (g Grant) Validate() error {
	for _, field := range []struct{ name, value string }{
		{"id", g.ID}, {"member_id", g.MemberID},
		{"cluster_id", g.ClusterID}, {"permission_ref", g.PermissionRef},
	} {
		if strings.TrimSpace(field.value) == "" {
			return errors.New(field.name + " is required")
		}
	}
	if g.CreatedAt.IsZero() || (!g.Permanent && (g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.CreatedAt))) || (g.Permanent && !g.ExpiresAt.IsZero()) {
		return errors.New("expiry must be later than creation")
	}
	if g.Policy() != "standard" && g.Policy() != "operations" {
		return errors.New("unknown credential policy")
	}
	if g.RevokedAt != nil && g.RevokedAt.Before(g.CreatedAt) {
		return errors.New("revocation must not precede creation")
	}
	return nil
}

// ActiveAt only describes the authorization record. Kubernetes access enforcement
// must be implemented separately; expiry here does not invalidate a kubeconfig.
func (g Grant) ActiveAt(at time.Time) bool {
	return g.Validate() == nil && !at.Before(g.CreatedAt) && (g.Permanent || at.Before(g.ExpiresAt)) &&
		(g.RevokedAt == nil || at.Before(*g.RevokedAt))
}

func (g Grant) Policy() string {
	if g.CredentialPolicy == "" {
		return "standard"
	}
	return g.CredentialPolicy
}

// Permanent is explicit in the domain; its SQL/JSON expiry is NULL, never a
// made-up distant date. Finite grants still require an expiry.
func (g Grant) MarshalJSON() ([]byte, error) {
	type plain Grant
	var expiry *time.Time
	if !g.Permanent {
		expiry = &g.ExpiresAt
	}
	value := plain(g)
	value.CredentialPolicy = g.Policy()
	return json.Marshal(struct {
		plain
		ExpiresAt *time.Time `json:"expires_at"`
	}{value, expiry})
}
