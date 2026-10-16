package grant

import (
	"testing"
	"time"
)

func TestGrantValidityAndRevocation(t *testing.T) {
	start := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	revoked := start.Add(30 * time.Minute)
	g := Grant{
		ID: "grant-1", MemberID: "member-1", ClusterID: "cluster-1",
		PermissionRef: "existing-permissions", CreatedAt: start, ExpiresAt: start.Add(time.Hour),
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before creation", start.Add(-time.Second), false},
		{"creation inclusive", start, true},
		{"before expiry", g.ExpiresAt.Add(-time.Nanosecond), true},
		{"expiry exclusive", g.ExpiresAt, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.ActiveAt(tc.at); got != tc.want {
				t.Fatalf("ActiveAt(%v) = %v, want %v", tc.at, got, tc.want)
			}
		})
	}
	g.RevokedAt = &revoked
	if !g.ActiveAt(revoked.Add(-time.Nanosecond)) || g.ActiveAt(revoked) {
		t.Fatal("revocation must end validity at its exact timestamp")
	}
}

func TestInvalidGrantCannotBeActive(t *testing.T) {
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	valid := Grant{ID: "g", MemberID: "m", ClusterID: "c", PermissionRef: "p", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	for _, tc := range []struct {
		name   string
		mutate func(*Grant)
	}{
		{"missing member", func(g *Grant) { g.MemberID = " " }},
		{"missing permission", func(g *Grant) { g.PermissionRef = "" }},
		{"missing creation", func(g *Grant) { g.CreatedAt = time.Time{} }},
		{"missing expiry", func(g *Grant) { g.ExpiresAt = time.Time{} }},
		{"zero duration", func(g *Grant) { g.ExpiresAt = g.CreatedAt }},
		{"early revocation", func(g *Grant) { earlier := now.Add(-time.Second); g.RevokedAt = &earlier }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := valid
			tc.mutate(&g)
			if g.Validate() == nil || g.ActiveAt(now) {
				t.Fatal("invalid grant must be rejected")
			}
		})
	}
}
