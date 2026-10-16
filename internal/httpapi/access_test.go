package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/identity"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

type fixtureIdentity struct{}

func (fixtureIdentity) Authenticate(_ context.Context, user, password string) (identity.Profile, error) {
	if user == "offline" {
		return identity.Profile{}, identity.ErrUnavailable
	}
	if password != "test-password" {
		return identity.Profile{}, identity.ErrCredentials
	}
	return identity.Profile{Provider: "test", Issuer: "fixture", Subject: user, Username: user, DisplayName: user, Administrator: user == "admin"}, nil
}

func TestLoginAuthorizationAndSessionSecurity(t *testing.T) {
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	store, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h, err := NewHandler(Options{Authenticator: fixtureIdentity{}, Store: store, PublicURL: "https://kubegrant.example", SecureCookies: true, ClusterID: "cluster", PermissionRef: "existing", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://kubegrant.example"+path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	login := func(user string) (storage.Session, *http.Cookie) {
		w := request("POST", "/api/v1/auth/login", `{"username":"`+user+`","password":"test-password"}`, "https://kubegrant.example", nil)
		if w.Code != 200 {
			t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
		}
		var session storage.Session
		if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
			t.Fatal(err)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("missing session cookie")
		}
		cookie := cookies[0]
		if cookie.Name != "__Host-kubegrant" || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatal("unsafe session cookie")
		}
		if bytes.Contains(w.Body.Bytes(), []byte(cookie.Value)) {
			t.Fatal("session token leaked into response body")
		}
		return session, cookie
	}
	for _, path := range []string{"/api/v1/me", "/api/v1/grants", "/api/v1/admin/grants", "/api/v1/admin/members", "/api/v1/admin/audit"} {
		if got := request("GET", path, "", "", nil).Code; got != 401 {
			t.Fatalf("anonymous access to %s: %d", path, got)
		}
	}
	member, memberCookie := login("member")
	_, adminCookie := login("admin")
	if got := request("GET", "/api/v1/admin/members", "", "", memberCookie).Code; got != 403 {
		t.Fatal("member accessed administrator endpoint")
	}
	body := `{"member_id":"` + member.Member.ID + `","expires_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`
	for _, origin := range []string{"", "null", "https://attacker.example"} {
		if got := request("POST", "/api/v1/admin/grants", body, origin, adminCookie).Code; got != 403 {
			t.Fatal("CSRF origin bypass:", origin, got)
		}
	}
	if got := request("POST", "/api/v1/admin/grants", body, "https://kubegrant.example", memberCookie).Code; got != 403 {
		t.Fatal("member created a grant")
	}
	w := request("POST", "/api/v1/admin/grants", body, "https://kubegrant.example", adminCookie)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	list := request("GET", "/api/v1/grants", "", "", memberCookie)
	if list.Code != 200 || !strings.Contains(list.Body.String(), created.ID) {
		t.Fatal("member cannot see own grant")
	}
	login("other")
	_, otherCookie := login("other")
	if w := request("GET", "/api/v1/grants", "", "", otherCookie); strings.Contains(w.Body.String(), created.ID) {
		t.Fatal("cross-member grant disclosure")
	}
	if w := request("POST", "/api/v1/admin/grants", strings.TrimSuffix(body, "}")+`,"cluster_id":"arbitrary"}`, "https://kubegrant.example", adminCookie); w.Code != 400 {
		t.Fatal("client altered configured target")
	}
	if w := request("POST", "/api/v1/admin/grants/"+created.ID+"/revoke", "", "https://kubegrant.example", adminCookie); w.Code != 204 {
		t.Fatal("cannot revoke grant", w.Code)
	}
	if w := request("POST", "/api/v1/auth/logout", "", "https://kubegrant.example", memberCookie); w.Code != 204 {
		t.Fatal("logout failed")
	}
	if w := request("GET", "/api/v1/me", "", "", memberCookie); w.Code != 401 {
		t.Fatal("logged out cookie still works")
	}
	now = now.Add(31 * time.Minute)
	if w := request("GET", "/api/v1/admin/audit", "", "", adminCookie); w.Code != 401 {
		t.Fatal("expired administrator cookie still works")
	}
	if w := request("POST", "/api/v1/auth/login", `{"username":"wrong","password":"wrong"}`, "https://kubegrant.example", nil); w.Code != 401 {
		t.Fatal("bad password accepted")
	}
	if w := request("POST", "/api/v1/auth/login", `{"username":"offline","password":"test-password"}`, "https://kubegrant.example", nil); w.Code != 503 {
		t.Fatal("provider failure must fail closed")
	}
	for i := 0; i < 6; i++ {
		w := request("POST", "/api/v1/auth/login", `{"username":"throttled","password":"wrong"}`, "https://kubegrant.example", nil)
		if i == 5 && w.Code != 429 {
			t.Fatal("login rate limit not enforced")
		}
	}
	large := `{"username":"huge","password":"` + strings.Repeat("x", 9000) + `"}`
	if w := request("POST", "/api/v1/auth/login", large, "https://kubegrant.example", nil); w.Code != 400 {
		t.Fatal("oversized login body accepted")
	}
	if w := request("GET", "/api/v1/status", "", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"kubeconfig_download":false`) {
		t.Fatal("unfinished signing advertised as ready")
	}
}
