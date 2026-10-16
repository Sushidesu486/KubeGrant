package httpapi

import (
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

type importIdentity struct {
	calls                             int
	changed, removed, broken, foreign bool
	hook                              func()
}

func (p *importIdentity) Authenticate(_ context.Context, u, password string) (identity.Profile, error) {
	if password != "correct" {
		return identity.Profile{}, identity.ErrCredentials
	}
	return identity.Profile{Provider: "freeipa", Issuer: "issuer", Subject: "uuid-" + u, Username: u, Administrator: u == "admin"}, nil
}
func (p *importIdentity) ReadUsers(ctx context.Context, u, password string) (identity.Profile, []identity.Profile, error) {
	p.calls++
	actor, err := p.Authenticate(ctx, u, password)
	if err != nil {
		return actor, nil, err
	}
	if p.changed {
		actor.Subject = "recreated-admin"
	}
	if p.removed {
		return actor, nil, identity.ErrDirectoryForbidden
	}
	if p.hook != nil {
		p.hook()
	}
	profiles := []identity.Profile{actor, {Provider: "freeipa", Issuer: "issuer", Subject: "uuid-bob", Username: "bob"}}
	if p.foreign {
		profiles[1].Issuer = "another-directory"
	}
	if p.broken {
		return actor, profiles, identity.ErrDirectory
	}
	return actor, profiles, nil
}
func TestDirectoryImportAuthenticationAndAtomicity(t *testing.T) {
	now := time.Now().UTC()
	s, err := storage.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	auth := &importIdentity{}
	handler, err := NewHandler(Options{Store: s, Authenticator: auth, PublicURL: "https://kubegrant.example", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "https://kubegrant.example/api/v1"+path, strings.NewReader(body))
		if cookie != nil {
			req.AddCookie(cookie)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	login := func(user string) *http.Cookie {
		t.Helper()
		w := call("POST", "/auth/login", `{"username":"`+user+`","password":"correct"}`, "https://kubegrant.example", nil)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		return w.Result().Cookies()[0]
	}
	admin, member := login("admin"), login("member")
	for _, tc := range []struct {
		name, body, origin string
		cookie             *http.Cookie
		code               int
	}{
		{"anonymous", `{"password":"correct"}`, "https://kubegrant.example", nil, 401},
		{"ordinary member", `{"password":"correct"}`, "https://kubegrant.example", member, 403},
		{"csrf", `{"password":"correct"}`, "https://untrusted.invalid", admin, 403},
		{"arbitrary uploaded users", `{"password":"correct","users":[]}`, "https://kubegrant.example", admin, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := auth.calls
			w := call("POST", "/admin/users/import", tc.body, tc.origin, tc.cookie)
			if w.Code != tc.code || auth.calls != before {
				t.Fatal("untrusted request reached directory", w.Code)
			}
		})
	}
	for _, tc := range []struct {
		name, password string
		setup          func()
		code           int
	}{
		{"wrong password", "wrong", func() {}, 403},
		{"recreated administrator", "correct", func() { auth.changed = true }, 403},
		{"removed admin group", "correct", func() { auth.removed = true }, 403},
		{"partial directory failure", "correct", func() { auth.broken = true }, 503},
		{"foreign directory identity", "correct", func() { auth.foreign = true }, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			w := call("POST", "/admin/users/import", `{"password":"`+tc.password+`"}`, "https://kubegrant.example", admin)
			if w.Code != tc.code {
				t.Fatal(w.Code)
			}
			auth.changed = false
			auth.removed = false
			auth.broken = false
			auth.foreign = false
			page, err := s.Users(context.Background(), "bob", 20, 0, now)
			if err != nil || page.Total != 0 {
				t.Fatal("failed import changed users")
			}
		})
	}
	// Reset the operation rate limit so independent rejection cases do not hide
	// the success or final-session-check path.
	handler, err = NewHandler(Options{Store: s, Authenticator: auth, PublicURL: "https://kubegrant.example", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	w := call("POST", "/admin/users/import", `{"password":"correct"}`, "https://kubegrant.example", admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"created":1`) {
		t.Fatal("valid import failed", w.Code, w.Body.String())
	}
	w = call("GET", "/admin/users?q=bob&limit=1&offset=0", "", "", admin)
	var page storage.UserPage
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Total != 1 || page.Items[0].LastLogin != nil {
		t.Fatal("imported user not listable without login", w.Code)
	}
	if w = call("GET", "/admin/users", "", "", member); w.Code != 403 {
		t.Fatal("member listed all users")
	}
	if w = call("GET", "/admin/users?limit=-1", "", "", admin); w.Code != 400 {
		t.Fatal("bad pagination accepted")
	}
	auth.hook = func() { now = now.Add(time.Hour) }
	if w = call("POST", "/admin/users/import", `{"password":"correct"}`, "https://kubegrant.example", admin); w.Code != 401 {
		t.Fatal("expired administrator completed import", w.Code)
	}
}
