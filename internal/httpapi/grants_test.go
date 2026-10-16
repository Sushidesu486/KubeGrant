package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

func TestExplicitPermanentGrantAndCredentialPolicy(t *testing.T) {
	now := time.Now().UTC()
	store, err := storage.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h, err := NewHandler(Options{Store: store, Authenticator: fixtureIdentity{}, PublicURL: "https://kubegrant.example", ClusterID: "cluster", PermissionRef: "existing", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://kubegrant.example"+path, strings.NewReader(body))
		r.Header.Set("Origin", "https://kubegrant.example")
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (storage.Session, *http.Cookie) {
		t.Helper()
		w := request("/api/v1/auth/login", `{"username":"`+name+`","password":"test-password"}`, nil)
		if w.Code != 200 {
			t.Fatal("login", w.Code)
		}
		var s storage.Session
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s, w.Result().Cookies()[0]
	}
	member, cookie := login("member")
	_, admin := login("admin")
	prefix := `{"member_id":"` + member.Member.ID + `"`
	for _, body := range []string{prefix + `}`, prefix + `,"permanent":false}`, prefix + `,"credential_policy":"forever","permanent":true}`, prefix + `,"permanent":true,"expires_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`} {
		if w := request("/api/v1/admin/grants", body, admin); w.Code != 400 {
			t.Fatal("ambiguous lifetime or policy accepted", w.Code)
		}
	}
	body := prefix + `,"permanent":true,"expires_at":null,"credential_policy":"operations"}`
	if w := request("/api/v1/admin/grants", body, cookie); w.Code != 403 {
		t.Fatal("member assigned permanent operations access")
	}
	w := request("/api/v1/admin/grants", body, admin)
	if w.Code != 201 {
		t.Fatal("permanent grant failed", w.Code)
	}
	var result map[string]any
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["expires_at"] != nil || result["permanent"] != true || result["credential_policy"] != "operations" || result["permission_ref"] != "existing" {
		t.Fatal("wrong permanent grant representation")
	}
	if !strings.Contains(w.Body.String(), `"expires_at":null`) {
		t.Fatal("permanent grant must expose null expiry")
	}
}
