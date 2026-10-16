package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/credential"
	"github.com/Sushidesu486/KubeGrant/internal/identity"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

type Options struct {
	StaticDir, PublicURL     string
	SecureCookies            bool
	Authenticator            identity.Authenticator
	Store                    *storage.Store
	SessionTTL, GrantMaxTTL  time.Duration
	ClusterID, PermissionRef string
	Now                      func() time.Time
	SigningEnabled           bool
	ClusterEndpoint          string
	ClusterCA                []byte
}

type attemptCounter struct {
	first time.Time
	count int
}
type access struct {
	opts      Options
	mu        sync.Mutex
	attempts  map[string]attemptCounter
	inflight  chan struct{}
	downloads chan struct{}
}

func (a *access) configured() bool { return a.opts.Authenticator != nil && a.opts.Store != nil }
func (a *access) canManageGrants() bool {
	return a.configured() && a.opts.ClusterID != "" && a.opts.PermissionRef != ""
}
func (a *access) cookieName() string {
	if a.opts.SecureCookies {
		return "__Host-kubegrant"
	}
	return "kubegrant-session"
}
func (a *access) token(r *http.Request) string {
	cookie, err := r.Cookie(a.cookieName())
	if err != nil {
		return ""
	}
	return cookie.Value
}
func (a *access) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), HttpOnly: true, Secure: a.opts.SecureCookies, SameSite: http.SameSiteStrictMode})
}

func (a *access) mutationAllowed(w http.ResponseWriter, r *http.Request) bool {
	if a.opts.PublicURL == "" || r.Header.Get("Origin") != a.opts.PublicURL {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "json_required"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err = d.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return false
	}
	if err = d.Decode(new(any)); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return false
	}
	return true
}

func (a *access) limited(username string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for name, c := range a.attempts {
		if now.Sub(c.first) >= time.Minute {
			delete(a.attempts, name)
		}
	}
	key := strings.ToLower(strings.TrimSpace(username))
	c, ok := a.attempts[key]
	if !ok {
		if len(a.attempts) >= 1024 {
			return true
		}
		c = attemptCounter{first: now}
	}
	c.count++
	a.attempts[key] = c
	return c.count > 5
}

func (a *access) login(w http.ResponseWriter, r *http.Request) {
	if !a.configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authentication_not_configured"})
		return
	}
	if !a.mutationAllowed(w, r) {
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	now := a.opts.Now()
	if a.limited(input.Username, now) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_attempts"})
		return
	}
	select {
	case a.inflight <- struct{}{}:
		defer func() { <-a.inflight }()
	default:
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_attempts"})
		return
	}
	profile, err := a.opts.Authenticator.Authenticate(r.Context(), input.Username, input.Password)
	input.Password = ""
	if errors.Is(err, identity.ErrCredentials) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "identity_unavailable"})
		return
	}
	// The session lifetime starts after the external authentication completes.
	now = a.opts.Now()
	session, token, err := a.opts.Store.StartSession(r.Context(), profile, now, now.Add(a.opts.SessionTTL), a.token(r))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: token, Path: "/", HttpOnly: true, Secure: a.opts.SecureCookies, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: int(a.opts.SessionTTL.Seconds())})
	writeJSON(w, http.StatusOK, session)
}

type authenticatedHandler func(http.ResponseWriter, *http.Request, storage.Session)

func (a *access) require(admin bool, next authenticatedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.configured() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authentication_not_configured"})
			return
		}
		session, err := a.opts.Store.Session(r.Context(), a.token(r), a.opts.Now())
		if errors.Is(err, storage.ErrNotFound) {
			a.clearCookie(w)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		if admin && !session.Administrator {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator_required"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !a.mutationAllowed(w, r) {
			return
		}
		next(w, r, session)
	}
}

func (a *access) routes(mux *http.ServeMux) {
	a.credentialRoutes(mux)
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.HandleFunc("GET /api/v1/me", a.require(false, func(w http.ResponseWriter, r *http.Request, s storage.Session) { writeJSON(w, http.StatusOK, s) }))
	mux.HandleFunc("POST /api/v1/auth/logout", a.require(false, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if err := a.opts.Store.EndSession(r.Context(), a.token(r), s.Member.ID, a.opts.Now()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		a.clearCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET /api/v1/grants", a.require(false, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		items, err := a.opts.Store.Grants(r.Context(), s.Member.ID)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}))
	mux.HandleFunc("GET /api/v1/admin/grants", a.require(true, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		items, err := a.opts.Store.Grants(r.Context(), "")
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}))
	mux.HandleFunc("GET /api/v1/admin/members", a.require(true, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		items, err := a.opts.Store.Members(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}))
	mux.HandleFunc("GET /api/v1/admin/audit", a.require(true, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		items, err := a.opts.Store.Audit(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}))
	mux.HandleFunc("POST /api/v1/admin/grants", a.require(true, a.createGrant))
	mux.HandleFunc("POST /api/v1/admin/grants/{id}/revoke", a.require(true, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if !a.canManageGrants() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "grant_target_not_configured"})
			return
		}
		err := a.opts.Store.RevokeGrant(r.Context(), s.Member.ID, r.PathValue("id"), a.opts.Now())
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "grant_not_found"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func (a *access) createGrant(w http.ResponseWriter, r *http.Request, s storage.Session) {
	if !a.canManageGrants() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "grant_target_not_configured"})
		return
	}
	var input struct {
		MemberID  string    `json:"member_id"`
		ExpiresAt time.Time `json:"expires_at"`
		Permanent bool      `json:"permanent"`
		Policy    string    `json:"credential_policy"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	now := a.opts.Now()
	if input.Policy == "" {
		input.Policy = string(credential.Standard)
	}
	if input.MemberID == "" || (input.Policy != string(credential.Standard) && input.Policy != string(credential.Operations)) || (input.Permanent && !input.ExpiresAt.IsZero()) || (!input.Permanent && (!input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(a.opts.GrantMaxTTL)))) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	g, err := a.opts.Store.CreateGrantWithPolicy(r.Context(), s.Member.ID, storage.NewGrant{MemberID: input.MemberID, ClusterID: a.opts.ClusterID, PermissionRef: a.opts.PermissionRef, Policy: input.Policy, Permanent: input.Permanent, ExpiresAt: input.ExpiresAt}, now)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "member_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
		return
	}
	writeJSON(w, http.StatusCreated, g)
}
