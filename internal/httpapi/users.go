package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Sushidesu486/KubeGrant/internal/identity"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

func userPagination(r *http.Request) (int, int, bool) {
	limit, offset := 50, 0
	if s := r.URL.Query().Get("limit"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil {
			return 0, 0, false
		}
		limit = v
	}
	if s := r.URL.Query().Get("offset"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil {
			return 0, 0, false
		}
		offset = v
	}
	return limit, offset, limit > 0 && limit <= 100 && offset >= 0 && offset <= 1000000
}
func (a *access) userRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/admin/users", a.require(true, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		limit, offset, ok := userPagination(r)
		query := strings.TrimSpace(r.URL.Query().Get("q"))
		if !ok || len(query) > 128 {
			writeJSON(w, 400, map[string]string{"error": "invalid_pagination"})
			return
		}
		items, err := a.opts.Store.Users(r.Context(), query, limit, offset, a.opts.Now())
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		writeJSON(w, 200, items)
	}))
	mux.HandleFunc("GET /api/v1/admin/users/{id}/grants", a.require(true, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		limit, offset, ok := userPagination(r)
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "invalid_pagination"})
			return
		}
		items, err := a.opts.Store.UserGrants(r.Context(), r.PathValue("id"), limit, offset)
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, 404, map[string]string{"error": "member_not_found"})
			return
		}
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		writeJSON(w, 200, items)
	}))
	mux.HandleFunc("POST /api/v1/admin/users/import", a.require(true, a.importUsers))
}
func (a *access) importUsers(w http.ResponseWriter, r *http.Request, s storage.Session) {
	directory, ok := a.opts.Authenticator.(identity.UserDirectory)
	if !ok {
		writeJSON(w, 503, map[string]string{"error": "directory_not_configured"})
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Password == "" || len(input.Password) > 4096 {
		writeJSON(w, 400, map[string]string{"error": "invalid_import"})
		return
	}
	if a.limited("directory:"+s.Member.ID, a.opts.Now()) {
		writeJSON(w, 429, map[string]string{"error": "too_many_attempts"})
		return
	}
	select {
	case a.inflight <- struct{}{}:
		defer func() { <-a.inflight }()
	default:
		writeJSON(w, 429, map[string]string{"error": "too_many_attempts"})
		return
	}
	actor, profiles, err := directory.ReadUsers(r.Context(), s.Member.Username, input.Password)
	input.Password = ""
	if errors.Is(err, identity.ErrCredentials) {
		writeJSON(w, 403, map[string]string{"error": "directory_credentials"})
		return
	}
	if errors.Is(err, identity.ErrDirectoryForbidden) {
		writeJSON(w, 403, map[string]string{"error": "directory_administrator_required"})
		return
	}
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "directory_unavailable"})
		return
	}
	// Reauthentication must resolve to the SAME stable IPA identity. A deleted and
	// recreated username cannot use an earlier member's still-valid session.
	matches, err := a.opts.Store.MatchesIdentity(r.Context(), s.Member.ID, actor)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "storage_unavailable"})
		return
	}
	if !actor.Administrator || actor.Provider != "freeipa" || !matches {
		writeJSON(w, 403, map[string]string{"error": "directory_identity_changed"})
		return
	}
	for _, profile := range profiles {
		if profile.Provider != actor.Provider || profile.Issuer != actor.Issuer {
			writeJSON(w, 503, map[string]string{"error": "directory_unavailable"})
			return
		}
	}
	result, err := a.opts.Store.ImportMembers(r.Context(), a.token(r), profiles, a.opts.Now())
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, 401, map[string]string{"error": "authentication_required"})
		return
	}
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "storage_unavailable"})
		return
	}
	writeJSON(w, 200, result)
}
