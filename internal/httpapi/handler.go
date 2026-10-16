package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func NewHandler(opts Options) (http.Handler, error) {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.SessionTTL == 0 {
		opts.SessionTTL = 30 * time.Minute
	}
	if opts.GrantMaxTTL == 0 {
		opts.GrantMaxTTL = 30 * 24 * time.Hour
	}
	a := &access{opts: opts, attempts: map[string]attemptCounter{}, inflight: make(chan struct{}, 4)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if a.configured() && opts.Store.Ping(r.Context()) == nil {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not_ready", "reason": "authentication_or_storage_unavailable",
		})
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		phase := "foundation"
		if a.configured() {
			phase = "access_management"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "kubegrant", "phase": phase, "identity_provider": "freeipa",
			"features":     map[string]bool{"login": a.configured(), "grant_management": a.canManageGrants(), "kubeconfig_download": false},
			"grant_target": map[string]any{"cluster_id": opts.ClusterID, "permission_ref": opts.PermissionRef, "max_ttl_seconds": int64(opts.GrantMaxTTL.Seconds())},
		})
	})
	a.routes(mux)
	// Reserve the API prefix so missing or unfinished endpoints never return the SPA.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	})
	if opts.StaticDir != "" {
		info, err := os.Stat(filepath.Join(opts.StaticDir, "index.html"))
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("static directory must contain an index.html file")
		}
		files := http.FileServer(http.Dir(opts.StaticDir))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
				return
			}
			files.ServeHTTP(w, r)
		})
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		mux.ServeHTTP(w, r)
	}), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
