package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/credential"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

func (a *access) signingReady(r *http.Request) bool {
	return a.canManageGrants() && a.opts.SigningEnabled && a.opts.Store.ControllerReady(r.Context(), a.opts.ClusterID, a.opts.PermissionRef, a.opts.Now())
}

func (a *access) credentialRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/grants/{id}/kubeconfig", a.require(false, a.download))
	for _, admin := range []bool{false, true} {
		path := "GET /api/v1/credentials"
		if admin {
			path = "GET /api/v1/admin/credentials"
		}
		mux.HandleFunc(path, a.require(admin, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			member := s.Member.ID
			if admin {
				member = ""
			}
			items, err := a.opts.Store.CredentialSummaries(r.Context(), member, a.opts.Now())
			if err != nil {
				writeJSON(w, 503, map[string]string{"error": "storage_unavailable"})
				return
			}
			writeJSON(w, 200, map[string]any{"items": items})
		}))
	}
}

func (a *access) download(w http.ResponseWriter, r *http.Request, session storage.Session) {
	// Downloads have no input besides the grant ID. In particular, members may
	// not supply another identity, role, policy, CSR, endpoint or expiry.
	if r.ContentLength != 0 {
		writeJSON(w, 400, map[string]string{"error": "invalid_download"})
		return
	}
	g, err := a.opts.Store.Grant(r.Context(), r.PathValue("id"))
	if errors.Is(err, storage.ErrNotFound) || (err == nil && g.MemberID != session.Member.ID) {
		writeJSON(w, 404, map[string]string{"error": "grant_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "storage_unavailable"})
		return
	}
	if !g.ActiveAt(a.opts.Now()) {
		writeJSON(w, 409, map[string]string{"error": "grant_inactive"})
		return
	}
	if !a.signingReady(r) || g.Execution.State != "applied" || g.ClusterID != a.opts.ClusterID || g.PermissionRef != a.opts.PermissionRef {
		writeJSON(w, 503, map[string]string{"error": "signing_unavailable"})
		return
	}
	if a.limited("credential:"+session.Member.ID, a.opts.Now()) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, 429, map[string]string{"error": "too_many_attempts"})
		return
	}
	select {
	case a.downloads <- struct{}{}:
		defer func() { <-a.downloads }()
	default:
		writeJSON(w, 429, map[string]string{"error": "too_many_attempts"})
		return
	}
	pending, err := credential.Policy(g.Policy()).New(g.Grant, session.Member.ID, a.opts.Now())
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": "insufficient_lifetime"})
		return
	}
	public := pending.PublicRequest()
	if err = a.opts.Store.QueueCredential(r.Context(), public, a.opts.Now()); err != nil {
		code, status := "signing_unavailable", 503
		if errors.Is(err, storage.ErrBusy) {
			code, status = "too_many_attempts", 429
		}
		writeJSON(w, status, map[string]string{"error": code})
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = a.opts.Store.EndCredential(ctx, public.ID, "abandoned", "download_ended", a.opts.Now())
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	timer := time.NewTicker(150 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if r.Context().Err() == nil {
				writeJSON(w, 504, map[string]string{"error": "signing_timeout"})
			}
			return
		case <-timer.C:
		}
		record, err := a.opts.Store.Credential(ctx, public.ID)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		if record.State == "pending" {
			continue
		}
		if record.State != "issued" {
			writeJSON(w, 409, map[string]string{"error": "signing_failed"})
			return
		}
		fresh, err := a.opts.Store.Grant(ctx, g.ID)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		if fresh.Execution.State != "applied" || !a.signingReady(r) {
			writeJSON(w, 409, map[string]string{"error": "grant_inactive"})
			return
		}
		download, err := pending.Kubeconfig(fresh.Grant, session.Member.ID, a.opts.ClusterEndpoint, record.Certificate, a.opts.ClusterCA, a.opts.Now())
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": "grant_inactive"})
			return
		}
		defer clear(download.Data)
		if err = a.opts.Store.PrepareDownload(ctx, a.token(r), public.ID, a.opts.Now()); err != nil {
			writeJSON(w, 409, map[string]string{"error": "authorization_changed"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="kubegrant.config"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-KubeGrant-Credential-Expires-At", download.ExpiresAt.Format(time.RFC3339))
		w.WriteHeader(200)
		_, _ = w.Write(download.Data)
		return
	}
}
