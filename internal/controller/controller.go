// Package controller reconciles authorization intent with cluster resources.
// It handles public CSRs only; no member private keys enter this process.
package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/credential"
	"github.com/Sushidesu486/KubeGrant/internal/grant"
	"github.com/Sushidesu486/KubeGrant/internal/kube"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

type API interface {
	CheckRole(context.Context, string) error
	ListBindings(context.Context, string) ([]kube.Binding, error)
	CreateBinding(context.Context, kube.Binding) (kube.Binding, error)
	DeleteBinding(context.Context, string, string) error
	GetBinding(context.Context, string) (kube.Binding, error)
	GetCSR(context.Context, string) (kube.CSR, error)
	CreateCSR(context.Context, kube.CSR) (kube.CSR, error)
	ApproveCSR(context.Context, kube.CSR, time.Time) (kube.CSR, error)
	DeleteCSR(context.Context, string, string) error
	ListCSRs(context.Context, string) ([]kube.CSR, error)
}

type Controller struct {
	Store                    *storage.Store
	API                      API
	ClusterID, PermissionRef string
	CA                       []byte
	Now                      func() time.Time
}

func Instance(cluster string) string {
	h := sha256.Sum256([]byte(cluster))
	return hex.EncodeToString(h[:12])
}
func BindingName(g grant.Grant) string {
	return "kg-" + strings.TrimPrefix(credential.Subject(g), "kubegrant:")
}
func CSRName(id string) string {
	h := sha256.Sum256([]byte(id))
	return "kg-" + hex.EncodeToString(h[:24])
}
func (c *Controller) labels(grantID string) map[string]string {
	return map[string]string{"app.kubernetes.io/managed-by": "kubegrant", "kubegrant.io/instance": Instance(c.ClusterID), "kubegrant.io/grant": grantID}
}
func (c *Controller) selector() string { return "kubegrant.io/instance=" + Instance(c.ClusterID) }
func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *Controller) Run(ctx context.Context, logger *slog.Logger) error {
	if c.Store == nil || c.API == nil || c.ClusterID == "" || c.PermissionRef == "" || len(c.CA) == 0 {
		return errors.New("controller configuration incomplete")
	}
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		if err := c.Round(ctx); err != nil && ctx.Err() == nil {
			logger.Error("reconciliation incomplete", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
	}
}

func (c *Controller) Round(ctx context.Context) error {
	bindings, err := c.API.ListBindings(ctx, c.selector())
	if err != nil {
		return err
	}
	byName := make(map[string]kube.Binding, len(bindings))
	for _, b := range bindings {
		byName[b.Metadata.Name] = b
	}
	var failures []error
	roleErr := c.API.CheckRole(ctx, c.PermissionRef)
	if roleErr != nil {
		failures = append(failures, roleErr)
	}
	// Always process revocations and expiries before granting or approving.
	for _, active := range []bool{false, true} {
		after := ""
		for {
			page, err := c.Store.ControllerGrants(ctx, c.ClusterID, after, active, c.now())
			if err != nil {
				return err
			}
			if len(page) == 0 {
				break
			}
			for _, g := range page {
				if active && roleErr != nil {
					failures = append(failures, roleErr)
					if err := c.Store.SetExecution(ctx, g.ID, "error", g.Execution.BindingUID, "role_unavailable", c.now()); err != nil {
						failures = append(failures, err)
					}
					continue
				}
				if err := c.reconcileGrant(ctx, g, byName); err != nil {
					failures = append(failures, err)
					if writeErr := c.Store.SetExecution(ctx, g.ID, "error", g.Execution.BindingUID, "reconcile_failed", c.now()); writeErr != nil {
						failures = append(failures, writeErr)
					}
				}
			}
			after = page[len(page)-1].ID
		}
	}
	// A cluster-owned binding without a database grant must not grant access.
	for _, b := range byName {
		_, err := c.Store.Grant(ctx, b.Metadata.Labels["kubegrant.io/grant"])
		if err == nil {
			continue
		}
		if !errors.Is(err, storage.ErrNotFound) {
			failures = append(failures, err)
			continue
		}
		orphan := grant.Grant{ID: b.Metadata.Labels["kubegrant.io/grant"], ClusterID: c.ClusterID, PermissionRef: b.RoleRef.Name}
		if err = c.validateBinding(b, orphan); err == nil {
			err = c.removeBinding(ctx, b)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) == 0 {
		if err = c.Store.Heartbeat(ctx, c.ClusterID, c.PermissionRef, c.now()); err != nil {
			return err
		}
	}
	after := ""
	for {
		page, err := c.Store.PendingCredentials(ctx, after)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		for _, r := range page {
			if r.Request.ClusterID != c.ClusterID {
				continue
			}
			if err := c.reconcileCredential(ctx, r); err != nil {
				failures = append(failures, err)
			}
		}
		after = page[len(page)-1].Request.ID
	}
	if err = c.cleanupCSRs(ctx); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (c *Controller) validateBinding(b kube.Binding, g grant.Grant) error {
	if b.Metadata.UID == "" || b.Metadata.Name != BindingName(g) || b.RoleRef != (kube.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: g.PermissionRef}) ||
		len(b.Subjects) != 1 || b.Subjects[0] != (kube.Subject{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: credential.Subject(g)}) {
		return errors.New("managed binding identity conflict")
	}
	for k, v := range c.labels(g.ID) {
		if b.Metadata.Labels[k] != v {
			return errors.New("binding ownership conflict")
		}
	}
	return nil
}

func (c *Controller) reconcileGrant(ctx context.Context, g storage.GrantRecord, bindings map[string]kube.Binding) error {
	name := BindingName(g.Grant)
	b, exists := bindings[name]
	if exists {
		if err := c.validateBinding(b, g.Grant); err != nil {
			return err
		}
		if g.Execution.BindingUID != "" && g.Execution.BindingUID != b.Metadata.UID {
			return errors.New("managed binding UID changed")
		}
	}
	if !g.ActiveAt(c.now()) || g.PermissionRef != c.PermissionRef {
		if exists {
			if err := c.removeBinding(ctx, b); err != nil {
				return err
			}
			delete(bindings, name)
		}
		state := "expired"
		if g.RevokedAt != nil {
			state = "revoked"
		}
		if g.ActiveAt(c.now()) {
			return errors.New("grant role no longer configured")
		}
		return c.Store.SetExecution(ctx, g.ID, state, "", "", c.now())
	}
	if !exists {
		var err error
		b, err = c.API.CreateBinding(ctx, kube.Binding{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Metadata: kube.Metadata{Name: name, Labels: c.labels(g.ID)}, RoleRef: kube.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: g.PermissionRef}, Subjects: []kube.Subject{{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: credential.Subject(g.Grant)}}})
		if err != nil {
			return err
		}
		if err = c.validateBinding(b, g.Grant); err != nil {
			return err
		}
		bindings[name] = b
	}
	if err := c.Store.SetExecution(ctx, g.ID, "applied", b.Metadata.UID, "", c.now()); err != nil {
		// Revocation may have committed while the API create was in flight.
		fresh, getErr := c.Store.Grant(ctx, g.ID)
		if getErr == nil && !fresh.ActiveAt(c.now()) {
			return c.reconcileGrant(ctx, fresh, bindings)
		}
		return err
	}
	return nil
}

func (c *Controller) removeBinding(ctx context.Context, b kube.Binding) error {
	err := c.API.DeleteBinding(ctx, b.Metadata.Name, b.Metadata.UID)
	if err != nil && !kube.IsStatus(err, http.StatusNotFound) {
		return err
	}
	_, err = c.API.GetBinding(ctx, b.Metadata.Name)
	if !kube.IsStatus(err, http.StatusNotFound) {
		if err != nil {
			return err
		}
		return errors.New("binding deletion not confirmed")
	}
	return nil
}

func (c *Controller) reconcileCredential(ctx context.Context, r storage.CredentialRecord) error {
	now := c.now()
	if !now.Before(r.WaitUntil) {
		return c.Store.EndCredential(ctx, r.Request.ID, "abandoned", "request_timeout", now)
	}
	g, err := c.Store.Grant(ctx, r.Request.GrantID)
	if err != nil {
		return err
	}
	policy := credential.Policy(g.Policy())
	if _, err = policy.ValidateRequest(r.Request, g.Grant, now); err != nil || g.PermissionRef != c.PermissionRef {
		return c.Store.EndCredential(ctx, r.Request.ID, "failed", "grant_inactive", now)
	}
	if g.Execution.State != "applied" || g.Execution.CheckedAt == nil || now.Sub(*g.Execution.CheckedAt) >= 30*time.Second {
		return nil
	}
	name := CSRName(r.Request.ID)
	csr, err := c.API.GetCSR(ctx, name)
	if kube.IsStatus(err, http.StatusNotFound) {
		if r.CSRUID != "" {
			return c.Store.EndCredential(ctx, r.Request.ID, "failed", "csr_missing", now)
		}
		seconds, ttlErr := policy.ExpirationSeconds(r.Request, now.Add(30*time.Second))
		if ttlErr != nil {
			return c.Store.EndCredential(ctx, r.Request.ID, "failed", "insufficient_lifetime", now)
		}
		labels := c.labels(g.ID)
		labels["kubegrant.io/request"] = r.Request.ID
		csr, err = c.API.CreateCSR(ctx, kube.CSR{APIVersion: "certificates.k8s.io/v1", Kind: "CertificateSigningRequest", Metadata: kube.Metadata{Name: name, Labels: labels}, Spec: kube.CSRSpec{Request: r.Request.CSR, SignerName: credential.SignerName, ExpirationSeconds: seconds, Usages: []string{"digital signature", "client auth"}}})
	}
	if err != nil {
		return err
	}
	if csr.Metadata.Name != name || csr.Metadata.UID == "" || (r.CSRUID != "" && csr.Metadata.UID != r.CSRUID) || !bytes.Equal(csr.Spec.Request, r.Request.CSR) || csr.Spec.SignerName != credential.SignerName || len(csr.Spec.Usages) != 2 || csr.Spec.Usages[0] != "digital signature" || csr.Spec.Usages[1] != "client auth" || csr.Spec.ExpirationSeconds < 600 || time.Duration(csr.Spec.ExpirationSeconds)*time.Second > r.Request.NotAfter.Sub(r.Request.CreatedAt) {
		return c.Store.EndCredential(ctx, r.Request.ID, "failed", "csr_conflict", c.now())
	}
	for k, v := range c.labels(g.ID) {
		if csr.Metadata.Labels[k] != v {
			return c.Store.EndCredential(ctx, r.Request.ID, "failed", "csr_conflict", c.now())
		}
	}
	if csr.Metadata.Labels["kubegrant.io/request"] != r.Request.ID {
		return c.Store.EndCredential(ctx, r.Request.ID, "failed", "csr_conflict", c.now())
	}
	if err = c.Store.SetCSRUID(ctx, r.Request.ID, csr.Metadata.UID); err != nil {
		return err
	}
	approved := false
	for _, condition := range csr.Status.Conditions {
		if condition.Type == "Denied" || condition.Type == "Failed" {
			return c.Store.EndCredential(ctx, r.Request.ID, "failed", "csr_denied", c.now())
		}
		if condition.Type == "Approved" && condition.Status == "True" {
			approved = true
		}
	}
	if !approved {
		// Check the persisted task and grant immediately before approval.
		fresh, err := c.Store.Credential(ctx, r.Request.ID)
		if err != nil {
			return err
		}
		g, err = c.Store.Grant(ctx, r.Request.GrantID)
		if err != nil {
			return err
		}
		if fresh.State != "pending" || !c.now().Before(fresh.WaitUntil) {
			return nil
		}
		if _, err = credential.Policy(g.Policy()).ValidateRequest(fresh.Request, g.Grant, c.now()); err != nil {
			return c.Store.EndCredential(ctx, r.Request.ID, "failed", "grant_inactive", c.now())
		}
		_, err = c.API.ApproveCSR(ctx, csr, c.now())
		return err
	}
	if len(csr.Status.Certificate) == 0 {
		return nil
	}
	expires, err := policy.Verify(r.Request, g.Grant, csr.Status.Certificate, c.CA, c.now())
	if err != nil {
		return c.Store.EndCredential(ctx, r.Request.ID, "failed", "certificate_invalid", c.now())
	}
	return c.Store.CompleteCredential(ctx, r.Request.ID, csr.Status.Certificate, expires, c.now())
}

func (c *Controller) cleanupCSRs(ctx context.Context) error {
	items, err := c.API.ListCSRs(ctx, c.selector())
	if err != nil {
		return err
	}
	var failures []error
	for _, csr := range items {
		id := csr.Metadata.Labels["kubegrant.io/request"]
		if id == "" || csr.Metadata.Name != CSRName(id) || csr.Metadata.Labels["app.kubernetes.io/managed-by"] != "kubegrant" || csr.Spec.SignerName != credential.SignerName {
			failures = append(failures, errors.New("CSR ownership conflict"))
			continue
		}
		r, err := c.Store.Credential(ctx, id)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			failures = append(failures, err)
			continue
		}
		if err == nil && r.State == "pending" {
			continue
		}
		if err = c.API.DeleteCSR(ctx, csr.Metadata.Name, csr.Metadata.UID); err != nil && !kube.IsStatus(err, http.StatusNotFound) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
