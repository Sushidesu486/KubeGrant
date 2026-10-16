package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/credential"
	"github.com/Sushidesu486/KubeGrant/internal/grant"
	"github.com/Sushidesu486/KubeGrant/internal/httpapi"
	"github.com/Sushidesu486/KubeGrant/internal/identity"
	"github.com/Sushidesu486/KubeGrant/internal/kube"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

type clusterFixture struct {
	mu                         sync.Mutex
	bindings                   map[string]kube.Binding
	csrs                       map[string]kube.CSR
	ca                         *x509.Certificate
	key                        *ecdsa.PrivateKey
	caPEM                      []byte
	now                        func() time.Time
	sequence, approvals        int
	createHook                 func()
	delayDeletion, unavailable bool
}

func (f *clusterFixture) CheckRole(context.Context, string) error { return nil }

func newCluster(t *testing.T, now func() time.Time) *clusterFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now().Add(-time.Hour), NotAfter: now().Add(400 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &clusterFixture{bindings: map[string]kube.Binding{}, csrs: map[string]kube.CSR{}, ca: ca, key: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), now: now}
}
func (f *clusterFixture) ListBindings(context.Context, string) ([]kube.Binding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unavailable {
		return nil, &kube.APIError{Status: 503}
	}
	out := []kube.Binding{}
	for _, b := range f.bindings {
		out = append(out, b)
	}
	return out, nil
}
func (f *clusterFixture) GetBinding(_ context.Context, name string) (kube.Binding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.bindings[name]
	if !ok {
		return b, &kube.APIError{Status: 404}
	}
	return b, nil
}
func (f *clusterFixture) CreateBinding(_ context.Context, b kube.Binding) (kube.Binding, error) {
	f.mu.Lock()
	if _, ok := f.bindings[b.Metadata.Name]; ok {
		f.mu.Unlock()
		return b, &kube.APIError{Status: 409}
	}
	f.sequence++
	b.Metadata.UID = fmt.Sprintf("binding-%d", f.sequence)
	f.bindings[b.Metadata.Name] = b
	hook := f.createHook
	f.createHook = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return b, nil
}
func (f *clusterFixture) DeleteBinding(_ context.Context, name, uid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.bindings[name]
	if !ok {
		return &kube.APIError{Status: 404}
	}
	if b.Metadata.UID != uid {
		return &kube.APIError{Status: 409}
	}
	if !f.delayDeletion {
		delete(f.bindings, name)
	}
	return nil
}
func (f *clusterFixture) GetCSR(_ context.Context, name string) (kube.CSR, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.csrs[name]
	if !ok {
		return c, &kube.APIError{Status: 404}
	}
	return c, nil
}
func (f *clusterFixture) CreateCSR(_ context.Context, c kube.CSR) (kube.CSR, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.csrs[c.Metadata.Name]; ok {
		return c, &kube.APIError{Status: 409}
	}
	f.sequence++
	c.Metadata.UID = fmt.Sprintf("csr-%d", f.sequence)
	f.csrs[c.Metadata.Name] = c
	return c, nil
}
func (f *clusterFixture) ApproveCSR(_ context.Context, c kube.CSR, now time.Time) (kube.CSR, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approvals++
	block, _ := pem.Decode(c.Spec.Request)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return c, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(f.sequence + 100)), Subject: csr.Subject, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Duration(c.Spec.ExpirationSeconds) * time.Second).Truncate(time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, csr.PublicKey, f.key)
	if err != nil {
		return c, err
	}
	c.Status.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	c.Status.Conditions = []kube.Condition{{Type: "Approved", Status: "True"}}
	f.csrs[c.Metadata.Name] = c
	return c, nil
}
func (f *clusterFixture) DeleteCSR(_ context.Context, name, uid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.csrs[name]
	if !ok {
		return &kube.APIError{Status: 404}
	}
	if c.Metadata.UID != uid {
		return &kube.APIError{Status: 409}
	}
	delete(f.csrs, name)
	return nil
}
func (f *clusterFixture) ListCSRs(context.Context, string) ([]kube.CSR, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []kube.CSR{}
	for _, c := range f.csrs {
		out = append(out, c)
	}
	return out, nil
}

type environment struct {
	c       *Controller
	f       *clusterFixture
	store   *storage.Store
	g       grant.Grant
	session storage.Session
	token   string
	clock   atomic.Int64
}

func setup(t *testing.T) *environment {
	t.Helper()
	e := &environment{}
	e.clock.Store(time.Now().UTC().UnixNano())
	now := func() time.Time { return time.Unix(0, e.clock.Load()).UTC() }
	s, err := storage.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	e.store = s
	t.Cleanup(func() { s.Close() })
	e.session, e.token, err = s.StartSession(context.Background(), identity.Profile{Provider: "test", Issuer: "test", Subject: "member", Username: "member"}, now(), now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	e.g, err = s.CreateGrant(context.Background(), "admin", e.session.Member.ID, "cluster", "existing", now(), now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	e.f = newCluster(t, now)
	e.c = &Controller{Store: s, API: e.f, ClusterID: "cluster", PermissionRef: "existing", CA: e.f.caPEM, Now: now}
	return e
}
func (e *environment) round(t *testing.T) {
	t.Helper()
	if err := e.c.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func (e *environment) queue(t *testing.T) *credential.Pending {
	t.Helper()
	p, err := credential.Standard.New(e.g, e.session.Member.ID, e.c.now())
	if err != nil {
		t.Fatal(err)
	}
	if err = e.store.QueueCredential(context.Background(), p.PublicRequest(), e.c.now()); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestControllerIssuesAndRevokesWithRestart(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.round(t)
	p := e.queue(t)
	e.round(t) // Create and approve, without blocking the sweep.
	// Recreating the controller object must continue the persisted CSR, not mint
	// a new identity or approve the request twice.
	e.c = &Controller{Store: e.store, API: e.f, ClusterID: "cluster", PermissionRef: "existing", CA: e.f.caPEM, Now: e.c.Now}
	e.round(t)
	r, err := e.store.Credential(ctx, p.PublicRequest().ID)
	if err != nil || r.State != "issued" || e.f.approvals != 1 {
		t.Fatal("restart lost signing state", err, r.State)
	}
	if _, err = p.Kubeconfig(e.g, e.session.Member.ID, "https://api.example", r.Certificate, e.f.caPEM, e.c.now()); err != nil {
		t.Fatal(err)
	}
	if err = e.store.RevokeGrant(ctx, "admin", e.g.ID, e.c.now()); err != nil {
		t.Fatal(err)
	}
	e.round(t)
	if _, err = e.f.GetBinding(ctx, BindingName(e.g)); !kube.IsStatus(err, 404) {
		t.Fatal("revocation left permission binding")
	}
	g, err := e.store.Grant(ctx, e.g.ID)
	if err != nil || g.Execution.State != "revoked" {
		t.Fatal("revocation not confirmed", err)
	}
}

func TestRevokeDuringCreateCannotPublishApplied(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.f.createHook = func() {
		if err := e.store.RevokeGrant(ctx, "admin", e.g.ID, e.c.now()); err != nil {
			t.Error(err)
		}
	}
	e.round(t)
	g, err := e.store.Grant(ctx, e.g.ID)
	if err != nil || g.Execution.State != "revoked" {
		t.Fatal("stale create revived access", err, g.Execution.State)
	}
	if len(e.f.bindings) != 0 {
		t.Fatal("binding survived concurrent revoke")
	}
}

func TestDeletionMustBeObservedAndFailuresRetried(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.round(t)
	e.f.delayDeletion = true
	if err := e.store.RevokeGrant(ctx, "admin", e.g.ID, e.c.now()); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Round(ctx); err == nil {
		t.Fatal("unconfirmed deletion was treated as complete")
	}
	g, _ := e.store.Grant(ctx, e.g.ID)
	if g.Execution.State != "error" {
		t.Fatal("failure not visible")
	}
	e.f.delayDeletion = false
	e.round(t)
	g, _ = e.store.Grant(ctx, e.g.ID)
	if g.Execution.State != "revoked" {
		t.Fatal("failed deletion did not recover")
	}
}

func TestUnmanagedCollisionAndCSRReplacementFailClosed(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.f.bindings[BindingName(e.g)] = kube.Binding{Metadata: kube.Metadata{Name: BindingName(e.g), UID: "foreign"}}
	if err := e.c.Round(ctx); err == nil {
		t.Fatal("unmanaged binding was taken over")
	}
	if e.f.bindings[BindingName(e.g)].Metadata.UID != "foreign" {
		t.Fatal("unmanaged binding modified")
	}
	delete(e.f.bindings, BindingName(e.g))
	e.round(t)
	p := e.queue(t)
	e.round(t)
	name := CSRName(p.PublicRequest().ID)
	csr, _ := e.f.GetCSR(ctx, name)
	csr.Metadata.UID = "replaced"
	e.f.csrs[name] = csr
	e.round(t)
	r, _ := e.store.Credential(ctx, p.PublicRequest().ID)
	if r.State != "failed" || r.ErrorCode != "csr_conflict" || e.f.approvals != 1 {
		t.Fatal("replacement CSR accepted")
	}
}

func TestExpiryAndControllerOutage(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.round(t)
	if !e.store.ControllerReady(ctx, "cluster", "existing", e.c.now()) {
		t.Fatal("healthy controller missing")
	}
	e.f.unavailable = true
	e.clock.Add(int64(31 * time.Second))
	if err := e.c.Round(ctx); err == nil {
		t.Fatal("API outage ignored")
	}
	if e.store.ControllerReady(ctx, "cluster", "existing", e.c.now()) {
		t.Fatal("stale controller advertised as healthy")
	}
	e.f.unavailable = false
	e.clock.Add(int64(time.Hour))
	e.round(t)
	g, _ := e.store.Grant(ctx, e.g.ID)
	if g.Execution.State != "expired" || len(e.f.bindings) != 0 {
		t.Fatal("expiry failed to revoke")
	}
}

type testIdentity struct{}

func (testIdentity) Authenticate(context.Context, string, string) (identity.Profile, error) {
	return identity.Profile{}, identity.ErrCredentials
}

func TestHTTPDownloadOwnershipCSRAndFinalSessionCheck(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.round(t)
	h, err := httpapi.NewHandler(httpapi.Options{Store: e.store, Authenticator: testIdentity{}, PublicURL: "https://kubegrant.example", ClusterID: "cluster", PermissionRef: "existing", SigningEnabled: true, ClusterEndpoint: "https://api.example:6443", ClusterCA: e.f.caPEM, Now: e.c.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := func(body, origin, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://kubegrant.example/api/v1/grants/"+e.g.ID+"/kubeconfig", bytes.NewBufferString(body))
		r.Header.Set("Origin", origin)
		r.AddCookie(&http.Cookie{Name: "kubegrant-session", Value: token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("", "https://attacker.example", e.token); w.Code != 403 {
		t.Fatal("download CSRF accepted")
	}
	if w := request(`{"credential_policy":"operations"}`, "https://kubegrant.example", e.token); w.Code != 400 {
		t.Fatal("download accepted policy override")
	}
	_, otherToken, err := e.store.StartSession(ctx, identity.Profile{Provider: "test", Issuer: "test", Subject: "other-admin", Username: "other-admin", Administrator: true}, e.c.now(), e.c.now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if w := request("", "https://kubegrant.example", otherToken); w.Code != 404 {
		t.Fatal("admin downloaded another member's private key")
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request("", "https://kubegrant.example", e.token) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	var response *httptest.ResponseRecorder
wait:
	for {
		select {
		case response = <-done:
			break wait
		case <-deadline.C:
			t.Fatal("download did not complete")
		default:
			e.round(t)
			time.Sleep(30 * time.Millisecond)
		}
	}
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Disposition") == "" {
		t.Fatal("download response invalid", response.Code, response.Body.String())
	}
	var config struct {
		Users []struct {
			User struct {
				Cert []byte `json:"client-certificate-data"`
				Key  []byte `json:"client-key-data"`
			} `json:"user"`
		} `json:"users"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if _, err = tls.X509KeyPair(config.Users[0].User.Cert, config.Users[0].User.Key); err != nil {
		t.Fatal("downloaded key and certificate mismatch", err)
	}
	items, err := e.store.CredentialSummaries(ctx, e.session.Member.ID, e.c.now())
	if err != nil || len(items) != 1 || items[0].State != "issued" {
		t.Fatal("issued credential metadata missing", err)
	}
	data, _ := json.Marshal(items)
	if bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("client-key-data")) {
		t.Fatal("private material leaked into credential listing")
	}
	if err = e.store.EndSession(ctx, e.token, e.session.Member.ID, e.c.now()); err != nil {
		t.Fatal(err)
	}
	if err = e.store.PrepareDownload(ctx, e.token, items[0].ID, e.c.now()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("ended session could prepare download", err)
	}
}
