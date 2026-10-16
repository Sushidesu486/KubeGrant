package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/httpapi"
	"github.com/Sushidesu486/KubeGrant/internal/kube"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

// Explicit opt-in only. The runner supplies credentials from a disposable kind
// cluster; the test rejects public and production API endpoints.
func TestRealClusterSigningRevocationAndAdmission(t *testing.T) {
	endpoint := os.Getenv("KUBEGRANT_E2E_API")
	if endpoint == "" {
		t.Skip("requires disposable kind cluster; see scripts/test-cluster.sh")
	}
	u, err := url.Parse(endpoint)
	if err != nil || !net.ParseIP(u.Hostname()).IsLoopback() || os.Getenv("KUBEGRANT_E2E_CONFIRM") != "kind-kubegrant-e2e" {
		t.Fatal("refusing a non-loopback or unconfirmed test cluster")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	caFile, tokenFile := os.Getenv("KUBEGRANT_E2E_CA"), os.Getenv("KUBEGRANT_E2E_TOKEN_FILE")
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kube.New(endpoint, caFile, tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	e := setup(t) // Independent local DB and member; real API replaces the fixture.
	e.c.API = api
	e.c.CA = ca
	e.c.PermissionRef = "kubegrant-e2e-reader"
	if err = e.store.RevokeGrant(ctx, "admin", e.g.ID, e.c.now()); err != nil {
		t.Fatal(err)
	}
	g, err := e.store.CreateGrantWithPolicy(ctx, "admin", storage.NewGrant{MemberID: e.session.Member.ID, ClusterID: "cluster", PermissionRef: e.c.PermissionRef, Policy: "operations", Permanent: true}, e.c.now())
	if err != nil {
		t.Fatal(err)
	}
	e.g = g
	e.round(t)
	handler, err := httpapi.NewHandler(httpapi.Options{Store: e.store, Authenticator: testIdentity{}, PublicURL: "https://kubegrant.example", ClusterID: "cluster", PermissionRef: e.c.PermissionRef, SigningEnabled: true, ClusterEndpoint: endpoint, ClusterCA: ca, Now: e.c.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "https://kubegrant.example/api/v1/grants/"+g.ID+"/kubeconfig", nil).WithContext(ctx)
	request.Header.Set("Origin", "https://kubegrant.example")
	request.AddCookie(&http.Cookie{Name: "kubegrant-session", Value: e.token})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); handler.ServeHTTP(w, request); done <- w }()
	var response *httptest.ResponseRecorder
wait:
	for {
		select {
		case response = <-done:
			break wait
		case <-ctx.Done():
			t.Fatal("real download timed out")
		default:
			e.round(t)
			time.Sleep(100 * time.Millisecond)
		}
	}
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("real download failed", response.Code)
	}
	summaries, err := e.store.CredentialSummaries(ctx, g.MemberID, e.c.now())
	if err != nil || len(summaries) != 1 || summaries[0].ExpiresAt == nil || summaries[0].ExpiresAt.Sub(e.c.now()) < 364*24*time.Hour {
		t.Fatal("operations credential unexpectedly short", err)
	}
	var config struct {
		Users []struct {
			User struct {
				Certificate []byte `json:"client-certificate-data"`
				Key         []byte `json:"client-key-data"`
			} `json:"user"`
		} `json:"users"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(config.Users[0].User.Certificate, config.Users[0].User.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	getNodes := func() int {
		t.Helper()
		r, err := client.Get(endpoint + "/api/v1/nodes")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
		return r.StatusCode
	}
	if status := getNodes(); status != 200 {
		t.Fatal("issued kubeconfig could not list assigned resources", status)
	}
	// Feed the attachment through a pipe: kubectl must load the exact file
	// format, with no login plugin and without a private key written to disk.
	kubectl := exec.CommandContext(ctx, "kubectl", "--kubeconfig=/dev/stdin", "--cache-dir="+t.TempDir(), "--request-timeout=5s", "get", "nodes", "-o", "name")
	kubectl.Stdin = bytes.NewReader(response.Body.Bytes())
	output, cliErr := kubectl.Output()
	if cliErr != nil || !strings.Contains(string(output), "node/kubegrant-e2e-control-plane") {
		t.Fatal("kubectl could not use the downloaded kubeconfig", cliErr)
	}
	t.Log("real kubectl accepted the downloaded kubeconfig without a login plugin")
	// The same client/key is reused after RBAC revocation. Its one-year client
	// certificate remains valid, so a 403 proves authorization was withdrawn.
	started := time.Now()
	if err = e.store.RevokeGrant(ctx, "admin", g.ID, e.c.now()); err != nil {
		t.Fatal(err)
	}
	e.round(t)
	for getNodes() != 403 {
		if time.Since(started) > 30*time.Second {
			t.Fatal("revocation exceeded 30 seconds")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Log("real one-year CSR signing, kubeconfig access and RBAC revocation passed")

	foreign, err := api.GetBinding(ctx, "kubegrant-e2e-foreign")
	if err != nil {
		t.Fatal(err)
	}
	if err = api.DeleteBinding(ctx, foreign.Metadata.Name, foreign.Metadata.UID); !kube.IsStatus(err, 403) && !kube.IsStatus(err, 422) {
		t.Fatal("admission allowed deletion of a shared binding", err)
	}
	if preserved, getErr := api.GetBinding(ctx, foreign.Metadata.Name); getErr != nil || preserved.Metadata.UID != foreign.Metadata.UID {
		t.Fatal("shared binding was modified", getErr)
	}
	bad := kube.Binding{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Metadata: kube.Metadata{Name: "kg-" + strings.Repeat("a", 48), Labels: e.c.labels("test")}, RoleRef: kube.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: e.c.PermissionRef}, Subjects: []kube.Subject{{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "system:admin"}}}
	if _, err = api.CreateBinding(ctx, bad); !kube.IsStatus(err, 403) && !kube.IsStatus(err, 422) {
		t.Fatal("admission allowed arbitrary subject", err)
	}
	t.Log("real admission rejected shared binding deletion and arbitrary identity")

	// Finite expiry is exercised by advancing controller time. It removes the
	// real binding without waiting for a naturally expiring certificate.
	finite, err := e.store.CreateGrant(ctx, "admin", g.MemberID, "cluster", e.c.PermissionRef, e.c.now(), e.c.now().Add(20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	e.round(t)
	e.clock.Add(int64(21 * time.Minute))
	e.round(t)
	observed, err := e.store.Grant(ctx, finite.ID)
	if err != nil || observed.Execution.State != "expired" {
		t.Fatal("real expiry was not confirmed", err)
	}
	if _, err = api.GetBinding(ctx, BindingName(finite)); !kube.IsStatus(err, 404) {
		t.Fatal("expired grant binding survived")
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err = e.store.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	t.Log("real binding expiry and consistent v2 backup passed")
}
