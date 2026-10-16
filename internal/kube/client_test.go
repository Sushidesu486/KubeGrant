package kube

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func newTestClient(t *testing.T, handler http.Handler) (*Client, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	dir := t.TempDir()
	ca, token := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("first-test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := New(server.URL, ca, token)
	if err != nil {
		t.Fatal(err)
	}
	return c, token
}

func TestProjectedTokenRotationAndUIDPrecondition(t *testing.T) {
	var requests atomic.Int32
	c, token := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		expected := "Bearer first-test-token"
		if n > 1 {
			expected = "Bearer second-test-token"
		}
		if r.Header.Get("Authorization") != expected {
			t.Error("projected token was not refreshed")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"metadata":{"name":"owned","uid":"uid-one"}}`))
	}))
	if _, err := c.GetBinding(context.Background(), "owned"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("second-test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetBinding(context.Background(), "owned"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteBinding(context.Background(), "owned", ""); err == nil {
		t.Fatal("unsafe deletion without UID accepted")
	}
	if requests.Load() != 2 {
		t.Fatal("unsafe request reached server")
	}
}

func TestRedirectDoesNotLeakTokenAndErrorsOmitBodies(t *testing.T) {
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer other.Close()
	var bad atomic.Bool
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bad.Load() {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("private response body"))
			return
		}
		http.Redirect(w, r, other.URL, 302)
	}))
	_, err := c.GetBinding(context.Background(), "owned")
	if !IsStatus(err, 302) || redirected.Load() != 0 {
		t.Fatal("API redirect was followed", err)
	}
	bad.Store(true)
	_, err = c.GetBinding(context.Background(), "owned")
	if !IsStatus(err, 403) || err.Error() != "Kubernetes API returned HTTP 403" {
		t.Fatal("error exposed response content", err)
	}
}
