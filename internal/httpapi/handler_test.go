package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFoundationDoesNotExposeUnimplementedAccess(t *testing.T) {
	h, err := NewHandler(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		code int
	}{
		{"/livez", http.StatusOK},
		{"/readyz", http.StatusServiceUnavailable},
		{"/api/v1/status", http.StatusOK},
		{"/api/v1/grants", http.StatusServiceUnavailable},
		{"/api/v1/kubeconfig", http.StatusNotFound},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != tc.code {
				t.Fatalf("status %d, want %d", w.Code, tc.code)
			}
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
				t.Fatal("API response must be JSON")
			}
			if tc.path == "/api/v1/status" {
				var body struct {
					Features map[string]bool `json:"features"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if len(body.Features) != 3 {
					t.Fatal("missing feature availability information")
				}
				for name, enabled := range body.Features {
					if enabled {
						t.Fatalf("unfinished feature %q must not be enabled", name)
					}
				}
			}
		})
	}
}

func TestStaticFrontendDoesNotMaskMissingAPI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("frontend"), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Options{StaticDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/missing", "/api/v1/unknown"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "frontend") {
			t.Fatal("unknown API must not serve frontend HTML")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || w.Body.String() != "frontend" {
		t.Fatal("static frontend was not served")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("static frontend must reject write methods")
	}
	if _, err := NewHandler(Options{StaticDir: filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("invalid static directory must fail startup")
	}
}
