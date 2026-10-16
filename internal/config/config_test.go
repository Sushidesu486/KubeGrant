package config

import "testing"

func TestInvalidListenAddress(t *testing.T) {
	for _, addr := range []string{"", "localhost", "localhost:http", "localhost:0", "localhost:65536"} {
		t.Run(addr, func(t *testing.T) {
			t.Setenv("KUBEGRANT_HTTP_ADDR", addr)
			if _, err := Load(); err == nil {
				t.Fatalf("accepted invalid address %q", addr)
			}
		})
	}
}

func TestPublicOriginAndLifetimeSafety(t *testing.T) {
	t.Setenv("KUBEGRANT_HTTP_ADDR", "127.0.0.1:8080")
	t.Setenv("KUBEGRANT_LDAP_URLS", "")
	for _, tc := range []struct {
		origin string
		valid  bool
	}{
		{"https://kubegrant.example", true},
		{"http://127.0.0.1:5173", true},
		{"http://[::1]:8080", true},
		{"http://kubegrant.example", false},
		{"ftp://localhost", false},
		{"https://user:password@kubegrant.example", false},
		{"https://kubegrant.example/path", false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			t.Setenv("KUBEGRANT_PUBLIC_URL", tc.origin)
			cfg, err := Load()
			if (err == nil) != tc.valid {
				t.Fatal("unexpected origin validation", err)
			}
			if err == nil && cfg.SecureCookies != (tc.origin[:5] == "https") {
				t.Fatal("cookie transport mismatch")
			}
		})
	}
	t.Setenv("KUBEGRANT_PUBLIC_URL", "https://kubegrant.example")
	for _, value := range []string{"0s", "30s", "25h"} {
		t.Setenv("KUBEGRANT_SESSION_TTL", value)
		if _, err := Load(); err == nil {
			t.Fatal("unsafe session TTL accepted", value)
		}
	}
	t.Setenv("KUBEGRANT_SESSION_TTL", "30m")
	for _, value := range []string{"0s", "30s", "9000h"} {
		t.Setenv("KUBEGRANT_GRANT_MAX_TTL", value)
		if _, err := Load(); err == nil {
			t.Fatal("invalid grant maximum accepted", value)
		}
	}
	t.Setenv("KUBEGRANT_GRANT_MAX_TTL", "720h")
	t.Setenv("KUBEGRANT_LDAP_URLS", "ldaps://ipa.example")
	t.Setenv("KUBEGRANT_PUBLIC_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("enabled authentication requires an explicit public origin")
	}
}
