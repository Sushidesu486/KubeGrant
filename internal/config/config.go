package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/identity"
)

type Config struct {
	HTTPAddr                                             string
	StaticDir                                            string
	DatabasePath                                         string
	PublicURL                                            string
	SecureCookies                                        bool
	SessionTTL, GrantMaxTTL                              time.Duration
	ClusterID, PermissionRef                             string
	LDAP                                                 identity.FreeIPAConfig
	SigningEnabled                                       bool
	ClusterEndpoint, ClusterCAFile                       string
	KubernetesAPI, KubernetesCAFile, KubernetesTokenFile string
}

func Load() (Config, error) {
	cfg := Config{HTTPAddr: "127.0.0.1:8080", StaticDir: os.Getenv("KUBEGRANT_STATIC_DIR")}
	if addr, ok := os.LookupEnv("KUBEGRANT_HTTP_ADDR"); ok {
		cfg.HTTPAddr = addr
	}
	_, port, err := net.SplitHostPort(cfg.HTTPAddr)
	if err != nil {
		return Config{}, fmt.Errorf("KUBEGRANT_HTTP_ADDR must be host:port: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return Config{}, fmt.Errorf("KUBEGRANT_HTTP_ADDR port must be between 1 and 65535")
	}
	cfg.DatabasePath = os.Getenv("KUBEGRANT_DATABASE_PATH")
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = "data/kubegrant.db"
	}
	cfg.PublicURL = strings.TrimSuffix(os.Getenv("KUBEGRANT_PUBLIC_URL"), "/")
	if cfg.PublicURL == "" {
		cfg.PublicURL = "http://127.0.0.1:8080"
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, fmt.Errorf("KUBEGRANT_PUBLIC_URL must be an origin without path")
	}
	cfg.SecureCookies = u.Scheme == "https"
	loopback := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()
	if !cfg.SecureCookies && !(u.Scheme == "http" && loopback) {
		return Config{}, fmt.Errorf("KUBEGRANT_PUBLIC_URL requires HTTPS except for loopback development")
	}
	cfg.SessionTTL = 30 * time.Minute
	if raw := os.Getenv("KUBEGRANT_SESSION_TTL"); raw != "" {
		cfg.SessionTTL, err = time.ParseDuration(raw)
		if err != nil || cfg.SessionTTL < time.Minute || cfg.SessionTTL > 24*time.Hour {
			return Config{}, fmt.Errorf("session TTL must be between 1m and 24h")
		}
	}
	cfg.GrantMaxTTL = 30 * 24 * time.Hour
	if raw := os.Getenv("KUBEGRANT_GRANT_MAX_TTL"); raw != "" {
		cfg.GrantMaxTTL, err = time.ParseDuration(raw)
		if err != nil || cfg.GrantMaxTTL < time.Minute || cfg.GrantMaxTTL > 366*24*time.Hour {
			return Config{}, fmt.Errorf("grant maximum TTL must be between 1m and 366 days")
		}
	}
	cfg.ClusterID, cfg.PermissionRef = os.Getenv("KUBEGRANT_CLUSTER_ID"), os.Getenv("KUBEGRANT_PERMISSION_REF")
	if (cfg.ClusterID == "") != (cfg.PermissionRef == "") {
		return Config{}, fmt.Errorf("cluster ID and permission reference must be configured together")
	}
	if raw := os.Getenv("KUBEGRANT_SIGNING_ENABLED"); raw != "" {
		cfg.SigningEnabled, err = strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid signing switch")
		}
	}
	cfg.ClusterEndpoint, cfg.ClusterCAFile = os.Getenv("KUBEGRANT_CLUSTER_ENDPOINT"), os.Getenv("KUBEGRANT_CLUSTER_CA_FILE")
	if cfg.SigningEnabled {
		u, e := url.Parse(cfg.ClusterEndpoint)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || cfg.ClusterCAFile == "" || cfg.ClusterID == "" {
			return Config{}, fmt.Errorf("signing requires a cluster target, HTTPS API endpoint and public CA file")
		}
	}
	cfg.KubernetesAPI = os.Getenv("KUBEGRANT_KUBERNETES_API")
	if cfg.KubernetesAPI == "" {
		cfg.KubernetesAPI = "https://kubernetes.default.svc"
	}
	cfg.KubernetesCAFile = os.Getenv("KUBEGRANT_KUBERNETES_CA_FILE")
	if cfg.KubernetesCAFile == "" {
		cfg.KubernetesCAFile = "/var/run/kubegrant/api/ca.crt"
	}
	cfg.KubernetesTokenFile = os.Getenv("KUBEGRANT_KUBERNETES_TOKEN_FILE")
	if cfg.KubernetesTokenFile == "" {
		cfg.KubernetesTokenFile = "/var/run/kubegrant/api/token"
	}
	for _, raw := range strings.Split(os.Getenv("KUBEGRANT_LDAP_URLS"), ",") {
		if value := strings.TrimSpace(raw); value != "" {
			cfg.LDAP.URLs = append(cfg.LDAP.URLs, value)
		}
	}
	cfg.LDAP.BaseDN, cfg.LDAP.CAFile = os.Getenv("KUBEGRANT_LDAP_BASE_DN"), os.Getenv("KUBEGRANT_LDAP_CA_FILE")
	for _, raw := range strings.Split(os.Getenv("KUBEGRANT_ADMIN_GROUPS"), ",") {
		if value := strings.TrimSpace(raw); value != "" {
			cfg.LDAP.AdminGroups = append(cfg.LDAP.AdminGroups, value)
		}
	}
	if len(cfg.LDAP.URLs) > 0 && os.Getenv("KUBEGRANT_PUBLIC_URL") == "" {
		return Config{}, fmt.Errorf("KUBEGRANT_PUBLIC_URL is required when FreeIPA is enabled")
	}
	return cfg, nil
}
