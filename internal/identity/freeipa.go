package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	ErrCredentials  = errors.New("invalid credentials")
	ErrUnavailable  = errors.New("identity provider unavailable")
	usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
)

type Profile struct {
	Provider, Issuer, Subject string
	Username, DisplayName     string
	Administrator             bool
}

type Authenticator interface {
	Authenticate(context.Context, string, string) (Profile, error)
}

type FreeIPAConfig struct {
	URLs           []string
	BaseDN, CAFile string
	AdminGroups    []string
}

type FreeIPA struct {
	urls        []string
	baseDN      string
	roots       *x509.CertPool
	adminGroups []*ldap.DN
}

func NewFreeIPA(cfg FreeIPAConfig) (*FreeIPA, error) {
	if len(cfg.URLs) == 0 || strings.TrimSpace(cfg.BaseDN) == "" || cfg.CAFile == "" {
		return nil, errors.New("FreeIPA requires LDAPS URLs, base DN, and CA file")
	}
	base, err := ldap.ParseDN(cfg.BaseDN)
	if err != nil || len(base.RDNs) == 0 {
		return nil, errors.New("invalid FreeIPA base DN")
	}
	for _, raw := range cfg.URLs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, errors.New("FreeIPA endpoints must be ldaps://host[:port] without credentials")
		}
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read FreeIPA CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("FreeIPA CA file contains no certificates")
	}
	p := &FreeIPA{urls: append([]string(nil), cfg.URLs...), baseDN: base.String(), roots: roots}
	for _, group := range cfg.AdminGroups {
		dn, err := ldap.ParseDN("cn=" + ldap.EscapeDN(group) + ",cn=groups,cn=accounts," + p.baseDN)
		if err != nil {
			return nil, errors.New("invalid FreeIPA administrator group")
		}
		p.adminGroups = append(p.adminGroups, dn)
	}
	return p, nil
}

func (p *FreeIPA) Authenticate(ctx context.Context, username, password string) (Profile, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !usernamePattern.MatchString(username) || password == "" || len(password) > 4096 {
		return Profile{}, ErrCredentials
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var conn *ldap.Conn
	for _, raw := range p.urls {
		if ctx.Err() != nil {
			break
		}
		u, _ := url.Parse(raw)
		deadline, _ := ctx.Deadline()
		timeout := min(3*time.Second, time.Until(deadline))
		c, err := ldap.DialURL(raw,
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
			ldap.DialWithTLSConfig(&tls.Config{RootCAs: p.roots, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}),
		)
		if err == nil {
			conn = c
			break
		}
	}
	if conn == nil {
		return Profile{}, ErrUnavailable
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetTimeout(time.Until(deadline))
	dn := "uid=" + ldap.EscapeDN(username) + ",cn=users,cn=accounts," + p.baseDN
	if err := conn.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Profile{}, ErrCredentials
		}
		return Profile{}, ErrUnavailable
	}
	result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 5, false, "(objectClass=person)", []string{"uid", "cn", "ipaUniqueID", "memberOf", "nsAccountLock"}, nil))
	if err != nil || len(result.Entries) != 1 {
		return Profile{}, ErrUnavailable
	}
	e := result.Entries[0]
	if strings.EqualFold(e.GetAttributeValue("nsAccountLock"), "TRUE") {
		return Profile{}, ErrCredentials
	}
	subject, uid := e.GetAttributeValue("ipaUniqueID"), e.GetAttributeValue("uid")
	if subject == "" || uid == "" {
		return Profile{}, ErrUnavailable
	}
	admin := false
	for _, raw := range e.GetAttributeValues("memberOf") {
		group, err := ldap.ParseDN(raw)
		if err != nil {
			continue
		}
		for _, allowed := range p.adminGroups {
			if group.EqualFold(allowed) {
				admin = true
			}
		}
	}
	return Profile{Provider: "freeipa", Issuer: p.baseDN, Subject: subject, Username: uid,
		DisplayName: e.GetAttributeValue("cn"), Administrator: admin}, nil
}
