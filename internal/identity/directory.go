package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var ErrDirectory = errors.New("directory cannot be read completely")
var ErrDirectoryForbidden = errors.New("directory administrator verification required")

// Credentials are supplied only for this operation. Implementations must not
// create sessions, persist passwords or derive Kubernetes grants from IPA groups.
type UserDirectory interface {
	ReadUsers(context.Context, string, string) (Profile, []Profile, error)
}

func (p *FreeIPA) ReadUsers(ctx context.Context, username, password string) (Profile, []Profile, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	actor, err := p.Authenticate(ctx, username, password)
	if err != nil {
		return Profile{}, nil, err
	}
	if !actor.Administrator {
		return Profile{}, nil, ErrDirectoryForbidden
	}
	conn, err := p.connect(ctx)
	if err != nil {
		return Profile{}, nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	dn := "uid=" + ldap.EscapeDN(actor.Username) + ",cn=users,cn=accounts," + p.baseDN
	if err = conn.Bind(dn, password); err != nil {
		return Profile{}, nil, ErrUnavailable
	}
	profiles, err := p.readPages(conn)
	return actor, profiles, err
}

type directorySearcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func (p *FreeIPA) readPages(conn directorySearcher) ([]Profile, error) {
	control := ldap.NewControlPaging(200)
	result := []Profile{}
	seen := map[string]bool{}
	usernames := map[string]bool{}
	for {
		page, err := conn.Search(ldap.NewSearchRequest("cn=users,cn=accounts,"+p.baseDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 5, false, "(objectClass=posixAccount)", []string{"uid", "cn", "ipaUniqueID"}, []ldap.Control{control}))
		if err != nil || len(page.Referrals) > 0 {
			return nil, ErrDirectory
		}
		for _, entry := range page.Entries {
			uid, id := entry.GetAttributeValue("uid"), entry.GetAttributeValue("ipaUniqueID")
			dn, e := ldap.ParseDN(entry.DN)
			expected, e2 := ldap.ParseDN("uid=" + ldap.EscapeDN(uid) + ",cn=users,cn=accounts," + p.baseDN)
			// Reject hidden stable IDs or malformed/duplicate results instead of doing
			// a partial import or attaching permissions by a mutable username.
			if e != nil || e2 != nil || !dn.EqualFold(expected) || !usernamePattern.MatchString(uid) || id == "" || len(id) > 256 || strings.ContainsAny(id, "\x00\r\n") || len(entry.GetAttributeValues("ipaUniqueID")) != 1 || len(entry.GetAttributeValues("uid")) != 1 || seen[id] || usernames[strings.ToLower(uid)] || len(result) >= 10000 {
				return nil, ErrDirectory
			}
			seen[id] = true
			usernames[strings.ToLower(uid)] = true
			result = append(result, Profile{Provider: "freeipa", Issuer: p.baseDN, Subject: id, Username: uid, DisplayName: entry.GetAttributeValue("cn")})
		}
		next, ok := ldap.FindControl(page.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok {
			return nil, ErrDirectory
		}
		if len(next.Cookie) == 0 {
			break
		}
		control.SetCookie(next.Cookie)
	}
	if len(result) == 0 {
		return nil, ErrDirectory
	}
	return result, nil
}
