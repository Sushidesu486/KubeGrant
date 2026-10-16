package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

type pageSearch struct {
	pages []*ldap.SearchResult
	fail  bool
	calls int
	t     *testing.T
}

func (s *pageSearch) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	s.t.Helper()
	if r.BaseDN != "cn=users,cn=accounts,dc=example,dc=com" || r.Scope != ldap.ScopeSingleLevel || r.Filter != "(objectClass=posixAccount)" {
		s.t.Fatal("unbounded or wrong directory search")
	}
	if len(r.Attributes) != 3 {
		s.t.Fatal("directory requested unnecessary attributes")
	}
	paging := ldap.FindControl(r.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
	if s.calls > 0 && string(paging.Cookie) != "next" {
		s.t.Fatal("paging cursor lost")
	}
	s.calls++
	if s.fail && s.calls == 2 {
		return nil, errors.New("partial page failure")
	}
	page := s.pages[0]
	s.pages = s.pages[1:]
	return page, nil
}
func entry(uid, id string) *ldap.Entry {
	return ldap.NewEntry("uid="+uid+",cn=users,cn=accounts,dc=example,dc=com", map[string][]string{"uid": {uid}, "ipaUniqueID": {id}, "cn": {uid}})
}
func page(cookie string, entries ...*ldap.Entry) *ldap.SearchResult {
	c := ldap.NewControlPaging(200)
	c.SetCookie([]byte(cookie))
	return &ldap.SearchResult{Entries: entries, Controls: []ldap.Control{c}}
}
func TestDirectoryPagingAndIncompleteReads(t *testing.T) {
	p := &FreeIPA{baseDN: "dc=example,dc=com"}
	for _, tc := range []struct {
		name  string
		pages []*ldap.SearchResult
		fail  bool
		count int
	}{
		{"all pages", []*ldap.SearchResult{page("next", entry("alice", "uuid1")), page("", entry("bob", "uuid2"))}, false, 2},
		{"page failure", []*ldap.SearchResult{page("next", entry("alice", "uuid1"))}, true, 0},
		{"hidden stable identity", []*ldap.SearchResult{page("", entry("alice", ""))}, false, 0},
		{"duplicate identity", []*ldap.SearchResult{page("next", entry("alice", "uuid1")), page("", entry("bob", "uuid1"))}, false, 0},
		{"missing paging control", []*ldap.SearchResult{{Entries: []*ldap.Entry{entry("alice", "uuid1")}}}, false, 0},
		{"empty hidden directory", []*ldap.SearchResult{page("")}, false, 0},
		{"referral", []*ldap.SearchResult{{Referrals: []string{"ldaps://untrusted.invalid"}}}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &pageSearch{pages: tc.pages, fail: tc.fail, t: t}
			profiles, err := p.readPages(s)
			if tc.count == 0 {
				if !errors.Is(err, ErrDirectory) || profiles != nil {
					t.Fatal("partial or unverified directory accepted")
				}
			} else if err != nil || len(profiles) != tc.count || profiles[0].Provider != "freeipa" || profiles[0].Administrator {
				t.Fatal("complete identity-only directory import failed", err)
			}
		})
	}
}
func TestDirectoryRequiresFreshAdministratorAuthentication(t *testing.T) {
	p, err := NewFreeIPA(directoryFixture(t, map[string][]string{"uid": {"alice"}, "ipaUniqueID": {"stable-uuid"}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = p.ReadUsers(context.Background(), "alice", "wrong"); !errors.Is(err, ErrCredentials) {
		t.Fatal("bad directory password accepted", err)
	}
	if _, _, err = p.ReadUsers(context.Background(), "alice", "correct"); !errors.Is(err, ErrDirectoryForbidden) {
		t.Fatal("non-admin could read directory", err)
	}
}

func TestDirectoryAdminLDAPSRead(t *testing.T) {
	p, err := NewFreeIPA(directoryFixture(t, map[string][]string{"uid": {"alice"}, "cn": {"Alice"}, "ipaUniqueID": {"uuid-one"}, "memberOf": {"cn=admins,cn=groups,cn=accounts,dc=example,dc=com"}}))
	if err != nil {
		t.Fatal(err)
	}
	actor, profiles, err := p.ReadUsers(context.Background(), "alice", "correct")
	if err != nil || !actor.Administrator || len(profiles) != 1 || profiles[0].Subject != "uuid-one" || profiles[0].Administrator {
		t.Fatal("verified LDAPS directory read failed", err)
	}
}
