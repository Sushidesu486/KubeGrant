package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func directoryFixture(t *testing.T, attributes map[string][]string) FreeIPAConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				bind, err := ber.ReadPacket(conn)
				if err != nil {
					return
				}
				if len(bind.Children) < 2 || len(bind.Children[1].Children) < 3 {
					return
				}
				id := bind.Children[0].Value.(int64)
				code := int64(0)
				if bind.Children[1].Children[1].Data.String() != "uid=alice,cn=users,cn=accounts,dc=example,dc=com" || bind.Children[1].Children[2].Data.String() != "correct" {
					code = 49
				}
				send := func(id int64, operation *ber.Packet) {
					packet := ber.NewSequence("")
					packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
					packet.AppendChild(operation)
					conn.Write(packet.Bytes())
				}
				result := func(tag ber.Tag, code int64) *ber.Packet {
					p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
					p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
					p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					return p
				}
				send(id, result(1, code))
				if code != 0 {
					return
				}
				search, err := ber.ReadPacket(conn)
				if err != nil {
					return
				}
				id = search.Children[0].Value.(int64)
				entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
				entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=alice,cn=users,cn=accounts,dc=example,dc=com", ""))
				attrs := ber.NewSequence("")
				for name, values := range attributes {
					attr := ber.NewSequence("")
					attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
					set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
					for _, value := range values {
						set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
					}
					attr.AppendChild(set)
					attrs.AppendChild(attr)
				}
				entry.AppendChild(attrs)
				send(id, entry)
				send(id, result(5, 0))
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); workers.Wait() })
	return FreeIPAConfig{URLs: []string{"ldaps://" + listener.Addr().String()}, BaseDN: "dc=example,dc=com", CAFile: ca, AdminGroups: []string{"admins"}}
}

func TestFreeIPALDAPSAndIdentityMapping(t *testing.T) {
	attrs := map[string][]string{"uid": {"alice"}, "cn": {"Alice"}, "ipaUniqueID": {"stable-uuid"}, "memberOf": {"cn=admins,cn=groups,cn=accounts,dc=example,dc=com"}}
	cfg := directoryFixture(t, attrs)
	p, err := NewFreeIPA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := p.Authenticate(context.Background(), "Alice", "correct")
	if err != nil || profile.Subject != "stable-uuid" || !profile.Administrator || profile.Username != "alice" {
		t.Fatal("LDAPS identity mapping failed:", profile, err)
	}
	if _, err = p.Authenticate(context.Background(), "alice", "wrong"); !errors.Is(err, ErrCredentials) {
		t.Fatal("incorrect password accepted:", err)
	}
	if _, err = p.Authenticate(context.Background(), "alice", ""); !errors.Is(err, ErrCredentials) {
		t.Fatal("empty bind password accepted")
	}
	cfg.AdminGroups = nil
	p, err = NewFreeIPA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	profile, err = p.Authenticate(context.Background(), "alice", "correct")
	if err != nil || profile.Administrator {
		t.Fatal("administrator mapping must be explicitly configured")
	}
	cfg.URLs = []string{"ldap://127.0.0.1:389"}
	if _, err = NewFreeIPA(cfg); err == nil {
		t.Fatal("unencrypted LDAP accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = p.Authenticate(ctx, "alice", "correct"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled request did not fail closed")
	}
}

func TestFreeIPARejectsUntrustedCAAndIncompleteIdentity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string][]string
		want  error
	}{
		{"missing stable ID", map[string][]string{"uid": {"alice"}}, ErrUnavailable},
		{"locked account", map[string][]string{"uid": {"alice"}, "ipaUniqueID": {"uuid"}, "nsAccountLock": {"TRUE"}}, ErrCredentials},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := directoryFixture(t, tc.attrs)
			p, err := NewFreeIPA(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.Authenticate(context.Background(), "alice", "correct"); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
	cfg := directoryFixture(t, map[string][]string{"uid": {"alice"}, "ipaUniqueID": {"uuid"}})
	unrelated := directoryFixture(t, nil)
	cfg.CAFile = unrelated.CAFile
	p, err := NewFreeIPA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Authenticate(context.Background(), "alice", "correct"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("untrusted LDAP certificate accepted")
	}
}
