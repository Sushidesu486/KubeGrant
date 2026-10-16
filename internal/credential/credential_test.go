package credential

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/grant"
)

var testNow = time.Date(2026, 10, 16, 4, 0, 0, 0, time.UTC)

func testGrant() grant.Grant {
	return grant.Grant{ID: "grant-one", MemberID: "member-one", ClusterID: "cluster-one", PermissionRef: "existing-role",
		CreatedAt: testNow.Add(-time.Hour), ExpiresAt: testNow.Add(30 * 24 * time.Hour)}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(400 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) sign(t *testing.T, r Request, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	b, _ := pem.Decode(r.CSR)
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject,
		NotBefore: testNow.Add(-time.Minute), NotAfter: r.NotAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mustNew(t *testing.T, g grant.Grant) *Pending {
	t.Helper()
	p, err := Standard.New(g, g.MemberID, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPersonalKubeconfigAndPublicPersistence(t *testing.T) {
	g, ca := testGrant(), newTestCA(t)
	p := mustNew(t, g)
	r := p.PublicRequest()
	if r.NotAfter != testNow.Add(24*time.Hour) {
		t.Fatal("credential lifetime must be 24h, independent of longer grant")
	}
	csr, err := Standard.ValidateRequest(r, g, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.Subject.Organization) != 0 || csr.Subject.CommonName != Subject(g) {
		t.Fatal("CSR must have only its independent user identity")
	}
	stored, err := json.Marshal(r)
	if err != nil || bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("public signing record contains private material", err)
	}
	hidden, err := json.Marshal(p)
	if err != nil || string(hidden) != "{}" {
		t.Fatal("pending download must not serialize private material")
	}
	// Callers cannot mutate the pending request by editing the public copy.
	r.CSR[0] = 'x'
	if _, err := Standard.ValidateRequest(p.PublicRequest(), g, testNow); err != nil {
		t.Fatal("public request shares mutable storage with private attempt")
	}
	r = p.PublicRequest()
	cert := ca.sign(t, r, nil)
	result, err := p.Kubeconfig(g, g.MemberID, "https://api.example:6443", cert, ca.pem, testNow)
	if err != nil || !result.ExpiresAt.Equal(r.NotAfter) {
		t.Fatal("failed to prepare valid kubeconfig", err)
	}
	var config struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Current    string `json:"current-context"`
		Clusters   []struct {
			Name    string `json:"name"`
			Cluster struct {
				Server string `json:"server"`
				CA     []byte `json:"certificate-authority-data"`
			} `json:"cluster"`
		} `json:"clusters"`
		Users []struct {
			Name string `json:"name"`
			User struct {
				Certificate []byte `json:"client-certificate-data"`
				Key         []byte `json:"client-key-data"`
			} `json:"user"`
		} `json:"users"`
		Contexts []struct {
			Name    string `json:"name"`
			Context struct {
				Cluster string `json:"cluster"`
				User    string `json:"user"`
			} `json:"context"`
		} `json:"contexts"`
	}
	if err := json.Unmarshal(result.Data, &config); err != nil {
		t.Fatal(err)
	}
	if config.APIVersion != "v1" || config.Kind != "Config" || config.Current != config.Contexts[0].Name ||
		config.Contexts[0].Context.User != config.Users[0].Name || config.Contexts[0].Context.Cluster != config.Clusters[0].Name ||
		config.Clusters[0].Cluster.Server != "https://api.example:6443" || !bytes.Equal(config.Clusters[0].Cluster.CA, ca.pem) {
		t.Fatal("kubeconfig identity or connection metadata was lost")
	}
	pair, err := tls.X509KeyPair(config.Users[0].User.Certificate, config.Users[0].User.Key)
	if err != nil {
		t.Fatal("downloaded certificate and private key do not match", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.Subject.CommonName != Subject(g) {
		t.Fatal("downloaded identity does not match grant")
	}
	for _, forbidden := range []string{"exec", "insecure-skip-tls-verify", "client-key\"", "certificate-authority\""} {
		if strings.Contains(string(result.Data), `"`+forbidden) {
			t.Fatal("download contains plugin, insecure option or filesystem reference")
		}
	}
	publicResult, _ := json.Marshal(result)
	if bytes.Contains(publicResult, []byte("client-key")) || bytes.Contains(publicResult, result.Data) {
		t.Fatal("download metadata must not serialize attachment")
	}
	again := mustNew(t, g).PublicRequest()
	if again.Fingerprint == r.Fingerprint || again.ID == r.ID || again.Subject != r.Subject {
		t.Fatal("each attempt needs fresh keys and an ID, while retaining grant identity")
	}
}

func TestSigningTrustBundleValidation(t *testing.T) {
	ca := newTestCA(t)
	if err := ValidateTrustBundle(ca.pem, testNow); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("invalid"), append(bytes.Clone(ca.pem), []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----")...)} {
		if err := ValidateTrustBundle(data, testNow); err == nil {
			t.Fatal("invalid signing trust bundle accepted")
		}
	}
	if err := ValidateTrustBundle(ca.pem, ca.cert.NotAfter); err == nil {
		t.Fatal("expired signing CA accepted")
	}
}

func TestAuthorizationAndLifetimeBoundaries(t *testing.T) {
	g := testGrant()
	for _, tc := range []struct {
		name string
		g    grant.Grant
		user string
		at   time.Time
	}{
		{"other member", g, "other", testNow},
		{"empty member", g, "", testNow},
		{"not yet active", g, g.MemberID, g.CreatedAt.Add(-time.Second)},
		{"expired", g, g.MemberID, g.ExpiresAt},
		{"too close to expiry", g, g.MemberID, g.ExpiresAt.Add(-MinimumTTL + time.Nanosecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Standard.New(tc.g, tc.user, tc.at); err == nil {
				t.Fatal("accepted unauthorized or too short request")
			}
		})
	}
	short := g
	short.ExpiresAt = testNow.Add(90*time.Minute + 123*time.Millisecond)
	p := mustNew(t, short)
	if p.PublicRequest().NotAfter != short.ExpiresAt.Truncate(time.Second) {
		t.Fatal("certificate deadline must not exceed the grant")
	}
	seconds, err := Standard.ExpirationSeconds(p.PublicRequest(), testNow.Add(time.Minute))
	if err != nil || seconds != 89*60 {
		t.Fatal("retry extended absolute deadline", seconds, err)
	}
	if _, err := Standard.ExpirationSeconds(p.PublicRequest(), short.ExpiresAt.Add(-MinimumTTL+time.Second)); !errors.Is(err, ErrLifetime) {
		t.Fatal("accepted Kubernetes CSR TTL below 600 seconds")
	}
	boundary := g
	boundary.ExpiresAt = testNow.Add(MinimumTTL)
	if _, err := Standard.New(boundary, boundary.MemberID, testNow); err != nil {
		t.Fatal("exact 600 second lifetime should be permitted", err)
	}
	revoked := testNow
	g.RevokedAt = &revoked
	if _, err := Standard.New(g, g.MemberID, testNow); !errors.Is(err, ErrAuthorization) {
		t.Fatal("revocation boundary should prevent new requests")
	}
	old := testGrant()
	newGrant := old
	newGrant.ID = "new-grant"
	if Subject(old) == Subject(newGrant) {
		t.Fatal("new grant reactivated old certificate identity")
	}
	newGrant = old
	newGrant.ClusterID = "other-cluster"
	if Subject(old) == Subject(newGrant) {
		t.Fatal("identity must also be scoped to the cluster")
	}
}

func TestRejectTamperedPublicRequests(t *testing.T) {
	g := testGrant()
	p := mustNew(t, g)
	for _, tc := range []struct {
		name   string
		mutate func(*Request)
	}{
		{"grant", func(r *Request) { r.GrantID = "other" }},
		{"member", func(r *Request) { r.MemberID = "other" }},
		{"cluster", func(r *Request) { r.ClusterID = "other" }},
		{"role", func(r *Request) { r.PermissionRef = "cluster-admin" }},
		{"policy", func(r *Request) { r.Policy = Operations }},
		{"subject", func(r *Request) { r.Subject = "system:admin" }},
		{"fingerprint", func(r *Request) { r.Fingerprint = "wrong" }},
		{"future request", func(r *Request) { r.CreatedAt = testNow.Add(time.Second) }},
		{"before grant", func(r *Request) { r.CreatedAt = g.CreatedAt.Add(-time.Second) }},
		{"expiry", func(r *Request) { r.NotAfter = testNow }},
		{"extended validity", func(r *Request) { r.NotAfter = testNow.Add(Lifetime + time.Second) }},
		{"multiple CSR blocks", func(r *Request) { r.CSR = append(r.CSR, r.CSR...) }},
		{"leading garbage", func(r *Request) { r.CSR = append([]byte("garbage\n"), r.CSR...) }},
		{"trailing garbage", func(r *Request) { r.CSR = append(r.CSR, []byte("garbage")...) }},
		{"oversized CSR", func(r *Request) { r.CSR = bytes.Repeat([]byte("x"), maxPEMBytes+1) }},
		{"wrong PEM kind", func(r *Request) { r.CSR = []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := p.PublicRequest()
			tc.mutate(&r)
			if _, err := Standard.ValidateRequest(r, g, testNow); err == nil {
				t.Fatal("tampered signing request accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*x509.CertificateRequest)
	}{
		{"extra group", func(c *x509.CertificateRequest) { c.Subject.Organization = []string{"system:masters"} }},
		{"extra UID", func(c *x509.CertificateRequest) {
			c.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57683, 2}, Value: "admin"}}
		}},
		{"extra SAN", func(c *x509.CertificateRequest) { c.DNSNames = []string{"example.com"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := p.PublicRequest()
			template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: r.Subject}}
			tc.mutate(template)
			der, err := x509.CreateCertificateRequest(rand.Reader, template, p.key)
			if err != nil {
				t.Fatal(err)
			}
			r.CSR = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
			if _, err := Standard.ValidateRequest(r, g, testNow); err == nil {
				t.Fatal("request with additional identity accepted")
			}
		})
	}
	// A well-formed CSR with a tampered signature must not be approved.
	r := p.PublicRequest()
	b, _ := pem.Decode(r.CSR)
	b.Bytes[len(b.Bytes)-1] ^= 1
	r.CSR = pem.EncodeToMemory(b)
	if _, err := Standard.ValidateRequest(r, g, testNow); err == nil {
		t.Fatal("invalid CSR signature accepted")
	}
}

func TestOperationsPolicySupportsOneYearWithoutChangingPermissions(t *testing.T) {
	g, ca := testGrant(), newTestCA(t)
	g.ExpiresAt = testNow.Add(400 * 24 * time.Hour)
	g.CredentialPolicy = "operations"
	p, err := Operations.New(g, g.MemberID, testNow)
	if err != nil {
		t.Fatal(err)
	}
	r := p.PublicRequest()
	if r.Policy != Operations || !r.NotAfter.Equal(testNow.Add(365*24*time.Hour)) || r.PermissionRef != g.PermissionRef {
		t.Fatal("operations lifetime must not change the assigned permission")
	}
	if _, err := Operations.ValidateRequest(r, g, testNow); err != nil {
		t.Fatal("one year request rejected", err)
	}
	cert := ca.sign(t, r, nil)
	result, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, ca.pem, testNow)
	if err != nil || !result.ExpiresAt.Equal(r.NotAfter) {
		t.Fatal("one year credential rejected", err)
	}
	if _, err := Operations.ValidateRequest(r, g, testNow.Add(30*24*time.Hour)); err != nil {
		t.Fatal("operations credential must not inherit the 24h cap", err)
	}
	seconds, err := Operations.ExpirationSeconds(r, testNow.Add(time.Minute))
	if err != nil || seconds != 365*24*3600-60 {
		t.Fatal("delayed signing changed the absolute one year deadline", seconds, err)
	}
	if _, err := Standard.ValidateRequest(r, g, testNow); err == nil {
		t.Fatal("standard policy accepted an operations request")
	}
	if _, err := Standard.ExpirationSeconds(r, testNow); err == nil {
		t.Fatal("standard policy accepted an operations TTL")
	}
	// Changing the untrusted metadata cannot authorize a longer request under
	// the server's standard policy, even if the grant itself lasts 400 days.
	r.Policy = Standard
	if _, err := Standard.ValidateRequest(r, g, testNow); err == nil {
		t.Fatal("member could relabel a long credential as standard")
	}
	if _, err := Standard.ExpirationSeconds(r, testNow); err == nil {
		t.Fatal("member could bypass standard expiration limits")
	}
	r = p.PublicRequest()
	r.NotAfter = r.CreatedAt.Add(OperationsLifetime + time.Second)
	if _, err := Operations.ValidateRequest(r, g, testNow); err == nil {
		t.Fatal("operations request exceeded one year")
	}
	if _, err := Operations.ExpirationSeconds(r, testNow); err == nil {
		t.Fatal("operations CSR TTL exceeded one year")
	}
	tooLong := ca.sign(t, p.PublicRequest(), func(c *x509.Certificate) { c.NotAfter = c.NotAfter.Add(time.Second) })
	if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", tooLong, ca.pem, testNow); !errors.Is(err, ErrCertificate) {
		t.Fatal("signer could extend operations certificate beyond one year")
	}
	revoked := testNow.Add(30 * 24 * time.Hour)
	g.RevokedAt = &revoked
	if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, ca.pem, revoked); !errors.Is(err, ErrAuthorization) {
		t.Fatal("long lived credential bypassed revocation before delivery")
	}
}

func TestOperationsPolicyStillHonorsGrantExpiry(t *testing.T) {
	g := testGrant() // 30 day grant, despite requesting the one year policy.
	g.CredentialPolicy = "operations"
	p, err := Operations.New(g, g.MemberID, testNow)
	if err != nil || !p.PublicRequest().NotAfter.Equal(g.ExpiresAt) {
		t.Fatal("operations certificate must never outlive its finite grant", err)
	}
	for _, policy := range []Policy{"", "permanent", "unknown"} {
		if _, err := policy.New(g, g.MemberID, testNow); err == nil {
			t.Fatal("unknown policy silently enabled signing", policy)
		}
		if _, err := policy.ValidateRequest(p.PublicRequest(), g, testNow); err == nil {
			t.Fatal("unknown policy validated a signing request", policy)
		}
		if _, err := policy.ExpirationSeconds(p.PublicRequest(), testNow); err == nil {
			t.Fatal("unknown policy supplied signing TTL", policy)
		}
	}
}

func TestPermanentGrantAndPolicyCannotBeSelectedByMember(t *testing.T) {
	g := testGrant()
	if _, err := Operations.New(g, g.MemberID, testNow); !errors.Is(err, ErrAuthorization) {
		t.Fatal("member selected operations without assigned policy")
	}
	g.Permanent = true
	g.ExpiresAt = time.Time{}
	g.CredentialPolicy = "operations"
	p, err := Operations.New(g, g.MemberID, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !p.PublicRequest().NotAfter.Equal(testNow.Add(365 * 24 * time.Hour)) {
		t.Fatal("permanent grant produced an unbounded certificate")
	}
	g.CredentialPolicy = "standard"
	if _, err := Operations.ValidateRequest(p.PublicRequest(), g, testNow); err == nil {
		t.Fatal("downgraded grant accepted old operations signing request")
	}
}

func TestRejectInvalidSignedCertificates(t *testing.T) {
	g, ca := testGrant(), newTestCA(t)
	p := mustNew(t, g)
	r := p.PublicRequest()
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{"wrong identity", func(c *x509.Certificate) { c.Subject.CommonName = "other" }},
		{"admin group", func(c *x509.Certificate) { c.Subject.Organization = []string{"system:masters"} }},
		{"extra UID", func(c *x509.Certificate) {
			c.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57683, 2}, Value: "admin"}}
		}},
		{"overlong", func(c *x509.Certificate) { c.NotAfter = r.NotAfter.Add(time.Second) }},
		{"expired", func(c *x509.Certificate) { c.NotAfter = testNow }},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = testNow.Add(time.Minute) }},
		{"server only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{"extra use", func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) }},
		{"extra key use", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment }},
		{"missing key use", func(c *x509.Certificate) { c.KeyUsage = 0 }},
		{"unknown use", func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}} }},
		{"CA", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{"extra DNS", func(c *x509.Certificate) { c.DNSNames = []string{"api.example"} }},
		{"extra IP", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }},
		{"empty SAN extension", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := ca.sign(t, r, tc.mutate)
			if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, ca.pem, testNow); !errors.Is(err, ErrCertificate) {
				t.Fatal("unsafe certificate accepted", err)
			}
		})
	}
	cert := ca.sign(t, r, nil)
	otherCA := newTestCA(t)
	if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, otherCA.pem, testNow); !errors.Is(err, ErrCertificate) {
		t.Fatal("wrong signing CA accepted")
	}
	other := mustNew(t, g)
	if _, err := other.Kubeconfig(g, g.MemberID, "https://api.example", cert, ca.pem, testNow); !errors.Is(err, ErrCertificate) {
		t.Fatal("certificate for a different private key accepted")
	}
	if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", append(cert, []byte("extra")...), ca.pem, testNow); !errors.Is(err, ErrCertificate) {
		t.Fatal("certificate PEM with unrelated data accepted")
	}
	if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, append(ca.pem, []byte("private junk")...), testNow); !errors.Is(err, ErrCertificate) {
		t.Fatal("CA bundle with unrelated data accepted")
	}
	shorter := ca.sign(t, r, func(c *x509.Certificate) { c.NotAfter = testNow.Add(time.Hour) })
	if result, err := p.Kubeconfig(g, g.MemberID, "https://api.example", shorter, ca.pem, testNow); err != nil || !result.ExpiresAt.Equal(testNow.Add(time.Hour)) {
		t.Fatal("shorter signer lifetime should be accepted", err)
	}
}

// This exercises a real mutual TLS connection with the exact material from the
// generated attachment. It verifies authentication only, not Kubernetes RBAC.
func TestKubeconfigAuthenticatesMutualTLS(t *testing.T) {
	g, ca := testGrant(), newTestCA(t)
	p := mustNew(t, g)
	cert := ca.sign(t, p.PublicRequest(), nil)
	download, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, ca.pem, testNow)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Users []struct {
			User struct {
				Certificate []byte `json:"client-certificate-data"`
				Key         []byte `json:"client-key-data"`
			} `json:"user"`
		} `json:"users"`
	}
	if err := json.Unmarshal(download.Data, &config); err != nil {
		t.Fatal(err)
	}
	clientKeyPair, err := tls.X509KeyPair(config.Users[0].User.Certificate, config.Users[0].User.Key)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: testNow.Add(-time.Minute), NotAfter: testNow.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	serverCert, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca.cert, &serverKey.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 {
			t.Error("client certificate was not verified")
		}
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		Time: func() time.Time { return testNow }, Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert}, PrivateKey: serverKey}}}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool,
		Certificates: []tls.Certificate{clientKeyPair}, Time: func() time.Time { return testNow }}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal("downloaded kubeconfig failed client TLS authentication", err)
	}
	defer response.Body.Close()
	identity, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || string(identity) != Subject(g) {
		t.Fatal("unexpected authenticated identity", response.StatusCode, err)
	}
}

func TestDownloadRechecksGrantAndMember(t *testing.T) {
	g, ca := testGrant(), newTestCA(t)
	p := mustNew(t, g)
	cert := ca.sign(t, p.PublicRequest(), nil)
	if _, err := p.Kubeconfig(g, "different-member", "https://api.example", cert, ca.pem, testNow); !errors.Is(err, ErrAuthorization) {
		t.Fatal("cross member download accepted")
	}
	revoked := testNow.Add(time.Second)
	g.RevokedAt = &revoked
	if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, ca.pem, revoked); !errors.Is(err, ErrAuthorization) {
		t.Fatal("grant revoked while signing was still delivered")
	}
	g.RevokedAt = nil
	g.ExpiresAt = testNow.Add(time.Minute)
	if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, ca.pem, g.ExpiresAt); !errors.Is(err, ErrAuthorization) {
		t.Fatal("expired grant delivered")
	}
	g = testGrant()
	g.PermissionRef = "other-role"
	if _, err := p.Kubeconfig(g, g.MemberID, "https://api.example", cert, ca.pem, testNow); !errors.Is(err, ErrAuthorization) {
		t.Fatal("grant changed during signing was delivered")
	}
	g = testGrant()
	for _, endpoint := range []string{"http://api.example", "https://", "https://user:secret@api.example", "https://api.example/proxy", "https://api.example?secret=value", "https://api.example?", "https://api.example#fragment", "file:///tmp/config"} {
		if _, err := p.Kubeconfig(g, g.MemberID, endpoint, cert, ca.pem, testNow); err == nil {
			t.Fatal("unsafe cluster endpoint accepted", endpoint)
		}
	}
}
