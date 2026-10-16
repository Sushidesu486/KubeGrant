// Package credential owns the public signing request and the ephemeral private
// key used to prepare a personal kubeconfig. It never calls a Kubernetes API.
package credential

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/grant"
)

const (
	Lifetime           = 24 * time.Hour
	OperationsLifetime = 365 * 24 * time.Hour
	MinimumTTL         = 10 * time.Minute
	SignerName         = "kubernetes.io/kube-apiserver-client"
	maxPEMBytes        = 64 << 10
)

// Policy is resolved from an administrator's grant by the trusted caller, never
// from the member's download request or their FreeIPA platform-admin status.
// It describes credential lifetime, independently of Kubernetes permission level.
type Policy string

const (
	Standard   Policy = "standard"
	Operations Policy = "operations"
)

func (p Policy) lifetime() (time.Duration, error) {
	switch p {
	case Standard:
		return Lifetime, nil
	case Operations:
		return OperationsLifetime, nil
	default:
		return 0, errors.New("unknown credential policy")
	}
}

var (
	ErrAuthorization = errors.New("credential authorization is not active or does not match")
	ErrLifetime      = errors.New("insufficient time for certificate signing")
	ErrRequest       = errors.New("invalid credential request")
	ErrCertificate   = errors.New("invalid client certificate")
)

// Request is safe to persist: it contains only a public CSR and metadata. The
// deadline is absolute, so delayed signing and retries cannot extend access.
type Request struct {
	ID            string    `json:"id"`
	Policy        Policy    `json:"credential_policy"`
	GrantID       string    `json:"grant_id"`
	MemberID      string    `json:"member_id"`
	ClusterID     string    `json:"cluster_id"`
	PermissionRef string    `json:"permission_ref"`
	Subject       string    `json:"subject"`
	CSR           []byte    `json:"csr"`
	Fingerprint   string    `json:"public_key_sha256"`
	CreatedAt     time.Time `json:"created_at"`
	NotAfter      time.Time `json:"not_after"`
}

// Pending belongs to one download attempt. It must remain in memory and must
// not be logged. Encoding it as JSON deliberately produces no private material.
type Pending struct {
	request Request
	key     *ecdsa.PrivateKey
	policy  Policy
}

// Subject scopes the identity to a cluster and a single grant, independent of
// mutable FreeIPA usernames. Regranting under a new ID cannot reactivate old keys.
func Subject(g grant.Grant) string {
	h := sha256.Sum256([]byte(g.ClusterID + "\x00" + g.ID))
	return "kubegrant:" + hex.EncodeToString(h[:24])
}

func (policy Policy) New(g grant.Grant, member string, now time.Time) (*Pending, error) {
	lifetime, err := policy.lifetime()
	if err != nil {
		return nil, err
	}
	if member == "" || member != g.MemberID || !g.ActiveAt(now) {
		return nil, ErrAuthorization
	}
	deadline := now.Add(lifetime)
	if g.ExpiresAt.Before(deadline) {
		deadline = g.ExpiresAt
	}
	deadline = deadline.UTC().Truncate(time.Second)
	if deadline.Sub(now) < MinimumTTL {
		return nil, ErrLifetime
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate credential key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: Subject(g)}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("generate public CSR: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(spki)
	return &Pending{key: key, policy: policy, request: Request{
		ID: rand.Text(), Policy: policy, GrantID: g.ID, MemberID: member, ClusterID: g.ClusterID,
		PermissionRef: g.PermissionRef, Subject: Subject(g), Fingerprint: hex.EncodeToString(h[:]),
		CSR:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		CreatedAt: now.UTC(), NotAfter: deadline,
	}}, nil
}

func (p *Pending) PublicRequest() Request {
	r := p.request
	r.CSR = bytes.Clone(r.CSR)
	return r
}

// ValidateRequest must also run in the controller immediately before approval.
// It accepts exactly the identity, key algorithm and attributes we generate.
func (policy Policy) ValidateRequest(r Request, g grant.Grant, now time.Time) (*x509.CertificateRequest, error) {
	lifetime, err := policy.lifetime()
	if err != nil || r.Policy != policy {
		return nil, ErrRequest
	}
	if !g.ActiveAt(now) || r.GrantID != g.ID || r.MemberID != g.MemberID ||
		r.ClusterID != g.ClusterID || r.PermissionRef != g.PermissionRef {
		return nil, ErrAuthorization
	}
	if r.ID == "" || r.Subject != Subject(g) || r.CreatedAt.Before(g.CreatedAt) ||
		r.CreatedAt.After(now) || !r.NotAfter.After(now) || r.NotAfter.After(g.ExpiresAt) ||
		r.NotAfter.After(r.CreatedAt.Add(lifetime)) || r.NotAfter.Sub(r.CreatedAt) < MinimumTTL {
		return nil, ErrRequest
	}
	blocks, err := decodePEM(r.CSR, "CERTIFICATE REQUEST")
	if err != nil || len(blocks) != 1 {
		return nil, ErrRequest
	}
	csr, err := x509.ParseCertificateRequest(blocks[0])
	if err != nil || csr.CheckSignature() != nil || !validSubject(csr.Subject, r.Subject) ||
		len(csr.Extensions) != 0 || len(csr.Attributes) != 0 || csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, ErrRequest
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrRequest
	}
	h := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(h[:]) != r.Fingerprint {
		return nil, ErrRequest
	}
	return csr, nil
}

// ExpirationSeconds is recalculated just before creating a Kubernetes CSR.
// The absolute NotAfter is still checked on the resulting certificate, since
// signing can occur later than CSR creation.
func (policy Policy) ExpirationSeconds(r Request, now time.Time) (int32, error) {
	lifetime, err := policy.lifetime()
	remaining := r.NotAfter.Sub(now)
	if err != nil || r.Policy != policy || r.CreatedAt.After(now) || r.NotAfter.After(r.CreatedAt.Add(lifetime)) || remaining < MinimumTTL || remaining > lifetime {
		return 0, ErrLifetime
	}
	return int32(remaining / time.Second), nil
}

type Download struct {
	Data      []byte    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Kubeconfig only prepares the attachment after checking the current grant and
// member again. The HTTP layer must additionally recheck the live session and
// the controller's observed binding state before writing the response.
func (p *Pending) Kubeconfig(g grant.Grant, member, endpoint string, certificate, ca []byte, now time.Time) (Download, error) {
	if member != p.request.MemberID {
		return Download{}, ErrAuthorization
	}
	csr, err := p.policy.ValidateRequest(p.request, g, now)
	if err != nil {
		return Download{}, err
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return Download{}, errors.New("cluster endpoint must be a direct HTTPS origin")
	}
	leaf, err := validateCertificate(p.request, csr, certificate, ca, now)
	if err != nil {
		return Download{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		return Download{}, err
	}
	defer clear(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	// JSON is valid kubeconfig input. []byte fields are base64 encoded by the
	// standard encoder, without a YAML string interpolation or path injection.
	contextName := "kubegrant"
	value := map[string]any{
		"apiVersion": "v1", "kind": "Config", "current-context": contextName,
		"clusters": []any{map[string]any{"name": p.request.ClusterID, "cluster": map[string]any{
			"server": endpoint, "certificate-authority-data": ca,
		}}},
		"users": []any{map[string]any{"name": p.request.Subject, "user": map[string]any{
			"client-certificate-data": certificate, "client-key-data": keyPEM,
		}}},
		"contexts": []any{map[string]any{"name": contextName, "context": map[string]any{
			"cluster": p.request.ClusterID, "user": p.request.Subject,
		}}},
	}
	data, err := json.Marshal(value)
	return Download{Data: data, ExpiresAt: leaf.NotAfter.UTC()}, err
}

func validSubject(name pkix.Name, subject string) bool {
	return name.CommonName == subject && len(name.Names) == 1 && name.Names[0].Type.Equal([]int{2, 5, 4, 3})
}

func decodePEM(data []byte, kind string) ([][]byte, error) {
	if len(data) == 0 || len(data) > maxPEMBytes {
		return nil, errors.New("invalid PEM size")
	}
	var blocks [][]byte
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN "+kind+"-----")) {
			return nil, errors.New("unexpected PEM content")
		}
		b, rest := pem.Decode(data)
		if b == nil || b.Type != kind || len(b.Headers) != 0 {
			return nil, errors.New("invalid PEM block")
		}
		blocks = append(blocks, b.Bytes)
		data = rest
	}
	return blocks, nil
}

func validateCertificate(r Request, csr *x509.CertificateRequest, data, ca []byte, now time.Time) (*x509.Certificate, error) {
	blocks, err := decodePEM(data, "CERTIFICATE")
	if err != nil || len(blocks) == 0 {
		return nil, ErrCertificate
	}
	certs := make([]*x509.Certificate, 0, len(blocks))
	for _, b := range blocks {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, ErrCertificate
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal([]int{2, 5, 29, 17}) {
			return nil, ErrCertificate
		}
	}
	if leaf.IsCA || !validSubject(leaf.Subject, r.Subject) || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) ||
		leaf.NotAfter.After(r.NotAfter) || !leaf.NotAfter.After(now) ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 {
		return nil, ErrCertificate
	}
	caBlocks, err := decodePEM(ca, "CERTIFICATE")
	if err != nil || len(caBlocks) == 0 {
		return nil, ErrCertificate
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, b := range caBlocks {
		cert, err := x509.ParseCertificate(b)
		if err != nil || !cert.IsCA {
			return nil, ErrCertificate
		}
		roots.AddCert(cert)
	}
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil, ErrCertificate
	}
	return leaf, nil
}
