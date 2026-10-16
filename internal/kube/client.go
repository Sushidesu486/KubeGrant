// Package kube implements only the API surface owned by KubeGrant. It uses a
// rotating projected token, verified TLS, bounded requests and UID preconditions.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Metadata struct {
	Name              string            `json:"name"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	CreationTimestamp *time.Time        `json:"creationTimestamp,omitempty"`
}
type Subject struct {
	Kind      string `json:"kind"`
	APIGroup  string `json:"apiGroup"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}
type RoleRef struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}
type Binding struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Metadata   Metadata  `json:"metadata"`
	RoleRef    RoleRef   `json:"roleRef"`
	Subjects   []Subject `json:"subjects"`
}
type CSRSpec struct {
	Request           []byte              `json:"request"`
	SignerName        string              `json:"signerName"`
	ExpirationSeconds int32               `json:"expirationSeconds"`
	Usages            []string            `json:"usages"`
	Username          string              `json:"username,omitempty"`
	UID               string              `json:"uid,omitempty"`
	Groups            []string            `json:"groups,omitempty"`
	Extra             map[string][]string `json:"extra,omitempty"`
}
type Condition struct {
	Type               string     `json:"type"`
	Status             string     `json:"status"`
	Reason             string     `json:"reason"`
	Message            string     `json:"message,omitempty"`
	LastUpdateTime     *time.Time `json:"lastUpdateTime,omitempty"`
	LastTransitionTime *time.Time `json:"lastTransitionTime,omitempty"`
}
type CSR struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       CSRSpec  `json:"spec"`
	Status     struct {
		Certificate []byte      `json:"certificate,omitempty"`
		Conditions  []Condition `json:"conditions,omitempty"`
	} `json:"status,omitempty"`
}

const bindingPath = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
const csrPath = "/apis/certificates.k8s.io/v1/certificatesigningrequests"

func (c *Client) CheckRole(ctx context.Context, name string) error {
	var role struct {
		Metadata Metadata `json:"metadata"`
	}
	if err := c.request(ctx, "GET", "/apis/rbac.authorization.k8s.io/v1/clusterroles/"+url.PathEscape(name), nil, &role); err != nil {
		return err
	}
	if role.Metadata.Name != name {
		return errors.New("configured Kubernetes role not found")
	}
	return nil
}

type APIError struct{ Status int }

func (e *APIError) Error() string { return fmt.Sprintf("Kubernetes API returned HTTP %d", e.Status) }
func IsStatus(err error, status int) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == status
}

type Client struct {
	server, tokenFile string
	http              *http.Client
}

func New(server, caFile, tokenFile string) (*Client, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("Kubernetes API endpoint must be an HTTPS origin")
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("cannot read Kubernetes API CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid Kubernetes API CA")
	}
	if tokenFile == "" {
		return nil, errors.New("projected token path is required")
	}
	return &Client{server: strings.TrimSuffix(server, "/"), tokenFile: tokenFile, http: &http.Client{
		Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second},
	}}, nil
}

func (c *Client) request(ctx context.Context, method, path string, value, out any) error {
	var data []byte
	var err error
	if value != nil {
		data, err = json.Marshal(value)
		if err != nil {
			return err
		}
	}
	token, err := os.ReadFile(c.tokenFile)
	if err != nil || len(token) == 0 || len(token) > 64<<10 {
		return errors.New("projected Kubernetes token unavailable")
	}
	r, err := http.NewRequestWithContext(ctx, method, c.server+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	r.Header.Set("Accept", "application/json")
	if value != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(r)
	if err != nil {
		return errors.New("Kubernetes API unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{response.StatusCode}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out)
}

func (c *Client) GetBinding(ctx context.Context, name string) (Binding, error) {
	var b Binding
	err := c.request(ctx, "GET", bindingPath+"/"+url.PathEscape(name), nil, &b)
	return b, err
}
func (c *Client) CreateBinding(ctx context.Context, b Binding) (Binding, error) {
	var out Binding
	err := c.request(ctx, "POST", bindingPath, b, &out)
	return out, err
}
func deleteOptions(uid string) any {
	return map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]string{"uid": uid}}
}
func (c *Client) DeleteBinding(ctx context.Context, name, uid string) error {
	if uid == "" {
		return errors.New("binding deletion requires a UID")
	}
	return c.request(ctx, "DELETE", bindingPath+"/"+url.PathEscape(name), deleteOptions(uid), nil)
}
func (c *Client) ListBindings(ctx context.Context, selector string) ([]Binding, error) {
	return listObjects[Binding](ctx, c, bindingPath, selector)
}
func (c *Client) GetCSR(ctx context.Context, name string) (CSR, error) {
	var out CSR
	err := c.request(ctx, "GET", csrPath+"/"+url.PathEscape(name), nil, &out)
	return out, err
}
func (c *Client) CreateCSR(ctx context.Context, csr CSR) (CSR, error) {
	var out CSR
	err := c.request(ctx, "POST", csrPath, csr, &out)
	return out, err
}
func (c *Client) ApproveCSR(ctx context.Context, csr CSR, at time.Time) (CSR, error) {
	csr.Status.Conditions = append(csr.Status.Conditions, Condition{Type: "Approved", Status: "True", Reason: "KubeGrantAuthorized", Message: "Validated managed grant and public request", LastUpdateTime: &at})
	var out CSR
	err := c.request(ctx, "PUT", csrPath+"/"+url.PathEscape(csr.Metadata.Name)+"/approval", csr, &out)
	return out, err
}
func (c *Client) DeleteCSR(ctx context.Context, name, uid string) error {
	if uid == "" {
		return errors.New("CSR deletion requires a UID")
	}
	return c.request(ctx, "DELETE", csrPath+"/"+url.PathEscape(name), deleteOptions(uid), nil)
}
func (c *Client) ListCSRs(ctx context.Context, selector string) ([]CSR, error) {
	return listObjects[CSR](ctx, c, csrPath, selector)
}

func listObjects[T any](ctx context.Context, c *Client, path, selector string) ([]T, error) {
	result := []T{}
	next := ""
	for {
		q := url.Values{"labelSelector": {selector}, "limit": {"200"}}
		if next != "" {
			q.Set("continue", next)
		}
		var page struct {
			Items    []T `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := c.request(ctx, "GET", path+"?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		result = append(result, page.Items...)
		if page.Metadata.Continue == "" {
			return result, nil
		}
		if next == page.Metadata.Continue {
			return nil, errors.New("Kubernetes pagination did not advance")
		}
		next = page.Metadata.Continue
	}
}
