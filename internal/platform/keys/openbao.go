// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// OpenBao Transit (D157, G7). The client is in-house over net/http: it
// calls encrypt, decrypt and rewrap on one Transit key, authenticated by a
// token file or AppRole. It talks only to the configured address, with TLS
// unless that address is loopback, and never follows redirects or proxies
// (HR-488).

// ErrKeyServiceUnavailable reports a Transit call that did not complete;
// the caller fails closed (HR-486).
var ErrKeyServiceUnavailable = errors.New("keys: key service unavailable")

// Auth kinds.
const (
	AuthToken   = "token"
	AuthAppRole = "approle"
)

// OpenBaoAuth authenticates the Transit client. Secrets are files (SB-7).
type OpenBaoAuth struct {
	// Kind is "token" or "approle".
	Kind string `json:"kind"`
	// TokenFile holds a token (kind token).
	TokenFile string `json:"token_file"`
	// RoleID and SecretIDFile are the AppRole credentials (kind approle).
	RoleID       string `json:"role_id"`
	SecretIDFile string `json:"secret_id_file"`
	// Mount is the AppRole auth mount; default "approle".
	Mount string `json:"mount"`
}

// OpenBaoConfig is the openbao part of the key_service config.
type OpenBaoConfig struct {
	// Address is the OpenBao base URL: https, or http on loopback only.
	Address string `json:"address" env:"PC_OPENBAO_ADDR"`
	// Mount is the Transit secrets engine mount; default "transit".
	Mount string `json:"mount" env:"PC_OPENBAO_MOUNT"`
	// KeyName is the Transit key that wraps PantherClaw keys.
	KeyName string      `json:"key_name" env:"PC_OPENBAO_KEY_NAME"`
	Auth    OpenBaoAuth `json:"auth"`
	// CAFile is an optional PEM bundle that verifies the server's
	// certificate instead of the system roots.
	CAFile string `json:"ca_file"`
	// TimeoutSeconds bounds each call; default 10.
	TimeoutSeconds int `json:"timeout_seconds"`
}

var transitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,58}$`)

// maxTransitResponse bounds a Transit response body.
const maxTransitResponse = 1 << 20

// Validate checks the configuration without reading files.
func (c OpenBaoConfig) Validate() []error {
	var errs []error
	if _, err := baoBaseURL(c.Address); err != nil {
		errs = append(errs, err)
	}
	if c.Mount != "" && !transitName.MatchString(c.Mount) {
		errs = append(errs, errors.New("key_service.openbao.mount is not a valid mount name"))
	}
	if !transitName.MatchString(c.KeyName) {
		errs = append(errs, errors.New("key_service.openbao.key_name is required (letters, digits, _ . -; at most 59)"))
	}
	switch c.Auth.Kind {
	case AuthToken:
		if c.Auth.TokenFile == "" {
			errs = append(errs, errors.New("key_service.openbao.auth.token_file is required"))
		}
	case AuthAppRole:
		if c.Auth.RoleID == "" || c.Auth.SecretIDFile == "" {
			errs = append(errs, errors.New("key_service.openbao.auth needs role_id and secret_id_file"))
		}
		if c.Auth.Mount != "" && !transitName.MatchString(c.Auth.Mount) {
			errs = append(errs, errors.New("key_service.openbao.auth.mount is not a valid mount name"))
		}
	default:
		errs = append(errs, errors.New(`key_service.openbao.auth.kind must be "token" or "approle"`))
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 120 {
		errs = append(errs, errors.New("key_service.openbao.timeout_seconds must be 0..120"))
	}
	return errs
}

// baoBaseURL parses the address. Plain http is accepted only for a
// loopback host (HR-488).
func baoBaseURL(addr string) (*url.URL, error) {
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil, errors.New("key_service.openbao.address must be a base URL such as https://bao.example:8200")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(u.Hostname()) {
			return nil, errors.New("key_service.openbao.address must use https unless it is loopback")
		}
	default:
		return nil, errors.New("key_service.openbao.address must use https unless it is loopback")
	}
	u.Path = ""
	return u, nil
}

// loopbackHost accepts only a literal loopback IP (127.0.0.0/8, ::1). A
// name such as localhost is resolved by DNS or a hosts file, so it needs
// TLS like any other host.
func loopbackHost(h string) bool {
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// TransitClient calls one OpenBao Transit key.
type TransitClient struct {
	base    *url.URL
	mount   string
	key     string
	auth    OpenBaoAuth
	http    *http.Client
	timeout time.Duration

	mu      sync.Mutex
	token   pclog.Secret[string]
	expires time.Time // zero: no expiry known (token file)
	// login shares one token read or AppRole login among concurrent
	// callers; c.mu is never held across it.
	login singleflight.Group
}

// NewTransitClient builds a client. It reads no secret until the first call.
func NewTransitClient(c OpenBaoConfig) (*TransitClient, error) {
	if errs := c.Validate(); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	base, _ := baoBaseURL(c.Address)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile) //nolint:gosec // G304: operator-configured CA bundle
		if err != nil {
			return nil, fmt.Errorf("keys: openbao ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("keys: openbao ca_file holds no PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	mount := c.Mount
	if mount == "" {
		mount = "transit"
	}
	auth := c.Auth
	if auth.Kind == AuthAppRole && auth.Mount == "" {
		auth.Mount = "approle"
	}
	return &TransitClient{
		base: base, mount: mount, key: c.KeyName, auth: auth, timeout: timeout,
		http: &http.Client{
			// Only the configured address: no proxy, no redirect (HR-488).
			Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true, MaxIdleConns: 8},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("keys: openbao redirects are refused")
			},
		},
	}, nil
}

// Encrypt returns the Transit ciphertext ("vault:vN:…") of plaintext.
func (c *TransitClient) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	in := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	if err := c.call(ctx, "encrypt", in, &out); err != nil {
		return "", err
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:v") {
		return "", fmt.Errorf("%w: malformed encrypt response", ErrKeyServiceUnavailable)
	}
	return out.Data.Ciphertext, nil
}

// Decrypt returns the plaintext of a Transit ciphertext.
func (c *TransitClient) Decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := c.call(ctx, "decrypt", map[string]string{"ciphertext": ciphertext}, &out); err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed decrypt response", ErrKeyServiceUnavailable)
	}
	return pt, nil
}

// Rewrap re-encrypts a ciphertext under the key's latest version without
// returning the plaintext.
func (c *TransitClient) Rewrap(ctx context.Context, ciphertext string) (string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := c.call(ctx, "rewrap", map[string]string{"ciphertext": ciphertext}, &out); err != nil {
		return "", err
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:v") {
		return "", fmt.Errorf("%w: malformed rewrap response", ErrKeyServiceUnavailable)
	}
	return out.Data.Ciphertext, nil
}

// errStatus is a non-2xx Transit response.
type errStatus struct{ code int }

func (e errStatus) Error() string { return fmt.Sprintf("openbao returned HTTP %d", e.code) }

// call posts to {mount}/{op}/{key}, logging in again once when the token
// was refused.
func (c *TransitClient) call(ctx context.Context, op string, in, out any) error {
	path := "/v1/" + c.mount + "/" + op + "/" + c.key
	for attempt := 0; ; attempt++ {
		tok, err := c.currentToken(ctx)
		if err != nil {
			return err
		}
		err = c.post(ctx, path, tok, in, out)
		var st errStatus
		if attempt == 0 && errors.As(err, &st) && st.code == http.StatusForbidden {
			c.dropToken()
			continue
		}
		return err
	}
}

func (c *TransitClient) post(ctx context.Context, path, token string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	u := *c.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeyServiceUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTransitResponse))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeyServiceUnavailable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body may echo request data; it is never logged or returned.
		return fmt.Errorf("%w: %w", ErrKeyServiceUnavailable, errStatus{resp.StatusCode})
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: malformed response", ErrKeyServiceUnavailable)
	}
	return nil
}

func (c *TransitClient) dropToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = pclog.Secret[string]{}
	c.expires = time.Time{}
}

// currentToken returns the cached token, reading the token file or logging
// in with AppRole when there is none or it is about to expire.
func (c *TransitClient) currentToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if t := c.token.Reveal(); t != "" && (c.expires.IsZero() || time.Until(c.expires) > 30*time.Second) {
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()
	// One login for every concurrent caller, detached from the first
	// caller's cancellation; post still bounds it by the call timeout.
	v, err, _ := c.login.Do("token", func() (any, error) {
		tok, expires, err := c.fetchToken(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.token, c.expires = tok, expires
		c.mu.Unlock()
		return tok, nil
	})
	if err != nil {
		return "", err
	}
	return v.(pclog.Secret[string]).Reveal(), nil //nolint:forcetypeassert // the only value Do returns
}

// fetchToken reads the token file or logs in with AppRole.
func (c *TransitClient) fetchToken(ctx context.Context) (pclog.Secret[string], time.Time, error) {
	var none pclog.Secret[string]
	switch c.auth.Kind {
	case AuthToken:
		s, err := config.ReadSecretFile(c.auth.TokenFile)
		if err != nil {
			return none, time.Time{}, fmt.Errorf("keys: openbao token_file: %w", err)
		}
		return pclog.NewSecret(string(bytes.TrimSpace(s.Reveal()))), time.Time{}, nil
	case AuthAppRole:
		s, err := config.ReadSecretFile(c.auth.SecretIDFile)
		if err != nil {
			return none, time.Time{}, fmt.Errorf("keys: openbao secret_id_file: %w", err)
		}
		var out struct {
			Auth struct {
				ClientToken   string `json:"client_token"`
				LeaseDuration int    `json:"lease_duration"`
			} `json:"auth"`
		}
		in := map[string]string{"role_id": c.auth.RoleID, "secret_id": string(bytes.TrimSpace(s.Reveal()))}
		if err := c.post(ctx, "/v1/auth/"+c.auth.Mount+"/login", "", in, &out); err != nil {
			return none, time.Time{}, err
		}
		if out.Auth.ClientToken == "" {
			return none, time.Time{}, fmt.Errorf("%w: AppRole login returned no token", ErrKeyServiceUnavailable)
		}
		var expires time.Time
		if out.Auth.LeaseDuration > 0 {
			expires = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second)
		}
		return pclog.NewSecret(out.Auth.ClientToken), expires, nil
	}
	return none, time.Time{}, fmt.Errorf("keys: unknown openbao auth kind %q", c.auth.Kind)
}

// OpenBaoProvider is a KeyProvider over one Transit key. Its wrapped values
// use the common envelope (version ‖ len(kid) ‖ kid ‖ Transit ciphertext)
// with kid "bao:<key_name>", so a Router can route them. The associated
// data is bound inside the encrypted plaintext as its SHA-256, so a value
// moved to another row does not unwrap.
type OpenBaoProvider struct {
	c   *TransitClient
	kid string
}

var _ KeyProvider = (*OpenBaoProvider)(nil)

// NewOpenBaoProvider returns a provider over c.
func NewOpenBaoProvider(c *TransitClient) *OpenBaoProvider {
	return &OpenBaoProvider{c: c, kid: PrefixOpenBao + c.key}
}

// CurrentKEK implements KeyProvider.
func (p *OpenBaoProvider) CurrentKEK() string { return p.kid }

func (p *OpenBaoProvider) aadDigest(aad []byte) ([]byte, error) {
	full, err := wrapAAD(p.kid, aad)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(full)
	return sum[:], nil
}

// Wrap implements KeyProvider.
func (p *OpenBaoProvider) Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	digest, err := p.aadDigest(aad)
	if err != nil {
		return nil, err
	}
	in := append(digest, plaintext...)
	defer clear(in)
	ct, err := p.c.Encrypt(ctx, in)
	if err != nil {
		return nil, err
	}
	out := []byte{wrapV1, byte(len(p.kid))} //nolint:gosec // G115: kid ≤ 63 bytes (transitName)
	out = append(out, p.kid...)
	return append(out, ct...), nil
}

// Unwrap implements KeyProvider. Every failure, an outage included, is
// ErrUnwrap: there is no fallback (HR-486).
func (p *OpenBaoProvider) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) < 2 || wrapped[0] != wrapV1 || len(wrapped) < 2+int(wrapped[1]) ||
		string(wrapped[2:2+int(wrapped[1])]) != p.kid {
		return nil, ErrUnwrap
	}
	digest, err := p.aadDigest(aad)
	if err != nil {
		return nil, err
	}
	pt, err := p.c.Decrypt(ctx, string(wrapped[2+len(p.kid):]))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnwrap, err)
	}
	if len(pt) < len(digest) || subtle.ConstantTimeCompare(pt[:len(digest)], digest) != 1 {
		clear(pt)
		return nil, ErrUnwrap
	}
	out := append([]byte(nil), pt[len(digest):]...)
	clear(pt)
	return out, nil
}
