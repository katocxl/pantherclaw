// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuerkeys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The spiffe_x509 preset (G0 M35 D1030, HR-778). Its evidence is a compact
// JWS signed by an X.509-SVID's key: the header carries the SVID chain in
// x5c (leaf first) and the payload is the L3 binding string. The chain is
// verified against the X.509 authorities ("use": "x509-svid") of the trust
// domain's bundle, from the same operator-configured source as the
// JWT-SVID keys (identity.spiffe_trust_domains), never from a tenant. The
// x509-svid keys are accepted for this preset only.

// maxX509Chain bounds the certificates in x5c.
const maxX509Chain = 4

// x509Header are the JWS header members the preset accepts.
var x509Header = []string{"alg", "x5c", "typ"}

// X509Directory is the X.509 bundles of the configured SPIFFE trust
// domains, keyed by name.
type X509Directory struct {
	entries map[string]*x509Bundle
	now     func() time.Time
}

type x509Bundle struct {
	client *http.Client
	url    string
	orgs   []string
	static bool

	mu        sync.Mutex
	roots     []*x509.Certificate
	fetchedAt time.Time
	lastMiss  time.Time
}

// NewSPIFFEX509Directory returns the X.509 bundles of the configured trust
// domains. A bundle file is read once, here; a bundle URL is fetched over
// the egress client and cached at most CacheFor (HR-142).
func NewSPIFFEX509Directory(cfgs []TrustDomain, timeout time.Duration) (*X509Directory, error) {
	if err := ValidateSPIFFE(cfgs); err != nil {
		return nil, err
	}
	d := &X509Directory{entries: map[string]*x509Bundle{}, now: time.Now}
	for _, td := range cfgs {
		b := &x509Bundle{orgs: td.Orgs}
		if td.BundleFile != "" {
			raw, err := os.ReadFile(td.BundleFile)
			if err != nil {
				return nil, fmt.Errorf("spiffe trust domain %q: %w", td.TrustDomain, err)
			}
			// A static bundle without X.509 authorities only refuses
			// spiffe_x509 attestations; its JWT-SVID keys still serve.
			b.roots, _ = parseX509Bundle(raw)
			b.static = true
		} else {
			ec, err := td.client(timeout)
			if err != nil {
				return nil, fmt.Errorf("spiffe trust domain %q: %w", td.TrustDomain, err)
			}
			b.client, b.url = httpx.NewEgressClient(*ec), td.BundleURL
		}
		d.entries[td.TrustDomain] = b
	}
	return d, nil
}

// Allowed reports whether org may bind entries to trust domain td.
func (d *X509Directory) Allowed(td string, org ids.OrgID) bool {
	if d == nil {
		return false
	}
	b, ok := d.entries[td]
	return ok && (len(b.orgs) == 0 || slices.Contains(b.orgs, org.String()))
}

// Verify checks an X.509-SVID signed binding for org: the leaf's trust
// domain must be configured for org, the chain must verify against that
// trust domain's X.509 authorities at the current time, the leaf must be
// an X.509-SVID (one spiffe URI SAN, not a CA, digitalSignature), and its
// key must have signed the payload with an algorithm that fits it. The
// payload is the preset's to check.
func (d *X509Directory) Verify(ctx context.Context, org ids.OrgID, token string) (issuers.X509SVID, error) {
	if len(token) > MaxToken {
		return issuers.X509SVID{}, fmt.Errorf("%w: size", ErrUnverified)
	}
	alg, chain, err := x509TokenHeader(token)
	if err != nil {
		return issuers.X509SVID{}, err
	}
	leaf := chain[0]
	id, err := svidID(leaf)
	if err != nil {
		return issuers.X509SVID{}, err
	}
	td, ok := issuers.ParseSPIFFEID(id)
	if !ok || !d.Allowed(td, org) {
		return issuers.X509SVID{}, fmt.Errorf("%w: trust domain %q is not configured for this organization", ErrUnverified, td)
	}
	b := d.entries[td]
	now := d.now()
	verify := func(roots []*x509.Certificate) error {
		if len(roots) == 0 {
			return errors.New("no X.509 authorities")
		}
		opts := x509.VerifyOptions{
			Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool(), CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		for _, r := range roots {
			opts.Roots.AddCert(r)
		}
		for _, c := range chain[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := leaf.Verify(opts)
		return err
	}
	roots, fresh, err := b.authorities(ctx, now, false)
	if err != nil {
		return issuers.X509SVID{}, err
	}
	if err := verify(roots); err != nil {
		// A rotated authority: refetch at most once per MissInterval.
		if fresh || b.static {
			return issuers.X509SVID{}, fmt.Errorf("%w: chain: %w", ErrUnverified, err)
		}
		if roots, _, err = b.authorities(ctx, now, true); err != nil {
			return issuers.X509SVID{}, err
		}
		if err := verify(roots); err != nil {
			return issuers.X509SVID{}, fmt.Errorf("%w: chain: %w", ErrUnverified, err)
		}
	}
	if !x509Fits(leaf.PublicKey, alg) {
		return issuers.X509SVID{}, fmt.Errorf("%w: key does not fit %s", ErrUnverified, alg)
	}
	obj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
	if err != nil || len(obj.Signatures) != 1 {
		return issuers.X509SVID{}, fmt.Errorf("%w: parse", ErrUnverified)
	}
	payload, err := obj.Verify(leaf.PublicKey)
	if err != nil {
		return issuers.X509SVID{}, fmt.Errorf("%w: signature", ErrUnverified)
	}
	return issuers.X509SVID{TrustDomain: td, SPIFFEID: id, Payload: payload, NotAfter: leaf.NotAfter}, nil
}

// x509TokenHeader returns the algorithm and the x5c chain of a compact JWS,
// accepting only the preset's header members and algorithms.
func x509TokenHeader(token string) (string, []*x509.Certificate, error) {
	seg, _, ok := strings.Cut(token, ".")
	if !ok {
		return "", nil, fmt.Errorf("%w: malformed", ErrUnverified)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return "", nil, fmt.Errorf("%w: header encoding", ErrUnverified)
	}
	var h map[string]jsontext.Value
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", nil, fmt.Errorf("%w: header", ErrUnverified)
	}
	for k := range h {
		if !slices.Contains(x509Header, k) {
			return "", nil, fmt.Errorf("%w: header member %q", ErrUnverified, k)
		}
	}
	var alg string
	var x5c []string
	if json.Unmarshal(h["alg"], &alg) != nil || !slices.Contains(issuers.SPIFFEX509Algorithms, alg) {
		return "", nil, fmt.Errorf("%w: algorithm", ErrUnverified)
	}
	if json.Unmarshal(h["x5c"], &x5c) != nil || len(x5c) == 0 || len(x5c) > maxX509Chain {
		return "", nil, fmt.Errorf("%w: x5c", ErrUnverified)
	}
	chain := make([]*x509.Certificate, 0, len(x5c))
	for _, c := range x5c {
		der, err := base64.StdEncoding.Strict().DecodeString(c)
		if err != nil {
			return "", nil, fmt.Errorf("%w: x5c encoding", ErrUnverified)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return "", nil, fmt.Errorf("%w: x5c certificate", ErrUnverified)
		}
		chain = append(chain, cert)
	}
	return alg, chain, nil
}

// svidID returns the SPIFFE ID of an X.509-SVID leaf: exactly one URI SAN,
// a spiffe ID, not a CA, usable for digital signatures and never for
// signing certificates (SPIFFE X509-SVID §4).
func svidID(leaf *x509.Certificate) (string, error) {
	switch {
	case len(leaf.URIs) != 1:
		return "", fmt.Errorf("%w: an X.509-SVID has exactly one URI SAN", ErrUnverified)
	case leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 || leaf.KeyUsage&x509.KeyUsageCRLSign != 0:
		return "", fmt.Errorf("%w: the leaf is a CA", ErrUnverified)
	case leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0:
		return "", fmt.Errorf("%w: the leaf may not sign", ErrUnverified)
	}
	id := leaf.URIs[0].String()
	if _, ok := issuers.ParseSPIFFEID(id); !ok {
		return "", fmt.Errorf("%w: the URI SAN is not a SPIFFE ID", ErrUnverified)
	}
	return id, nil
}

// x509Fits reports whether a leaf key may sign with alg: ECDSA P-256 or
// P-384 with the matching ES algorithm, RSA of at least 2048 bits with an
// RS or PS algorithm, or Ed25519 with EdDSA.
func x509Fits(pub any, alg string) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return (alg == "ES256" && k.Curve == elliptic.P256()) || (alg == "ES384" && k.Curve == elliptic.P384())
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048 && (strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"))
	case ed25519.PublicKey:
		return alg == "EdDSA"
	}
	return false
}

// authorities returns the bundle's X.509 authorities and whether they were
// fetched by this call: a stale cache is refetched, and with force a fresh
// one too, at most once per MissInterval. A bundle that can't be fetched
// once the cache expired fails closed.
func (b *x509Bundle) authorities(ctx context.Context, now time.Time, force bool) ([]*x509.Certificate, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.static {
		return b.roots, false, nil
	}
	stale := b.roots == nil || now.Sub(b.fetchedAt) >= CacheFor
	if !stale && !force {
		return b.roots, false, nil
	}
	if !stale {
		if now.Sub(b.lastMiss) < MissInterval {
			return b.roots, false, nil
		}
		b.lastMiss = now
	}
	roots, err := b.fetch(ctx)
	if err != nil {
		if stale {
			b.roots = nil
		}
		return nil, false, err
	}
	b.roots, b.fetchedAt = roots, now
	return roots, true, nil
}

func (b *x509Bundle) fetch(ctx context.Context) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issuerkeys: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuerkeys: fetch %s: status %d", b.url, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil || len(raw) > MaxDocument {
		return nil, fmt.Errorf("issuerkeys: fetch %s: document too large or unreadable", b.url)
	}
	return parseX509Bundle(raw)
}

// parseX509Bundle keeps the X.509 authorities of a SPIFFE bundle: the
// x5c certificate of each key whose use is x509-svid (at most MaxKeys).
// The JWT-SVID keys are the JWT preset's.
func parseX509Bundle(raw []byte) ([]*x509.Certificate, error) {
	if len(raw) > MaxDocument {
		return nil, errors.New("issuerkeys: bundle too large")
	}
	var set struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("issuerkeys: bundle: %w", err)
	}
	var out []*x509.Certificate
	for _, v := range set.Keys {
		if len(out) == MaxKeys {
			break
		}
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(v); err != nil || k.Use != "x509-svid" || len(k.Certificates) != 1 || !k.IsPublic() {
			continue
		}
		out = append(out, k.Certificates[0])
	}
	if len(out) == 0 {
		return nil, errors.New("issuerkeys: the bundle holds no X.509 authorities")
	}
	return out, nil
}
