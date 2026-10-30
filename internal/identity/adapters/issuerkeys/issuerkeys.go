// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package issuerkeys verifies attestation token signatures with an issuer's
// published keys (HR-142, ADR-0018). Keys come from one source per preset:
// the issuer's discovery document (JWKS on the issuer's own host), a JWKS
// URL the preset pins, or a static JWKS from operator configuration. Fetched
// keys travel over TLS through the egress-guarded client only (no
// redirects, no proxy variables, no private addresses unless the operator
// allows them); documents are size-capped; at most 20 RSA (at least 2048
// bits) or EC (P-256, P-384) keys are kept, for at most 15 minutes; and an
// unknown kid triggers at most one refetch per minute. An unreachable
// issuer fails closed. Algorithms, key uses and header members come from
// the preset, never from the token.
package issuerkeys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Limits (HR-142).
const (
	MaxDocument  = 64 << 10
	MaxKeys      = 20
	CacheFor     = 15 * time.Minute
	MissInterval = time.Minute
	MaxToken     = 16 << 10
)

// Algorithms a preset may allow. Symmetric algorithms and none never are.
var supported = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"}

// ErrUnverified is returned for every token that does not verify; the
// detail is for logs only.
var ErrUnverified = errors.New("issuerkeys: token not verified")

// Config is one issuer's key source and the preset's token rules. Exactly
// one source is used: StaticJWKS, else JWKSURL, else discovery on Issuer.
type Config struct {
	// Issuer is the https issuer URL whose discovery document names the
	// JWKS (on the same host). It is also the label in errors.
	Issuer string
	// JWKSURL pins the key document (https) instead of discovery.
	JWKSURL string
	// StaticJWKS is an operator-supplied key set; nothing is fetched.
	StaticJWKS []byte
	// Algorithms the preset accepts; default RS256.
	Algorithms []string
	// Uses are the accepted JWK "use" values; default sig. A key without
	// "use" is accepted only where sig is.
	Uses []string
	// Header lists the token header members allowed; default alg, kid,
	// typ and x5t. Keys never come from the token (no jwk, jku, x5u, x5c).
	Header []string
	// Types, when set, are the accepted typ values (typ may be absent).
	Types []string
}

type jwk struct {
	key crypto.PublicKey
	alg string // the JWK's alg, when it names one
}

// Fetcher caches one issuer's signing keys.
type Fetcher struct {
	client *http.Client
	cfg    Config
	static bool
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]jwk
	fetchedAt time.Time
	lastMiss  time.Time
}

// New returns a discovery fetcher for issuer (https only) that accepts
// RS256 only, using client, which must be an egress client
// (httpx.NewEgressClient).
func New(client *http.Client, issuer string, now func() time.Time) (*Fetcher, error) {
	return NewFetcher(client, Config{Issuer: issuer}, now)
}

// NewFetcher returns a fetcher for cfg. client must be an egress client; it
// is unused for a static key set.
func NewFetcher(client *http.Client, cfg Config, now func() time.Time) (*Fetcher, error) {
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"RS256"}
	}
	for _, a := range cfg.Algorithms {
		if !slices.Contains(supported, a) {
			return nil, fmt.Errorf("issuerkeys: algorithm %q is not supported", a)
		}
	}
	if len(cfg.Uses) == 0 {
		cfg.Uses = []string{"sig"}
	}
	if len(cfg.Header) == 0 {
		cfg.Header = []string{"alg", "kid", "typ", "x5t"}
	}
	if now == nil {
		now = time.Now
	}
	f := &Fetcher{client: client, cfg: cfg, now: now}
	switch {
	case len(cfg.StaticJWKS) > 0:
		keys, err := f.parse(cfg.StaticJWKS)
		if err != nil {
			return nil, err
		}
		f.keys, f.static = keys, true
	case cfg.JWKSURL != "":
		if !httpsURL(cfg.JWKSURL) {
			return nil, fmt.Errorf("issuerkeys: JWKS URL %q must be an https URL", cfg.JWKSURL)
		}
	default:
		u, err := url.Parse(cfg.Issuer)
		if err != nil || !httpsURL(cfg.Issuer) || u.RawQuery != "" {
			return nil, fmt.Errorf("issuerkeys: issuer %q must be an https URL", cfg.Issuer)
		}
		f.cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	}
	return f, nil
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

// Verify checks compact's signature with the issuer's key named by its kid
// and returns the payload. Claims are checked by the preset.
func (f *Fetcher) Verify(ctx context.Context, compact string) ([]byte, error) {
	if len(compact) > MaxToken {
		return nil, fmt.Errorf("%w: size", ErrUnverified)
	}
	alg, err := f.checkHeader(compact)
	if err != nil {
		return nil, err
	}
	algs := make([]jose.SignatureAlgorithm, len(f.cfg.Algorithms))
	for i, a := range f.cfg.Algorithms {
		algs[i] = jose.SignatureAlgorithm(a)
	}
	obj, err := jose.ParseSigned(compact, algs)
	if err != nil || len(obj.Signatures) != 1 {
		return nil, fmt.Errorf("%w: parse", ErrUnverified)
	}
	h := obj.Signatures[0].Protected
	if h.KeyID == "" {
		return nil, fmt.Errorf("%w: header", ErrUnverified)
	}
	k, err := f.key(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	if !fits(k, alg) {
		return nil, fmt.Errorf("%w: key does not fit %s", ErrUnverified, alg)
	}
	payload, err := obj.Verify(k.key)
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrUnverified)
	}
	return payload, nil
}

// fits reports whether k may verify alg: the JWK's own alg, when it names
// one, must be alg, and the key type and curve must match it.
func fits(k jwk, alg string) bool {
	if k.alg != "" && k.alg != alg {
		return false
	}
	switch pub := k.key.(type) {
	case *rsa.PublicKey:
		return alg[0] == 'R' || alg[0] == 'P'
	case *ecdsa.PublicKey:
		return (alg == "ES256" && pub.Curve == elliptic.P256()) || (alg == "ES384" && pub.Curve == elliptic.P384())
	}
	return false
}

// checkHeader accepts only the members the preset allows, and returns the
// algorithm, which must be one the preset accepts. Nothing is critical.
func (f *Fetcher) checkHeader(compact string) (string, error) {
	seg, _, ok := strings.Cut(compact, ".")
	if !ok {
		return "", fmt.Errorf("%w: malformed", ErrUnverified)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return "", fmt.Errorf("%w: header encoding", ErrUnverified)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", fmt.Errorf("%w: header", ErrUnverified)
	}
	for k := range h {
		if !slices.Contains(f.cfg.Header, k) {
			return "", fmt.Errorf("%w: header member %q", ErrUnverified, k)
		}
	}
	alg, _ := h["alg"].(string)
	if !slices.Contains(f.cfg.Algorithms, alg) {
		return "", fmt.Errorf("%w: algorithm", ErrUnverified)
	}
	if typ, present := h["typ"]; present && len(f.cfg.Types) > 0 {
		if s, _ := typ.(string); !slices.Contains(f.cfg.Types, s) {
			return "", fmt.Errorf("%w: typ", ErrUnverified)
		}
	}
	return alg, nil
}

// key returns the key for kid, refreshing a stale cache, or the cache on a
// miss at most once per MissInterval. A static key set never refreshes.
func (f *Fetcher) key(ctx context.Context, kid string) (jwk, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.static {
		if k, ok := f.keys[kid]; ok {
			return k, nil
		}
		return jwk{}, fmt.Errorf("%w: unknown kid", ErrUnverified)
	}
	now := f.now()
	stale := f.keys == nil || now.Sub(f.fetchedAt) >= CacheFor
	k, ok := f.keys[kid]
	if !stale && ok {
		return k, nil
	}
	if !stale && !ok {
		if now.Sub(f.lastMiss) < MissInterval {
			return jwk{}, fmt.Errorf("%w: unknown kid", ErrUnverified)
		}
		f.lastMiss = now
	}
	keys, err := f.fetch(ctx)
	if err != nil {
		if stale {
			f.keys = nil // an issuer that cannot be reached fails closed once the cache expired
		}
		return jwk{}, err
	}
	f.keys, f.fetchedAt = keys, now
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return jwk{}, fmt.Errorf("%w: unknown kid", ErrUnverified)
}

func (f *Fetcher) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issuerkeys: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuerkeys: fetch %s: status %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil || len(b) > MaxDocument {
		return nil, fmt.Errorf("issuerkeys: fetch %s: document too large or unreadable", u)
	}
	return b, nil
}

func (f *Fetcher) fetch(ctx context.Context) (map[string]jwk, error) {
	jwksURI := f.cfg.JWKSURL
	if jwksURI == "" {
		raw, err := f.get(ctx, f.cfg.Issuer+"/.well-known/openid-configuration")
		if err != nil {
			return nil, err
		}
		var disc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(raw, &disc); err != nil {
			return nil, fmt.Errorf("issuerkeys: discovery: %w", err)
		}
		ju, err := url.Parse(disc.JWKSURI)
		iu, _ := url.Parse(f.cfg.Issuer)
		if disc.Issuer != f.cfg.Issuer || err != nil || ju.Scheme != "https" || !strings.EqualFold(ju.Host, iu.Host) {
			return nil, errors.New("issuerkeys: discovery must name this issuer and a JWKS URI on its own https host")
		}
		jwksURI = disc.JWKSURI
	}
	raw, err := f.get(ctx, jwksURI)
	if err != nil {
		return nil, err
	}
	return f.parse(raw)
}

// parse keeps the usable keys of a JWKS: RSA of at least 2048 bits or EC
// on P-256/P-384, with a kid, a use the preset accepts, and an alg (when
// named) the preset accepts. Other members of the set (a SPIFFE bundle's
// spiffe_sequence, say) are ignored.
func (f *Fetcher) parse(raw []byte) (map[string]jwk, error) {
	if len(raw) > MaxDocument {
		return nil, errors.New("issuerkeys: jwks too large")
	}
	var set struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("issuerkeys: jwks: %w", err)
	}
	out := map[string]jwk{}
	for _, v := range set.Keys {
		if len(out) == MaxKeys {
			break
		}
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(v); err != nil || k.KeyID == "" || !k.IsPublic() || !f.usable(k.Use) ||
			(k.Algorithm != "" && !slices.Contains(f.cfg.Algorithms, k.Algorithm)) {
			continue
		}
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			if pub.N.BitLen() < 2048 {
				continue
			}
		case *ecdsa.PublicKey:
			if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
				continue
			}
		default:
			continue
		}
		out[k.KeyID] = jwk{key: k.Key, alg: k.Algorithm}
	}
	if len(out) == 0 {
		return nil, errors.New("issuerkeys: no usable keys")
	}
	return out, nil
}

func (f *Fetcher) usable(use string) bool {
	if use == "" {
		return slices.Contains(f.cfg.Uses, "sig")
	}
	return slices.Contains(f.cfg.Uses, use)
}
