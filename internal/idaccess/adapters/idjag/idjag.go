// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package idjag verifies Identity Assertion JWT Authorization Grants (ID-JAG)
// as draft-ietf-oauth-identity-assertion-authz-grant-06 defines them (G0 M26
// D400, D408; HR-622). It is the adapter behind ports.AssertionVerifier, so
// a later draft revision changes this package only.
//
// What it checks (draft -06 §3, §4.4.1, §9.11; HR-145 lifetimes):
//
//   - the JWS typ is oauth-id-jag+jwt, and no header carries a key or a
//     critical extension, so keys never come from the assertion;
//   - the algorithm is one the issuer entry allows (RS256, ES256, EdDSA), and
//     the signature verifies with the issuer's published key named by kid,
//     read over HTTPS through the egress guard from the jwks_uri of its
//     RFC 8414 or OpenID discovery document, whose issuer must match;
//   - iss is the entry's issuer; aud is exactly the entry's audience, as a
//     string or a one-element array; client_id, sub and jti are present;
//     exp and iat are present, iat at most AssertionMaxAge old, the lifetime
//     at most AssertionMaxLife, nbf (when present) passed;
//   - resource is present (a string or an array of strings);
//   - a multi-tenant entry's tenant equals the tenant claim, and aud_tenant,
//     when present, names this organization;
//   - cnf and authorization_details are refused: this server supports no
//     proof-of-possession method and no rich authorization requests.
//
// Replay (jti single use), the client binding and the grant are the use
// case's.
package idjag

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// Draft is the specification revision this adapter implements.
const Draft = "draft-ietf-oauth-identity-assertion-authz-grant-06"

// Typ is the JWS typ of an ID-JAG (draft -06 §3).
const Typ = "oauth-id-jag+jwt"

// Limits of what is read from an issuer.
const (
	maxDocument = 256 << 10
	// KeysTTL is how long an issuer's keys are used before they are read
	// again; an unknown kid reads them again at most once per refetchGap.
	KeysTTL    = 10 * time.Minute
	refetchGap = 30 * time.Second
	maxClaim   = 512
	maxValues  = 16
)

// algorithms this adapter can verify, by JWS name.
var algorithms = map[string]jose.SignatureAlgorithm{"RS256": jose.RS256, "ES256": jose.ES256, "EdDSA": jose.EdDSA}

// Verifier implements ports.AssertionVerifier and ports.Discovery.
type Verifier struct {
	// Client reads issuer documents. Nil is the egress client, which refuses
	// private and loopback addresses at dial time (HR-071).
	Client *http.Client
	// CheckURL checks every issuer and jwks_uri URL before it is read; nil
	// is oidcrp.CheckOrgURL (HTTPS on a public host, HR-483).
	CheckURL func(string) error

	once sync.Once
	mu   sync.Mutex
	keys map[string]*keySet
}

type keySet struct {
	set     jose.JSONWebKeySet
	fetched time.Time
}

func (v *Verifier) init() {
	v.once.Do(func() {
		if v.Client == nil {
			v.Client = httpx.NewEgressClient(httpx.EgressConfig{Timeout: 10 * time.Second})
		}
		if v.CheckURL == nil {
			v.CheckURL = oidcrp.CheckOrgURL
		}
		v.keys = map[string]*keySet{}
	})
}

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", domain.ErrAssertion, fmt.Sprintf(format, a...))
}

// Check reads an issuer's discovery document and keys, so a person files
// only an issuer that can be used. It says only whether it worked (HR-483).
func (v *Verifier) Check(ctx context.Context, issuerURL string) error {
	v.init()
	if _, err := v.fetchKeys(ctx, issuerURL); err != nil {
		return refuse("discovery")
	}
	return nil
}

// header is a JWS protected header. Members that carry or point to a key,
// or demand an extension, are refused.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

var forbiddenHeaders = []string{"jwk", "jku", "x5u", "x5c", "crit", "b64", "zip"}

func parseHeader(raw string) (header, error) {
	var h header
	i := strings.IndexByte(raw, '.')
	if i < 0 || strings.Count(raw, ".") != 2 || strings.ContainsAny(raw, " \t\r\n") {
		return h, refuse("not a compact JWS")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw[:i])
	if err != nil {
		return h, refuse("header encoding")
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(b, &members); err != nil {
		return h, refuse("header")
	}
	for _, m := range forbiddenHeaders {
		if _, ok := members[m]; ok {
			return h, refuse("header member %q", m)
		}
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return h, refuse("header")
	}
	typ := strings.ToLower(h.Typ)
	if typ != Typ && typ != "application/"+Typ {
		return h, refuse("typ %q", h.Typ)
	}
	if h.Kid == "" || len(h.Kid) > 256 {
		return h, refuse("kid")
	}
	return h, nil
}

// claims of an ID-JAG. Unknown claims are ignored; the checked ones must
// have exactly these types.
type claims struct {
	Iss          string         `json:"iss"`
	Sub          string         `json:"sub"`
	Aud          jsontext.Value `json:"aud"`
	ClientID     string         `json:"client_id"`
	JTI          string         `json:"jti"`
	Exp          *float64       `json:"exp"`
	Iat          *float64       `json:"iat"`
	Nbf          *float64       `json:"nbf"`
	Resource     jsontext.Value `json:"resource"`
	Scope        *string        `json:"scope"`
	Tenant       *string        `json:"tenant"`
	AudTenant    *string        `json:"aud_tenant"`
	Cnf          jsontext.Value `json:"cnf"`
	AuthzDetails jsontext.Value `json:"authorization_details"`
}

// strings1 reads a string or an array of strings.
func strings1(v jsontext.Value) ([]string, bool) {
	if len(v) == 0 {
		return nil, false
	}
	var one string
	if err := json.Unmarshal(v, &one); err == nil {
		return []string{one}, true
	}
	var many []string
	if err := json.Unmarshal(v, &many); err != nil || len(many) == 0 {
		return nil, false
	}
	return many, true
}

func unix(f *float64) (time.Time, bool) {
	if f == nil || math.IsNaN(*f) || math.IsInf(*f, 0) || *f < 0 || *f > 1<<40 {
		return time.Time{}, false
	}
	return time.Unix(int64(*f), 0), true
}

// Verify implements ports.AssertionVerifier.
func (v *Verifier) Verify(ctx context.Context, raw string, iss domain.Issuer, now time.Time) (domain.Assertion, error) {
	v.init()
	if len(raw) > domain.MaxAssertionBytes {
		return domain.Assertion{}, refuse("too large")
	}
	h, err := parseHeader(raw)
	if err != nil {
		return domain.Assertion{}, err
	}
	alg, ok := algorithms[h.Alg]
	if !ok || !slices.Contains(iss.Algorithms, h.Alg) {
		return domain.Assertion{}, refuse("algorithm %q", h.Alg)
	}
	key, err := v.key(ctx, iss.URL, h.Kid, h.Alg, now)
	if err != nil {
		return domain.Assertion{}, err
	}
	obj, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{alg})
	if err != nil || len(obj.Signatures) != 1 {
		return domain.Assertion{}, refuse("signature format")
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return domain.Assertion{}, refuse("signature")
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return domain.Assertion{}, refuse("claims")
	}
	return check(c, iss, now)
}

// check applies every claim rule to a verified assertion.
func check(c claims, iss domain.Issuer, now time.Time) (domain.Assertion, error) {
	aud, okAud := strings1(c.Aud)
	res, okRes := strings1(c.Resource)
	exp, okExp := unix(c.Exp)
	iat, okIat := unix(c.Iat)
	nbf, okNbf := unix(c.Nbf)
	skew := domain.AssertionSkew
	switch {
	case c.Iss != iss.URL:
		return domain.Assertion{}, refuse("iss")
	case !okAud || len(aud) != 1 || aud[0] != iss.Audience:
		return domain.Assertion{}, refuse("aud")
	case c.ClientID == "" || len(c.ClientID) > maxClaim:
		return domain.Assertion{}, refuse("client_id")
	case c.Sub == "" || len(c.Sub) > 255:
		return domain.Assertion{}, refuse("sub")
	case c.JTI == "" || len(c.JTI) > maxClaim:
		return domain.Assertion{}, refuse("jti")
	case !okExp || !okIat || (c.Nbf != nil && !okNbf):
		return domain.Assertion{}, refuse("exp and iat are required")
	case !now.Before(exp):
		return domain.Assertion{}, refuse("expired")
	case iat.After(now.Add(skew)) || now.Sub(iat) > domain.AssertionMaxAge+skew:
		return domain.Assertion{}, refuse("iat")
	case exp.Sub(iat) > domain.AssertionMaxLife:
		return domain.Assertion{}, refuse("lifetime")
	case okNbf && nbf.After(now.Add(skew)):
		return domain.Assertion{}, refuse("not yet valid")
	case !okRes || len(res) > maxValues || slices.ContainsFunc(res, func(r string) bool { return r == "" || len(r) > maxClaim }):
		return domain.Assertion{}, refuse("resource")
	case len(c.Cnf) > 0:
		return domain.Assertion{}, refuse("cnf is not supported") // -06 §9.11: invalid_grant
	case len(c.AuthzDetails) > 0:
		return domain.Assertion{}, refuse("authorization_details is not supported")
	case iss.Tenant != "" && (c.Tenant == nil || *c.Tenant != iss.Tenant):
		return domain.Assertion{}, refuse("tenant")
	case c.AudTenant != nil && *c.AudTenant != iss.AudTenant:
		return domain.Assertion{}, refuse("aud_tenant")
	}
	out := domain.Assertion{
		Issuer: c.Iss, Subject: c.Sub, ClientID: c.ClientID, JTI: c.JTI, Resources: res, IssuedAt: iat, ExpiresAt: exp,
	}
	if c.Scope != nil {
		out.Scope, out.HasScope = *c.Scope, true
	}
	return out, nil
}

// key returns the issuer's verification key kid for alg, reading the keys
// again when they are stale or kid is unknown (at most once per refetchGap).
func (v *Verifier) key(ctx context.Context, issuer, kid, alg string, now time.Time) (any, error) {
	v.mu.Lock()
	ks := v.keys[issuer]
	v.mu.Unlock()
	if ks == nil || now.Sub(ks.fetched) > KeysTTL || (len(ks.set.Key(kid)) == 0 && now.Sub(ks.fetched) > refetchGap) {
		set, err := v.fetchKeys(ctx, issuer)
		if err != nil {
			return nil, refuse("issuer keys unavailable")
		}
		ks = &keySet{set: set, fetched: now}
		v.mu.Lock()
		v.keys[issuer] = ks
		v.mu.Unlock()
	}
	found := ks.set.Key(kid)
	if len(found) != 1 {
		return nil, refuse("kid")
	}
	k := found[0]
	if !k.Valid() || !k.IsPublic() || (k.Use != "" && k.Use != "sig") || (k.Algorithm != "" && k.Algorithm != alg) {
		return nil, refuse("key")
	}
	switch kk := k.Key.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" || kk.N.BitLen() < 2048 {
			return nil, refuse("key type")
		}
	case *ecdsa.PublicKey:
		if alg != "ES256" || kk.Curve.Params().Name != "P-256" {
			return nil, refuse("key type")
		}
	case ed25519.PublicKey:
		if alg != "EdDSA" {
			return nil, refuse("key type")
		}
	default:
		return nil, refuse("key type")
	}
	return k.Key, nil
}

// metadataURLs are where an issuer's metadata may be: RFC 8414 §3.1 (with
// the well-known segment inserted before the issuer's path) and OpenID
// Connect Discovery 1.0 §4.
func metadataURLs(issuer string) []string {
	scheme, rest, _ := strings.Cut(issuer, "://")
	host, path, _ := strings.Cut(rest, "/")
	if path != "" {
		path = "/" + strings.TrimSuffix(path, "/")
	}
	return []string{
		scheme + "://" + host + "/.well-known/oauth-authorization-server" + path,
		strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration",
	}
}

func (v *Verifier) fetchKeys(ctx context.Context, issuer string) (jose.JSONWebKeySet, error) {
	if err := v.CheckURL(issuer); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	var jwksURI string
	var errs []error
	for _, u := range metadataURLs(issuer) {
		var meta struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := v.get(ctx, u, &meta); err != nil {
			errs = append(errs, err)
			continue
		}
		if meta.Issuer != issuer {
			return jose.JSONWebKeySet{}, errors.New("idjag: metadata issuer does not match")
		}
		jwksURI = meta.JWKSURI
		break
	}
	if jwksURI == "" {
		return jose.JSONWebKeySet{}, fmt.Errorf("idjag: no metadata: %w", errors.Join(errs...))
	}
	if err := v.CheckURL(jwksURI); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	var set jose.JSONWebKeySet
	if err := v.get(ctx, jwksURI, &set); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	return set, nil
}

func (v *Verifier) get(ctx context.Context, u string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("idjag: %s: status %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDocument+1))
	if err != nil {
		return err
	}
	if len(b) > maxDocument {
		return errors.New("idjag: document too large")
	}
	return json.Unmarshal(b, out)
}
