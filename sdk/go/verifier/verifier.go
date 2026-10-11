// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Package verifier is target verifier middleware for PantherClaw action
// tokens (PAP/1 §10, HR-202). A service PantherClaw reaches through a
// target-enforced connection wraps its handlers with it: a request runs
// only when its PAP-Action token was minted by PantherClaw for exactly this
// request (this connection, this body, this operation and target), is
// unexpired, and was never used before, by this replica or any other that
// shares the replay store. Everything else is refused before the handler
// runs, so a request that did not pass PantherClaw has no effect.
package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

// TypeActionToken is the JOSE typ of an action token.
const TypeActionToken = "pap-action+jwt" //nolint:gosec // G101: a JOSE type name, not a credential

// Limits of verification (PAP/1 §10).
const (
	// MaxLifetime is the longest an action token may live.
	MaxLifetime = 60 * time.Second
	// Skew tolerates clock differences with PantherClaw.
	Skew = 5 * time.Second
	// DefaultMaxBody caps the request body the middleware reads.
	DefaultMaxBody = 1 << 20
	jwksMaxAge     = 15 * time.Minute
	jwksMinGap     = time.Minute
	maxToken       = 8 << 10
)

// Code names why a request was refused.
type Code string

// Refusal codes (G0 M8 design decision 3).
const (
	Missing           Code = "missing"
	BadSignature      Code = "bad_signature"
	WrongIssuer       Code = "wrong_issuer"
	WrongAudience     Code = "wrong_audience"
	Expired           Code = "expired"
	BodyMismatch      Code = "body_mismatch"
	OperationMismatch Code = "operation_mismatch"
	Replayed          Code = "replayed"
	StoreUnavailable  Code = "store_unavailable"
)

// RefusalError is a verification failure. Every refusal means the request must
// not run.
type RefusalError struct {
	Code   Code
	detail string
}

func (r *RefusalError) Error() string {
	return "action token refused: " + string(r.Code) + ": " + r.detail
}

// Status is the HTTP status the middleware answers: 409 for a replay, 503
// when the keys or the replay store cannot be reached, 401 otherwise.
func (r *RefusalError) Status() int {
	//exhaustive:ignore // every other code is 401
	switch r.Code {
	case Replayed:
		return http.StatusConflict
	case StoreUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusUnauthorized
	}
}

func refusal(c Code, format string, a ...any) error {
	return &RefusalError{Code: c, detail: fmt.Sprintf(format, a...)}
}

// CodeOf returns the refusal code of err, "" for nil.
func CodeOf(err error) Code {
	var r *RefusalError
	if errors.As(err, &r) {
		return r.Code
	}
	if err != nil {
		return StoreUnavailable
	}
	return ""
}

// Claims are a verified action token's claims.
type Claims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	ID       string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	PAP      struct {
		V      int    `json:"v"`
		Txn    string `json:"txn"`
		Act    string `json:"act"`
		BH     string `json:"bh"`
		Op     string `json:"op"`
		Target struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"target"`
	} `json:"pap"`
}

// Config configures a Verifier.
type Config struct {
	// JWKSURL is PantherClaw's /.well-known/pantherclaw/jwks.json: https,
	// or http only to a loopback address.
	JWKSURL string
	// Issuer is the deployment's issuer (the iss of its tokens).
	Issuer string
	// Audience is the connection id this target is registered as.
	Audience string
	// Store spends each token id once. Every replica of the target must
	// share it (SQLStore); a MemoryStore is for a single replica.
	Store ReplayStore
	// Client fetches the JWKS; nil uses one with a 5-second timeout.
	// Redirects are never followed, whichever client fetches.
	Client *http.Client
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Verifier verifies action tokens. It is safe for concurrent use.
type Verifier struct {
	cfg Config

	mu      sync.Mutex
	keys    map[string]ed25519.PublicKey
	fetched time.Time
	tried   time.Time
	// flight is closed when the JWKS fetch in progress ends; fetchErr is
	// the last fetch's error.
	flight   chan struct{}
	fetchErr error
}

// New returns a verifier.
func New(cfg Config) (*Verifier, error) {
	switch {
	case cfg.JWKSURL == "" || cfg.Issuer == "" || cfg.Audience == "":
		return nil, errors.New("verifier: the JWKS URL, the issuer and the audience are required")
	case cfg.Store == nil:
		return nil, errors.New("verifier: a replay store is required")
	case !secureURL(cfg.JWKSURL):
		return nil, errors.New("verifier: the JWKS URL must use https (http only on a loopback address)")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	if cfg.Client != nil {
		copied := *cfg.Client
		client = &copied
	}
	// A redirect could hand the keys to anyone on the way (HR-202).
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.Client = client
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg}, nil
}

// SingleReplica reports whether the verifier's replay store serves one
// replica only. Such a verifier cannot back an enforced claim for a target
// with more than one replica (HR-024).
func (v *Verifier) SingleReplica() bool { return !v.cfg.Store.Shared() }

// Verify checks the action token of a request whose exact body is body and
// spends it. match must report whether the token's operation and target
// are what the request does. The checks run in the order of PAP/1 §10; the
// token id is spent only after all of them passed.
func (v *Verifier) Verify(ctx context.Context, token string, body []byte, match func(Claims) bool) (Claims, error) {
	var c Claims
	if token == "" {
		return c, refusal(Missing, "no PAP-Action header")
	}
	payload, err := v.verifySignature(ctx, token)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, refusal(BadSignature, "claims: %v", err)
	}
	now := v.cfg.Now()
	sum := sha256.Sum256(body)
	iat, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.Expiry, 0)
	switch {
	case c.Issuer != v.cfg.Issuer:
		return c, refusal(WrongIssuer, "%q", c.Issuer)
	case c.Audience != v.cfg.Audience:
		return c, refusal(WrongAudience, "%q", c.Audience)
	case !exp.After(iat) || exp.Sub(iat) > MaxLifetime || !now.Before(exp.Add(Skew)) || iat.After(now.Add(Skew)):
		return c, refusal(Expired, "iat %d exp %d", c.IssuedAt, c.Expiry)
	case c.PAP.V != pap.Version || c.ID == "" || len(c.ID) > 128:
		return c, refusal(BadSignature, "not a version 1 action token")
	case c.PAP.BH != hex.EncodeToString(sum[:]):
		return c, refusal(BodyMismatch, "the body is not the one the token binds")
	case match == nil || !match(c):
		return c, refusal(OperationMismatch, "%s on %s %s", c.PAP.Op, c.PAP.Target.Type, c.PAP.Target.ID)
	}
	first, err := v.cfg.Store.Use(ctx, Spend{Audience: c.Audience, ID: c.ID, IssuedAt: iat, Now: now, Until: exp.Add(Skew)})
	switch {
	case err != nil:
		return c, refusal(StoreUnavailable, "%v", err)
	case !first:
		return c, refusal(Replayed, "token %s", c.ID)
	}
	return c, nil
}

// header is the only protected header accepted: keys never come from the
// token (no jwk, jku, x5u, x5c), and nothing is critical.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

func (v *Verifier) verifySignature(ctx context.Context, token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(token) > maxToken || len(parts) != 3 {
		return nil, refusal(BadSignature, "malformed")
	}
	enc := base64.RawURLEncoding.Strict()
	raw, err1 := enc.DecodeString(parts[0])
	payload, err2 := enc.DecodeString(parts[1])
	sig, err3 := enc.DecodeString(parts[2])
	var h header
	if err := errors.Join(err1, err2, err3); err != nil || json.Unmarshal(raw, &h, json.RejectUnknownMembers(true)) != nil {
		return nil, refusal(BadSignature, "malformed")
	}
	if (h.Alg != "EdDSA" && h.Alg != "Ed25519") || h.Typ != TypeActionToken || h.Kid == "" {
		return nil, refusal(BadSignature, "header alg %q typ %q", h.Alg, h.Typ)
	}
	key, err := v.key(ctx, h.Kid)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, refusal(BadSignature, "signature")
	}
	return payload, nil
}

// key returns the action-tokens key kid. The JWKS is cached at most 15
// minutes and refetched at most once a minute for a kid it does not hold.
// One fetch runs at a time, outside the lock: verifications that need it
// wait for it, and the others go on with the cached keys.
func (v *Verifier) key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	v.mu.Lock()
	now := v.cfg.Now()
	stale := v.keys == nil || now.Sub(v.fetched) >= jwksMaxAge
	// A verification that needs the keys waits for a fetch in flight, even
	// one started within the minute (a burst after a key rotation).
	if (stale || v.keys[kid] == nil) && (v.tried.IsZero() || now.Sub(v.tried) >= jwksMinGap || stale || v.flight != nil) {
		flight := v.flight
		if flight == nil {
			v.tried, v.flight = now, make(chan struct{})
			flight = v.flight
			v.mu.Unlock()
			// The fetch outlives a caller that gives up: others wait on it.
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jwksFetchTimeout)
			keys, err := v.fetch(fctx)
			cancel()
			v.mu.Lock()
			switch {
			case err == nil:
				v.keys, v.fetched = keys, now
			case stale:
				v.keys = nil
			}
			v.fetchErr, v.flight = err, nil
			close(flight)
		} else {
			v.mu.Unlock()
			select {
			case <-flight:
			case <-ctx.Done():
				return nil, refusal(StoreUnavailable, "JWKS: %v", ctx.Err())
			}
			v.mu.Lock()
		}
	}
	defer v.mu.Unlock()
	if v.keys == nil || v.cfg.Now().Sub(v.fetched) >= jwksMaxAge {
		return nil, refusal(StoreUnavailable, "JWKS: %v", v.fetchErr)
	}
	if k := v.keys[kid]; k != nil {
		return k, nil
	}
	return nil, refusal(BadSignature, "unknown key %q", kid)
}

// jwksFetchTimeout bounds one JWKS fetch.
const jwksFetchTimeout = 10 * time.Second

// secureURL reports whether a URL is https, or http to a loopback address,
// without user information.
func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback()))
}

// ActionTokenKID is the kid of an action-tokens key: "action-tokens-" and
// the first 22 characters of its RFC 7638 thumbprint. Only keys whose kid
// has this form verify, so no other PantherClaw key can mint a token the
// target accepts.
func ActionTokenKID(pub ed25519.PublicKey) string {
	return "action-tokens-" + pap.Thumbprint(pub)[:22]
}

func (v *Verifier) fetch(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := v.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.UnmarshalRead(io.LimitReader(res.Body, 64<<10), &set); err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		x, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
		if err != nil || k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Alg != "" && k.Alg != "EdDSA" && k.Alg != "Ed25519") || len(x) != ed25519.PublicKeySize {
			continue
		}
		if pub := ed25519.PublicKey(x); k.Kid == ActionTokenKID(pub) {
			keys[k.Kid] = pub
		}
	}
	return keys, nil
}

type claimsKey struct{}

// FromContext returns the verified claims of the request a handler serves.
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(Claims)
	return c, ok
}

// Middleware refuses, before next runs, every request without a valid,
// unused action token for exactly that request. match reports whether the
// token's operation and target are what the request does. The body is
// read in full (at most maxBody bytes, DefaultMaxBody when 0; 413 beyond)
// and handed on unchanged, with the claims in the context.
func (v *Verifier) Middleware(match func(*http.Request, Claims) bool, maxBody int64, next http.Handler) http.Handler {
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || int64(len(body)) > maxBody {
			problem(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		c, err := v.Verify(r.Context(), r.Header.Get(pap.HeaderAction), body, func(c Claims) bool { return match(r, c) })
		if err != nil {
			var ref *RefusalError
			if !errors.As(err, &ref) {
				ref = &RefusalError{Code: StoreUnavailable}
			}
			problem(w, ref.Status(), string(ref.Code))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, c)))
	})
}

// problem writes an RFC 9457 problem document naming the refusal code.
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "{\"type\":\"urn:pantherclaw:action-token:%s\",\"title\":\"action token refused\",\"status\":%d,\"code\":%q}\n", code, status, code)
}
