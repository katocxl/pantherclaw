// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package setverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Key fetching limits (the issuerkeys package's, HR-142, kept for
// transmitters by D39).
const (
	MaxDocument  = 64 << 10
	MaxKeys      = 20
	CacheFor     = 15 * time.Minute
	MissInterval = time.Minute
	MinRSABits   = 2048
)

// ErrJWKSURI reports a JWKS URI that is not https on the issuer's host.
var ErrJWKSURI = errors.New("setverify: the JWKS URI must be an https URL on the issuer's own host")

// CheckJWKSURI checks that jwksURI is https, without credentials, query or
// fragment, on the issuer's host (D37).
func CheckJWKSURI(issuer, jwksURI string) error {
	iu, err := url.Parse(issuer)
	if err != nil || iu.Scheme != "https" || iu.Host == "" || iu.User != nil || iu.Fragment != "" {
		return ErrJWKSURI
	}
	ju, err := url.Parse(jwksURI)
	if err != nil || ju.Scheme != "https" || ju.User != nil || ju.Fragment != "" || ju.RawQuery != "" ||
		!strings.EqualFold(ju.Host, iu.Host) || len(jwksURI) > 2048 {
		return ErrJWKSURI
	}
	return nil
}

// JWKS caches the signing keys of one transmitter, read from its pinned
// JWKS URI through an egress client: never from a token. Keys are kept for
// CacheFor; an unknown kid refetches at most once per MissInterval; once
// the cache has expired an unreachable JWKS fails closed.
type JWKS struct {
	client *http.Client
	uri    string
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]any
	fetchedAt time.Time
	lastMiss  time.Time
	lastFail  time.Time
}

// NewJWKS returns the key cache of a transmitter. client must be an egress
// client (httpx.NewEgressClient).
func NewJWKS(client *http.Client, issuer, jwksURI string, now func() time.Time) (*JWKS, error) {
	if err := CheckJWKSURI(issuer, jwksURI); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &JWKS{client: client, uri: jwksURI, now: now}, nil
}

// errUnknownKid reports a kid the JWKS does not have.
var errUnknownKid = errors.New("setverify: unknown kid")

// Key returns the public key for kid (*rsa.PublicKey or *ecdsa.PublicKey).
func (j *JWKS) Key(ctx context.Context, kid string) (any, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	stale := j.keys == nil || now.Sub(j.fetchedAt) >= CacheFor
	k, ok := j.keys[kid]
	if !stale && ok {
		return k, nil
	}
	if !stale && !ok {
		if now.Sub(j.lastMiss) < MissInterval {
			return nil, errUnknownKid
		}
		j.lastMiss = now
	}
	// A failed fetch is not retried within MissInterval either: a down
	// issuer never turns pushes into a stream of fetches (D64 L7).
	if !j.lastFail.IsZero() && now.Sub(j.lastFail) < MissInterval {
		if stale {
			j.keys = nil
		}
		return nil, errors.New("setverify: the key set is unavailable")
	}
	keys, err := j.fetch(ctx)
	if err != nil {
		j.lastFail = now
		if stale {
			j.keys = nil
		}
		return nil, err
	}
	j.keys, j.fetchedAt, j.lastFail = keys, now, time.Time{}
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errUnknownKid
}

func (j *JWKS) fetch(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("setverify: fetch keys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("setverify: fetch keys: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil || len(raw) > MaxDocument {
		return nil, errors.New("setverify: key set too large or unreadable")
	}
	return parseKeys(raw)
}

// parseKeys keeps at most MaxKeys signing keys: RSA of at least 2048 bits
// for RS256 and P-256 EC keys for ES256, each with a kid; private keys and
// keys meant for other uses or algorithms are skipped.
func parseKeys(raw []byte) (map[string]any, error) {
	var set struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("setverify: key set: %w", err)
	}
	out := map[string]any{}
	for _, kr := range set.Keys {
		if len(out) == MaxKeys {
			break
		}
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(kr); err != nil || k.KeyID == "" || !k.IsPublic() || (k.Use != "" && k.Use != "sig") {
			continue
		}
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			if (k.Algorithm == "" || k.Algorithm == string(jose.RS256)) && pub.N.BitLen() >= MinRSABits {
				out[k.KeyID] = pub
			}
		case *ecdsa.PublicKey:
			if (k.Algorithm == "" || k.Algorithm == string(jose.ES256)) && pub.Curve == elliptic.P256() {
				out[k.KeyID] = pub
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("setverify: no usable keys")
	}
	return out, nil
}
