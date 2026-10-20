// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pep

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSource returns the bearer access token the enforcement point
// presents to the decision endpoint.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// ClientCredentials gets access tokens for the enforcement point's service
// account from PantherClaw's OAuth token endpoint with the client
// credentials grant, authenticated by a private_key_jwt client assertion
// (RFC 7523) signed with the account's registered key. Tokens are reused
// until a minute before they expire.
type ClientCredentials struct {
	// TokenURL is the token endpoint, the server's public URL followed by
	// /oauth2/token.
	TokenURL string
	// ClientID is the service account's client id.
	ClientID string
	// Key is the account's private key: an ed25519.PrivateKey (EdDSA) or a
	// P-256 *ecdsa.PrivateKey (ES256).
	Key crypto.Signer
	// HTTPClient sends the request; nil is a client with a 10 second
	// timeout that ignores proxy settings. It never follows redirects.
	HTTPClient *http.Client
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	hc      *http.Client // built once
	token   string
	expires time.Time
}

// ErrToken reports that no access token could be obtained.
var ErrToken = errors.New("pep: no access token")

// Token returns a current access token.
func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && now().Before(c.expires.Add(-time.Minute)) {
		return c.token, nil
	}
	// Whatever happens next, the old token is not used again (D113).
	c.token, c.expires = "", time.Time{}
	if u, err := url.Parse(c.TokenURL); err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !loopback(u))) {
		return "", fmt.Errorf("%w: TokenURL must be https unless it is a loopback address", ErrToken)
	}
	assertion, err := c.assertion(now())
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {c.ClientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode())) //nolint:gosec // G704: the operator configures the token endpoint
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.hc == nil {
		c.hc = noRedirects(c.HTTPClient)
	}
	resp, err := c.hc.Do(req) //nolint:gosec // G704: the operator configures the token endpoint
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrToken, err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tr); err != nil || resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		return "", fmt.Errorf("%w: status %d %s", ErrToken, resp.StatusCode, tr.Error)
	}
	c.token, c.expires = tr.AccessToken, now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return c.token, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// assertion is the signed client assertion: iss and sub the client id,
// aud the token endpoint, a fresh jti, five minutes of life.
func (c *ClientCredentials) assertion(now time.Time) (string, error) {
	alg, kid, err := keyID(c.Key)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	header, err := json.Marshal(jwtHeader{Alg: alg, Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(assertionClaims{
		Iss: c.ClientID, Sub: c.ClientID, Aud: c.TokenURL, JTI: b64(jti), Iat: now.Unix(), Exp: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(claims)
	sig, err := sign(c.Key, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

// keyID returns the JOSE algorithm and RFC 7638 thumbprint of the key's
// public half, which PantherClaw uses as its kid.
func keyID(k crypto.Signer) (alg, kid string, err error) {
	var canonical string
	switch pub := k.Public().(type) {
	case ed25519.PublicKey:
		alg, canonical = "EdDSA", `{"crv":"Ed25519","kty":"OKP","x":"`+b64(pub)+`"}`
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return "", "", errors.New("pep: only P-256 ECDSA keys are supported")
		}
		raw, err := pub.Bytes()
		if err != nil {
			return "", "", err
		}
		alg, canonical = "ES256", `{"crv":"P-256","kty":"EC","x":"`+b64(raw[1:33])+`","y":"`+b64(raw[33:])+`"}`
	default:
		return "", "", errors.New("pep: the key must be Ed25519 or P-256 ECDSA")
	}
	sum := sha256.Sum256([]byte(canonical))
	return alg, b64(sum[:]), nil
}

// sign signs input as JWS: Ed25519 over the bytes, ES256 as r||s.
func sign(k crypto.Signer, input []byte) ([]byte, error) {
	if _, ok := k.Public().(ed25519.PublicKey); ok {
		return k.Sign(rand.Reader, input, crypto.Hash(0))
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pep: an ES256 key must be an *ecdsa.PrivateKey")
	}
	sum := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type assertionClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	JTI string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// noRedirects copies hc (nil: a client with a 10 second timeout) so that
// it never follows a redirect, which would send the assertion, the token
// or the agent's credentials elsewhere, and, without a transport of its
// own, ignores proxy settings.
func noRedirects(hc *http.Client) *http.Client {
	out := &http.Client{Timeout: 10 * time.Second}
	if hc != nil {
		copied := *hc
		out = &copied
	}
	if out.Transport == nil {
		out.Transport = transport()
	}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return out
}

// Invalidate drops the cached token, which the decision endpoint refused.
func (c *ClientCredentials) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.expires = "", time.Time{}
}
