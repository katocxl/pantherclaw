// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// serviceAccountLifetime is how long a signed assertion is valid (G0 M31
// D952): five minutes from its issue.
const serviceAccountLifetime = 300 * time.Second

// jwtBearerGrant is the JWT-bearer grant type (RFC 7523 §2.1).
const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// ErrServiceAccountToken reports a token endpoint that did not issue a
// usable access token for a service account assertion; the dispatch fails
// before the action's request is sent (enforcement_failed).
var ErrServiceAccountToken = errors.New("broker: the token endpoint did not issue an access token for the service account")

// MintServiceAccountToken signs an RS256 assertion with the opened service
// account key (iss the account, sub the delegated user when set, aud the
// token endpoint, scope the credential's scopes, five minutes) and
// exchanges it, through s (an egress client pinned to the endpoint's
// host, which the seal must bind), for one access token (G0 M31 D952,
// HR-721). The key never leaves the gateway and the token is never
// cached; the answer must be a 200 with token_type Bearer, a positive
// expires_in and an opaque printable token of at most 4 KiB.
func MintServiceAccountToken(ctx context.Context, s Sender, hosts []string, sa domain.GoogleServiceAccount, now time.Time) (*ClientToken, error) {
	if sa.Validate() != nil {
		return nil, domain.ErrGoogleServiceAccount
	}
	u, _ := sa.Token()
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	if !Bound(hosts, u.Host, port) {
		return nil, ErrNotBound
	}
	key, err := sa.Key()
	if err != nil {
		return nil, err
	}
	assertion, err := serviceAccountJWT(key, sa, now)
	if err != nil {
		return nil, errors.Join(ErrServiceAccountToken, err)
	}
	defer clear(assertion)
	body := make([]byte, 0, 64+len(assertion))
	body = append(body, "grant_type="...)
	body = appendEscaped(body, []byte(jwtBearerGrant))
	body = append(body, "&assertion="...)
	body = appendEscaped(body, assertion)
	defer clear(body)
	req, err := s.HTTPRequest(ctx, egress.Request{Method: http.MethodPost, URL: u, Body: body, ContentType: egress.FormContentType})
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := s.Do(req)
	if err != nil {
		return nil, errors.Join(ErrServiceAccountToken, err)
	}
	defer clear(res.Body)
	if res.Status != http.StatusOK || res.Truncated {
		return nil, ErrServiceAccountToken
	}
	var a struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(res.Body, &a) != nil || !strings.EqualFold(a.TokenType, "Bearer") || a.ExpiresIn <= 0 || !validToken(a.AccessToken) {
		return nil, ErrServiceAccountToken
	}
	return &ClientToken{token: []byte(a.AccessToken), hosts: hosts}, nil
}

// serviceAccountJWT is the signed assertion of one token request.
func serviceAccountJWT(key *rsa.PrivateKey, sa domain.GoogleServiceAccount, now time.Time) ([]byte, error) {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]any{
		"iss": sa.ClientEmail, "aud": sa.TokenURI, "scope": strings.Join(sa.Scopes, " "),
		"iat": now.Unix(), "exp": now.Add(serviceAccountLifetime).Unix(),
	}
	if sa.Subject != "" {
		claims["sub"] = sa.Subject
	}
	c, err := json.Marshal(claims, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	signing := head + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return nil, err
	}
	return []byte(signing + "." + base64.RawURLEncoding.EncodeToString(sig)), nil
}
