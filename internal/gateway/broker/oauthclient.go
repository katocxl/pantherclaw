// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// ErrClientToken reports a token endpoint that did not issue a usable
// access token; the dispatch fails before the action's request is sent
// (enforcement_failed).
var ErrClientToken = errors.New("broker: the token endpoint did not issue an access token")

// ClientToken is an access token minted from an OAuth client credential
// for one dispatch (G0 M20 D254, HR-524). It is placed as "Authorization:
// Bearer", only on a host the credential is bound to, and is never cached
// or returned to the agent; Clear drops it when the dispatch ends. The
// client secret itself is never placed on a target request.
type ClientToken struct {
	token []byte
	hosts []string
}

// Token is the token's bytes, which a caller scrubs from what goes back to
// the agent; Clear clears them.
func (t *ClientToken) Token() []byte { return t.token }

// Clear overwrites the token.
func (t *ClientToken) Clear() { clear(t.token) }

// Place sets "Authorization: Bearer <token>" on r, for the credential's
// bound hosts only (HR-060).
func (t *ClientToken) Place(r *http.Request) error {
	return Place(r, t.hosts, domain.OAuthClientHeader, domain.OAuthClientScheme, t.token)
}

// MintClientToken asks the credential's token endpoint, through s (an
// egress client pinned to the endpoint's host), for an access token with
// the OAuth 2.0 client-credentials grant (RFC 6749 §4.4): the client id and
// secret in a form body, for the credential's one scope. The endpoint's
// host must be bound by the seal like every other host (HR-060). The
// answer must be a 200 with token_type Bearer, a positive expires_in and
// an opaque printable token of at most 4 KiB; anything else is refused.
func MintClientToken(ctx context.Context, s Sender, hosts []string, oc domain.OAuthClient) (*ClientToken, error) {
	if oc.Validate() != nil {
		return nil, domain.ErrOAuthClient
	}
	u, _ := oc.Token()
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	if !Bound(hosts, u.Host, port) {
		return nil, ErrNotBound
	}
	body := clientCredentialsForm(oc)
	defer clear(body)
	req, err := s.HTTPRequest(ctx, egress.Request{Method: http.MethodPost, URL: u, Body: body, ContentType: egress.FormContentType})
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := s.Do(req)
	if err != nil {
		return nil, errors.Join(ErrClientToken, err)
	}
	defer clear(res.Body)
	if res.Status != http.StatusOK || res.Truncated {
		return nil, ErrClientToken
	}
	var a struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(res.Body, &a) != nil || !strings.EqualFold(a.TokenType, "Bearer") || a.ExpiresIn <= 0 || !validToken(a.AccessToken) {
		return nil, ErrClientToken
	}
	return &ClientToken{token: []byte(a.AccessToken), hosts: hosts}, nil
}

// validToken reports an opaque token of 1..maxToken printable ASCII
// characters without spaces, so it can only ever be one header value.
func validToken(t string) bool {
	return t != "" && len(t) <= maxToken && !strings.ContainsFunc(t, func(c rune) bool { return c <= ' ' || c > '~' })
}

// clientCredentialsForm is the token request's body, written into one
// buffer the caller clears, so the secret is never left in a string.
func clientCredentialsForm(oc domain.OAuthClient) []byte {
	b := make([]byte, 0, 96+len(oc.ClientID)+3*len(oc.ClientSecret)+3*len(oc.Scope))
	b = append(b, "grant_type=client_credentials&client_id="...)
	b = appendEscaped(b, []byte(oc.ClientID))
	b = append(b, "&client_secret="...)
	b = appendEscaped(b, oc.ClientSecret)
	b = append(b, "&scope="...)
	return appendEscaped(b, []byte(oc.Scope))
}

// appendEscaped percent-encodes every byte that is not unreserved (RFC
// 3986 §2.3), as a form value.
func appendEscaped(b, v []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, c := range v {
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b = append(b, c)
			continue
		}
		b = append(b, '%', hex[c>>4], hex[c&0x0f])
	}
	return b
}
