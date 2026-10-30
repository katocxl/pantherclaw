// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"net/url"
	"regexp"
)

// KindOAuthClient is an OAuth 2.0 client-credentials credential (G0 M20
// D254, HR-524): the client secret is never placed on a request. The
// gateway exchanges it at the token endpoint for an access token once per
// dispatch and places that token as "Authorization: Bearer". The token is
// never cached and never returned to the agent. Microsoft Teams' Bot
// Framework is the first user.
const KindOAuthClient = "oauth_client"

// OAuth client tokens are placed as "Authorization: Bearer <token>".
const (
	OAuthClientHeader = "Authorization"
	OAuthClientScheme = "Bearer"
)

// ErrOAuthClient reports an OAuth client credential that cannot be used.
var ErrOAuthClient = errors.New("credentials: not an OAuth client credential")

// OAuthClient is the sealed content of an OAuth client credential: the
// token endpoint, the client id, the one scope asked for, and the client
// secret. The token endpoint's host must be one the seal binds, like every
// host the credential reaches (HR-060). The opener clears ClientSecret
// (Clear) as soon as the token request is built.
type OAuthClient struct {
	V            int    `json:"v"`
	TokenURL     string `json:"token_url"`
	ClientID     string `json:"client_id"`
	Scope        string `json:"scope"`
	ClientSecret []byte `json:"client_secret"`
}

var (
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	// scopeRe is one scope: printable ASCII without spaces or quotes.
	scopeRe        = regexp.MustCompile(`^[A-Za-z0-9:/._~-]{1,256}$`)
	clientSecretRe = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// Token returns the parsed token endpoint: https, or http for a loopback
// development simulator only by the connection's own rules; no user
// information, query or fragment.
func (o OAuthClient) Token() (*url.URL, error) {
	u, err := url.Parse(o.TokenURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(o.TokenURL) > 512 {
		return nil, ErrOAuthClient
	}
	return u, nil
}

// Validate checks every field.
func (o OAuthClient) Validate() error {
	if o.V != 1 || !clientIDRe.MatchString(o.ClientID) || !scopeRe.MatchString(o.Scope) || len(o.ClientSecret) > 1024 || !clientSecretRe.Match(o.ClientSecret) {
		return ErrOAuthClient
	}
	_, err := o.Token()
	return err
}

// Encode returns the plaintext to seal.
func (o OAuthClient) Encode() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(o, json.Deterministic(true))
}

// DecodeOAuthClient decodes and validates an opened OAuth client credential.
func DecodeOAuthClient(plain []byte) (OAuthClient, error) {
	var o OAuthClient
	if err := json.UnmarshalRead(bytes.NewReader(plain), &o, json.RejectUnknownMembers(true)); err != nil {
		return OAuthClient{}, ErrOAuthClient
	}
	return o, o.Validate()
}

// Clear overwrites the client secret's bytes.
func (o *OAuthClient) Clear() { clear(o.ClientSecret) }
