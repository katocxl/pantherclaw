// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
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

// BotFrameworkScope is the scope of a Microsoft Teams bot's tokens.
const BotFrameworkScope = "https://api.botframework.com/.default"

// ErrOAuthClient reports an OAuth client credential that cannot be used.
var ErrOAuthClient = errors.New("credentials: not an OAuth client credential")

// ErrOAuthClientTenant reports a Teams bot credential that pins no home
// tenant (G0 M20 D279): sealed, every post would fail on a missing
// teams.channel.external fact (D273).
var ErrOAuthClientTenant = fmt.Errorf("%w: a Microsoft Teams bot's token endpoint must name its home tenant, "+
	"https://login.microsoftonline.com/<tenant id, a lowercase GUID>/oauth2/v2.0/token, not botframework.com; nothing was sealed", ErrOAuthClient)

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

// Encode returns the plaintext to seal. A Teams bot must pin its home tenant
// here, where the plaintext is still in the sealer's hands; a decoded
// credential that pins none only leaves its facts unread (D273, D279).
func (o OAuthClient) Encode() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if o.Scope == BotFrameworkScope && o.Tenant() == "" {
		return nil, ErrOAuthClientTenant
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

var tenantRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Tenant is the Microsoft Entra tenant the token endpoint pins, the first
// segment of a single-tenant endpoint's path (/{tenant}/oauth2/v2.0/token),
// or "" for an endpoint that names none, such as the multi-tenant
// botframework.com (G0 M20 D273). The seal binds the endpoint, so the agent
// can never choose it.
func (o OAuthClient) Tenant() string {
	u, err := o.Token()
	if err != nil {
		return ""
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	if !tenantRe.MatchString(first) {
		return ""
	}
	return first
}
