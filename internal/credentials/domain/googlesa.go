// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"slices"
)

// KindGoogleServiceAccount is a Google service account's key (G0 M31
// D952, HR-721): the key is never placed on a request and never leaves the
// gateway. For each dispatch the gateway signs a short RS256 assertion with
// it, exchanges that at Google's token endpoint (the JWT-bearer grant, RFC
// 7523) for an access token with the credential's scopes, and places only
// that token, as "Authorization: Bearer". Nothing is cached.
const KindGoogleServiceAccount = "google_service_account"

// Google service account tokens are placed as "Authorization: Bearer
// <token>".
const (
	GoogleServiceAccountHeader = "Authorization"
	GoogleServiceAccountScheme = "Bearer"
)

// GoogleTokenURI is the one token endpoint a real Google service account
// credential names; a simulated connection's is a loopback address.
const GoogleTokenURI = "https://oauth2.googleapis.com/token" //nolint:gosec // G101: an endpoint, not a credential

// MaxGoogleScopes bounds a service account credential's scopes.
const MaxGoogleScopes = 8

// ErrGoogleServiceAccount reports a service account credential that
// cannot be used.
var ErrGoogleServiceAccount = errors.New("credentials: not a Google service account credential")

// GoogleServiceAccount is the sealed content of a Google service account
// credential: the account's email, its RSA private key (PEM), Google's
// token endpoint, the user it acts as by domain-wide delegation (empty for
// the account itself) and the scopes every token asks for. The opener
// clears PrivateKey (Clear) as soon as the assertion is signed.
type GoogleServiceAccount struct {
	V           int      `json:"v"`
	ClientEmail string   `json:"client_email"`
	PrivateKey  []byte   `json:"private_key"`
	TokenURI    string   `json:"token_uri"`
	Subject     string   `json:"subject,omitzero"`
	Scopes      []string `json:"scopes"`
}

var (
	googleEmailRe = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	googleScopeRe = regexp.MustCompile(`^https://www\.googleapis\.com/auth/[A-Za-z0-9._/-]{1,128}$`)
)

// Token returns the parsed token endpoint: exactly GoogleTokenURI, or a
// loopback simulator's endpoint (http or https), which only a simulated
// connection reaches.
func (g GoogleServiceAccount) Token() (*url.URL, error) {
	u, err := url.Parse(g.TokenURI)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(g.TokenURI) > 512 {
		return nil, ErrGoogleServiceAccount
	}
	if g.TokenURI == GoogleTokenURI || ((u.Scheme == "http" || u.Scheme == "https") && Loopback(u)) {
		return u, nil
	}
	return nil, ErrGoogleServiceAccount
}

// Key parses the account's private key: RSA (PKCS #8 as Google issues it,
// or PKCS #1), at least 2048 bits.
func (g GoogleServiceAccount) Key() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(g.PrivateKey)
	if block == nil {
		return nil, ErrGoogleServiceAccount
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		rk, ok := k.(*rsa.PrivateKey)
		if err != nil || !ok {
			return nil, ErrGoogleServiceAccount
		}
		key = rk
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrGoogleServiceAccount
		}
		key = k
	default:
		return nil, ErrGoogleServiceAccount
	}
	if key.N.BitLen() < 2048 {
		return nil, ErrGoogleServiceAccount
	}
	return key, nil
}

// Validate checks every field and that the key parses.
func (g GoogleServiceAccount) Validate() error {
	if g.V != 1 || len(g.ClientEmail) > 254 || !googleEmailRe.MatchString(g.ClientEmail) ||
		(g.Subject != "" && (len(g.Subject) > 254 || !googleEmailRe.MatchString(g.Subject))) ||
		len(g.Scopes) == 0 || len(g.Scopes) > MaxGoogleScopes {
		return ErrGoogleServiceAccount
	}
	for i, s := range g.Scopes {
		if !googleScopeRe.MatchString(s) || slices.Contains(g.Scopes[:i], s) {
			return ErrGoogleServiceAccount
		}
	}
	if _, err := g.Token(); err != nil {
		return err
	}
	_, err := g.Key()
	return err
}

// Encode returns the plaintext to seal.
func (g GoogleServiceAccount) Encode() ([]byte, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(g, json.Deterministic(true))
}

// DecodeGoogleServiceAccount decodes and validates an opened service
// account credential.
func DecodeGoogleServiceAccount(plain []byte) (GoogleServiceAccount, error) {
	var g GoogleServiceAccount
	if err := json.UnmarshalRead(bytes.NewReader(plain), &g, json.RejectUnknownMembers(true)); err != nil {
		return GoogleServiceAccount{}, ErrGoogleServiceAccount
	}
	return g, g.Validate()
}

// GoogleKeyFile is the part of a service account key file Google issues
// (JSON) that a credential is made from; the file's other members are
// left out and never sealed.
type GoogleKeyFile struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// ParseGoogleKeyFile reads a service account key file: a JSON object of
// type service_account.
func ParseGoogleKeyFile(b []byte) (GoogleKeyFile, error) {
	var f GoogleKeyFile
	if err := json.Unmarshal(b, &f); err != nil || f.Type != "service_account" || f.ClientEmail == "" || f.PrivateKey == "" {
		return GoogleKeyFile{}, ErrGoogleServiceAccount
	}
	return f, nil
}

// Clear overwrites the private key's bytes.
func (g *GoogleServiceAccount) Clear() { clear(g.PrivateKey) }
