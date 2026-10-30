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
	"regexp"
)

// Credential kinds. A static credential is placed on a request as it was
// sealed. A GitHub App credential is never placed: the gateway signs a
// short App JWT with its key and mints an installation token for each
// authorized action (G0 M8 decision 3, HR-203, HR-204). The kind is bound
// into the seal, so a blob sealed as one kind never opens as the other.
const (
	KindStatic    = "static"
	KindGitHubApp = "github_app"
)

// ValidKind reports whether k is a credential kind ("" is static).
func ValidKind(k string) bool {
	return k == "" || k == KindStatic || k == KindGitHubApp || k == KindOAuthClient || k == KindAWSSigV4
}

// Minted reports whether a kind is never placed as sealed: the gateway
// mints a short-lived token or session from it per dispatch (HR-203,
// HR-524, HR-525).
func Minted(k string) bool { return k == KindGitHubApp || k == KindOAuthClient || k == KindAWSSigV4 }

// GitHub App credentials are placed as "Authorization: Bearer <token>".
const (
	GitHubAppHeader = "Authorization"
	GitHubAppScheme = "Bearer"
)

// ErrGitHubApp reports a GitHub App credential that cannot be used.
var ErrGitHubApp = errors.New("credentials: not a GitHub App credential")

// GitHubApp is the sealed content of a GitHub App credential: the App
// (its client id, or its numeric id), the installation, the account it is
// installed on, and the App's private key (PEM, PKCS #1 as GitHub issues
// it, or PKCS #8; base64 in the JSON). The opener clears PrivateKey (Clear)
// as soon as the key is parsed.
type GitHubApp struct {
	V            int    `json:"v"`
	Issuer       string `json:"issuer"`
	Installation int64  `json:"installation"`
	Account      string `json:"account"`
	PrivateKey   []byte `json:"private_key"`
}

var (
	issuerRe  = regexp.MustCompile(`^([1-9][0-9]{0,18}|Iv[0-9A-Za-z.]{1,64})$`)
	accountRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)
)

// Key parses the App's private key: RSA, at least 2048 bits.
func (g GitHubApp) Key() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(g.PrivateKey)
	if block == nil {
		return nil, ErrGitHubApp
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrGitHubApp
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		rk, ok := k.(*rsa.PrivateKey)
		if err != nil || !ok {
			return nil, ErrGitHubApp
		}
		key = rk
	default:
		return nil, ErrGitHubApp
	}
	if key.N.BitLen() < 2048 {
		return nil, ErrGitHubApp
	}
	return key, nil
}

// Validate checks every field and that the key parses.
func (g GitHubApp) Validate() error {
	if g.V != 1 || !issuerRe.MatchString(g.Issuer) || g.Installation <= 0 || !accountRe.MatchString(g.Account) {
		return ErrGitHubApp
	}
	_, err := g.Key()
	return err
}

// Encode returns the plaintext to seal.
func (g GitHubApp) Encode() ([]byte, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(g, json.Deterministic(true))
}

// DecodeGitHubApp decodes and validates an opened GitHub App credential.
func DecodeGitHubApp(plain []byte) (GitHubApp, error) {
	var g GitHubApp
	if err := json.UnmarshalRead(bytes.NewReader(plain), &g, json.RejectUnknownMembers(true)); err != nil {
		return GitHubApp{}, ErrGitHubApp
	}
	return g, g.Validate()
}

// Clear overwrites the private key's bytes.
func (g *GitHubApp) Clear() { clear(g.PrivateKey) }
