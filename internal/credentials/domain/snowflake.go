// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
)

// KindSnowflakeKeypair is a Snowflake user's key pair (G0 M31 D962,
// HR-726): the private key is never placed on a request and never leaves
// the gateway. For each dispatch the gateway signs a short RS256 key-pair
// JWT with it (iss ACCOUNT.USER.SHA256:<public key fingerprint>, sub
// ACCOUNT.USER) and places only that, as "Authorization: Bearer" with
// "X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT". Nothing is cached.
const KindSnowflakeKeypair = "snowflake_keypair"

// Snowflake key-pair JWTs are placed as "Authorization: Bearer <jwt>",
// with the token type header beside it.
const (
	SnowflakeKeypairHeader    = "Authorization"
	SnowflakeKeypairScheme    = "Bearer"
	SnowflakeTokenTypeHeader  = "X-Snowflake-Authorization-Token-Type" //nolint:gosec // G101: a header name, not a credential
	SnowflakeTokenTypeKeypair = "KEYPAIR_JWT"                          //nolint:gosec // G101: a token type, not a credential
)

// ErrSnowflakeKeypair reports a key-pair credential that cannot be used.
var ErrSnowflakeKeypair = errors.New("credentials: not a Snowflake key-pair credential")

// SnowflakeKeypair is the sealed content of a Snowflake key-pair
// credential: the account identifier, the user and the user's RSA private
// key (PEM, unencrypted PKCS #8 or PKCS #1). The opener clears PrivateKey
// (Clear) as soon as the JWT is signed.
type SnowflakeKeypair struct {
	V          int    `json:"v"`
	Account    string `json:"account"`
	User       string `json:"user"`
	PrivateKey []byte `json:"private_key"`
}

var (
	// An account identifier: orgname-account_name, or an account locator
	// with its region and cloud (xy12345.us-east-2.aws).
	snowflakeAccountRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,254}(\.[A-Za-z0-9_-]{1,64}){0,2}$`)
	snowflakeUserRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@$-]{0,254}$`)
)

// Key parses the user's private key: RSA, at least 2048 bits.
func (k SnowflakeKeypair) Key() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(k.PrivateKey)
	if block == nil {
		return nil, ErrSnowflakeKeypair
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		p, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		rk, ok := p.(*rsa.PrivateKey)
		if err != nil || !ok {
			return nil, ErrSnowflakeKeypair
		}
		key = rk
	case "RSA PRIVATE KEY":
		p, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrSnowflakeKeypair
		}
		key = p
	default:
		return nil, ErrSnowflakeKeypair
	}
	if key.N.BitLen() < 2048 {
		return nil, ErrSnowflakeKeypair
	}
	return key, nil
}

// Qualified is ACCOUNT.USER as a key-pair JWT names it: the account
// without its region or cloud, both upper case.
func (k SnowflakeKeypair) Qualified() string {
	account, _, _ := strings.Cut(k.Account, ".")
	return strings.ToUpper(account) + "." + strings.ToUpper(k.User)
}

// Fingerprint is SHA256:<base64 of the sha256 of the public key's DER>,
// as Snowflake shows it in RSA_PUBLIC_KEY_FP.
func Fingerprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", ErrSnowflakeKeypair
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

// Validate checks every field and that the key parses.
func (k SnowflakeKeypair) Validate() error {
	if k.V != 1 || !snowflakeAccountRe.MatchString(k.Account) || !snowflakeUserRe.MatchString(k.User) {
		return ErrSnowflakeKeypair
	}
	_, err := k.Key()
	return err
}

// Encode returns the plaintext to seal.
func (k SnowflakeKeypair) Encode() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(k, json.Deterministic(true))
}

// DecodeSnowflakeKeypair decodes and validates an opened key-pair
// credential.
func DecodeSnowflakeKeypair(plain []byte) (SnowflakeKeypair, error) {
	var k SnowflakeKeypair
	if err := json.UnmarshalRead(bytes.NewReader(plain), &k, json.RejectUnknownMembers(true)); err != nil {
		return SnowflakeKeypair{}, ErrSnowflakeKeypair
	}
	return k, k.Validate()
}

// Clear overwrites the private key's bytes.
func (k *SnowflakeKeypair) Clear() { clear(k.PrivateKey) }
