// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
)

// snowflakeLifetime is how long a key-pair JWT is valid: Snowflake takes
// at most an hour; one dispatch needs its statement's timeout (at most 60
// s) and the polls after it.
const snowflakeLifetime = 5 * time.Minute

// SnowflakeToken is a key-pair JWT signed for one dispatch (G0 M31 D962,
// HR-726). It is placed as "Authorization: Bearer" with the KEYPAIR_JWT
// token type header, only on a host the credential is bound to, and is
// never cached or returned to the agent; Clear drops it when the dispatch
// ends. The private key itself is never placed.
type SnowflakeToken struct{ ClientToken }

// Place sets "Authorization: Bearer <jwt>" and the token type header on
// r, for the credential's bound hosts only (HR-060).
func (t *SnowflakeToken) Place(r *http.Request) error {
	if err := Place(r, t.hosts, domain.SnowflakeKeypairHeader, domain.SnowflakeKeypairScheme, t.token); err != nil {
		return err
	}
	r.Header.Set(domain.SnowflakeTokenTypeHeader, domain.SnowflakeTokenTypeKeypair)
	return nil
}

// MintSnowflakeToken signs an RS256 key-pair JWT with the opened key: iss
// ACCOUNT.USER.SHA256:<public key fingerprint>, sub ACCOUNT.USER, iat now
// and exp five minutes on. Nothing is sent: Snowflake checks the JWT on
// the request itself.
func MintSnowflakeToken(hosts []string, kp domain.SnowflakeKeypair, now time.Time) (*SnowflakeToken, error) {
	if kp.Validate() != nil {
		return nil, domain.ErrSnowflakeKeypair
	}
	key, err := kp.Key()
	if err != nil {
		return nil, err
	}
	jwt, err := snowflakeJWT(key, kp, now)
	if err != nil {
		return nil, err
	}
	return &SnowflakeToken{ClientToken{token: jwt, hosts: hosts}}, nil
}

func snowflakeJWT(key *rsa.PrivateKey, kp domain.SnowflakeKeypair, now time.Time) ([]byte, error) {
	fp, err := domain.Fingerprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sub := kp.Qualified()
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	c, err := json.Marshal(map[string]any{
		"iss": sub + "." + fp, "sub": sub, "iat": now.Unix(), "exp": now.Add(snowflakeLifetime).Unix(),
	}, json.Deterministic(true))
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
