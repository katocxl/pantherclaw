// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package actiontoken mints PAP-1 §10 action tokens: the JWS a
// target-enforced connection's verifier checks before it lets a request
// run (HR-188). The Authority mints one at BeginDispatch; the connection
// test mints test-purpose ones for a package's test read only (G0 M8, N15).
package actiontoken

import (
	"encoding/hex"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	// Type is the JOSE type of an action token.
	Type = "pap-action+jwt"
	// TTL is an action token's lifetime.
	TTL = 60 * time.Second
)

// Signer signs a compact JWS of a JOSE type (the action_tokens key's).
type Signer interface {
	Sign(typ string, payload []byte) (string, error)
}

// Token is what one action token binds.
type Token struct {
	Issuer string
	// Audience is the connection the target is registered as.
	Audience ids.UUID
	// Transaction is the transaction, or the connection test, it is for.
	Transaction ids.UUID
	// Act is the effective action hash; BodySHA256 the hash of the exact
	// outbound body.
	Act, BodySHA256      []byte
	Operation            string
	TargetType, TargetID string
	Now                  time.Time
	// NotAfter, when set, ends the token's life before Now + TTL if it
	// comes first: a connection test's token ends with its lease. A
	// dispatch's token leaves it unset.
	NotAfter time.Time
}

type claims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Pap pap    `json:"pap"`
}

type pap struct {
	V      int    `json:"v"`
	Txn    string `json:"txn"`
	Act    string `json:"act"`
	BH     string `json:"bh"`
	Op     string `json:"op"`
	Target target `json:"target"`
}

type target struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Mint signs t with a single-use id and a lifetime of TTL, or up to
// t.NotAfter when that is sooner, and returns the token and its id.
func Mint(s Signer, t Token) (string, ids.UUID, error) {
	jti := ids.NewV7()
	exp := t.Now.Add(TTL)
	if !t.NotAfter.IsZero() && t.NotAfter.Before(exp) {
		exp = t.NotAfter
	}
	b, err := json.Marshal(claims{
		Iss: t.Issuer, Aud: t.Audience.String(), Jti: jti.String(), Iat: t.Now.Unix(), Exp: exp.Unix(),
		Pap: pap{
			V: 1, Txn: t.Transaction.String(), Act: hex.EncodeToString(t.Act), BH: hex.EncodeToString(t.BodySHA256),
			Op: t.Operation, Target: target{Type: t.TargetType, ID: t.TargetID},
		},
	})
	if err != nil {
		return "", ids.UUID{}, err
	}
	tok, err := s.Sign(Type, b)
	return tok, jti, err
}
