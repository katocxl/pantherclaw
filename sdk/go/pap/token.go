// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"
)

// TokenAudience is the audience of every workload token.
const TokenAudience = "pantherclaw-gateway"

// TokenClaims are the claims of a workload token (PAP/1 §3.4). The SDK
// reads them without verifying the signature, only to know when to renew
// and which key the token is bound to; PantherClaw verifies the token.
type TokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
	ID        string `json:"jti"`
	Cnf       struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
	PAP struct {
		V     int    `json:"v"`
		Org   string `json:"org"`
		Env   string `json:"env"`
		Level int    `json:"att_lvl"`
	} `json:"pap"`
}

// ExpiresAt returns the token's expiry.
func (c TokenClaims) ExpiresAt() time.Time { return time.Unix(c.Expiry, 0) }

// ParseTokenClaims reads a workload token's claims without verifying it.
// Unknown claims are ignored (PAP/1 §13).
func ParseTokenClaims(token string) (TokenClaims, error) {
	var c TokenClaims
	payload, err := segment(token, 1)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("pap: workload token claims: %w", err)
	}
	if c.PAP.V != Version || c.Audience != TokenAudience || c.Expiry == 0 || c.Cnf.JKT == "" {
		return c, errors.New("pap: not a PAP/1 workload token")
	}
	return c, nil
}
