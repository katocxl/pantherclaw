// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pap

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Stale reports whether err refuses a request only because of time (HR-850):
// an expired workload token, a token or proof outside the clock-skew
// leeway, or a nonce that is missing or past its lifetime. use_nonce is
// how every client learns the current nonce on its first call, and a
// replay of an old proof meets it too, so it says nothing on its own. A
// stale refusal is logged, never recorded as an identity event.
func Stale(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Code {
	case CodeTokenExpired, CodeUseNonce:
		return true
	case CodeInvalidProof:
		return e.detail == "iat"
	case CodeInvalidToken:
		return e.detail == "not yet valid"
	}
	return false
}

// ProofJKT returns the RFC 7638 thumbprint of the key a proof's header
// carries, verifying nothing; "" when it names none. It only labels a
// refused proof (HR-850) and must never be trusted.
func ProofJKT(compact string) string {
	if compact == "" || len(compact) > MaxProofBytes || strings.Count(compact, ".") != 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(compact[:strings.IndexByte(compact, '.')])
	if err != nil {
		return ""
	}
	var h proofHeader
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	key, err := jws.JWK{Kty: h.JWK.Kty, Crv: h.JWK.Crv, X: h.JWK.X}.Key()
	if err != nil {
		return ""
	}
	return jws.Thumbprint(key)
}
