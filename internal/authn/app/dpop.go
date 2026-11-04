// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import "context"

// DPoPHeader is the request header a DPoP proof travels in (RFC 9449 §4.1).
const DPoPHeader = "DPoP"

// ErrInvalidDPoPProof refuses a token request whose DPoP proof is missing
// where it is required, or does not verify (RFC 9449 §5; G0 M30 D912).
var ErrInvalidDPoPProof = &OAuthError{Code: "invalid_dpop_proof", Description: "the DPoP proof is missing or not valid", Status: 400}

type dpopKey struct{}

// WithDPoP carries the token request's DPoP header values to the grant
// that handles it: the token endpoint's grants see only the form.
func WithDPoP(ctx context.Context, values []string) context.Context {
	return context.WithValue(ctx, dpopKey{}, values)
}

// DPoPProof returns the token request's DPoP proof: "" with ok true when
// the request carries none, and ok false when it carries more than one
// DPoP header (RFC 9449 §4.3 check 1).
func DPoPProof(ctx context.Context) (proof string, ok bool) {
	v, _ := ctx.Value(dpopKey{}).([]string)
	switch len(v) {
	case 0:
		return "", true
	case 1:
		return v[0], v[0] != ""
	}
	return "", false
}
