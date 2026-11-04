// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"net/http"
	"strings"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Token bindings an issued token's audit entry names (G0 M30 D914).
const (
	BindingDPoP   = "dpop"
	BindingBearer = "bearer"
)

// Token types of a token response (RFC 9449 §5).
const (
	tokenTypeBearer = "Bearer"
	tokenTypeDPoP   = "DPoP"
)

// dpopReplayIssuer is the pc.auth_replay issuer a DPoP proof's jti is
// recorded under at the token endpoint.
const dpopReplayIssuer = "dpop:"

// tokenDPoP checks the token request's DPoP proof (RFC 9449 §4.3, §5; G0
// M30 D912) and returns the thumbprint of its key, or "" when the request
// carries none. The proof is EdDSA with its public jwk only (the PAP/1
// list), its htm is POST and its htu the token endpoint under publicURL;
// the token endpoint asks for no nonce. Its jti is recorded in its own
// committed transaction, so a proof refused later is never accepted again.
// Every refusal is invalid_dpop_proof.
func tokenDPoP(ctx context.Context, pool *db.Pool, publicURL string, org ids.OrgID, now time.Time) (string, error) {
	proof, ok := authnapp.DPoPProof(ctx)
	if !ok {
		return "", refuse(authnapp.ErrInvalidDPoPProof, "dpop_header_repeated")
	}
	if proof == "" {
		return "", nil
	}
	c, err := pap.VerifyDPoP(proof, pap.DPoPRequest{
		Method: http.MethodPost, URL: strings.TrimSuffix(publicURL, "/") + authnapp.TokenPath,
	}, now)
	if err != nil {
		return "", refuse(authnapp.ErrInvalidDPoPProof, "dpop_proof: "+string(pap.CodeOf(err)))
	}
	var n int64
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		n, err = dbq.New(tx).InsertAuthReplay(ctx, dbq.InsertAuthReplayParams{
			OrgID: org, Issuer: dpopReplayIssuer + c.JKT(), Jti: c.JTI(), ExpiresAt: c.IssuedAt().Add(pap.DPoPReplayFor),
		})
		return err
	})
	switch {
	case err != nil:
		return "", err
	case n == 0:
		return "", refuse(authnapp.ErrInvalidDPoPProof, "dpop_proof_replayed")
	}
	return c.JKT(), nil
}

// bindingOf names how a token is bound, for its audit entry.
func bindingOf(jkt string) string {
	if jkt != "" {
		return BindingDPoP
	}
	return BindingBearer
}

// tokenType is the token_type of a token bound to jkt, or of a bearer
// token.
func tokenType(jkt string) string {
	if jkt != "" {
		return tokenTypeDPoP
	}
	return tokenTypeBearer
}

// optJKT is jkt as a nullable column.
func optJKT(jkt string) *string {
	if jkt == "" {
		return nil
	}
	return &jkt
}
