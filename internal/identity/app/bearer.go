// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	iddomain "github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// EnrolledMcpClient is the enrolled_via of an allow-listed MCP client's own
// instance (G0 M26 D408.1): its key is held by no one.
const EnrolledMcpClient = "mcp_client"

// EnrolledFederation is the enrolled_via of a federated peer agent's
// instance (G0 M35 D1024c): it has no key, and Identify refuses it for
// PAP/1 explicitly; it acts only through a federation call.
const EnrolledFederation = "federation"

// OAuthRoute reports whether a request URL is on a gateway's OAuth route
// (/mcp-oauth/), where only a pap-mcp+jwt is accepted (HR-626).
func OAuthRoute(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.Contains(u.EscapedPath(), iddomain.ResourcePath)
}

// McpVerifier returns the verifier for MCP access tokens: the mcp_tokens
// keys only.
func (s *Service) McpVerifier() (*jws.Verifier, error) {
	return s.keys.Verifier(keys.PurposeMcpTokens, mcptoken.TokenType)
}

// identifyBearer verifies a pap-mcp+jwt (G0 M26 D402, D408; HR-626): its
// signature with an mcp_tokens key, its audience exactly the request URL,
// and then, on every call, that its client is still bound or allow-listed,
// the org's MCP authorization is on for that gateway, its instance is still
// admitted and its agent usable. Bearer proof is level 0 (HR-627). The run
// and the connection the token names are checked against the action by the
// caller.
//
// A DPoP-bound token (cnf.jkt and pap.proof "dpop", G0 M30 D913) is never
// accepted as a bearer token: in.Proof must be a DPoP proof over this
// request, signed with the token's key, carrying the token's hash and a
// live nonce of the org, and its jti is consumed like a PAP/1 proof's
// (replay: proof_replay; nonce missing or stale: use_nonce). A proof with
// an unbound token is refused: the gateway forwards one only for the DPoP
// scheme.
func (s *Service) identifyBearer(ctx context.Context, org ids.OrgID, in IdentifyInput) (Identified, error) {
	if !OAuthRoute(in.Request.URL) {
		return Identified{}, pap.Err(pap.CodeInvalidToken) // a pap-mcp+jwt on a PAP/1 route
	}
	v, err := s.McpVerifier()
	if err != nil {
		return Identified{}, err
	}
	tok, err := mcptoken.Verify(v, s.issuer, in.Request.Token, in.Request.URL, s.clk.Now())
	if err != nil {
		if errors.Is(err, mcptoken.ErrExpired) {
			return Identified{}, pap.Err(pap.CodeTokenExpired)
		}
		return Identified{}, pap.Err(pap.CodeInvalidToken)
	}
	if tok.Instance.Org != org {
		return Identified{}, pap.Err(pap.CodeInvalidToken)
	}
	out := Identified{Instance: tok.Instance, Environment: tok.Environment, Level: 0, Proof: mcptoken.ProofBearer, Bearer: &tok}
	switch {
	case tok.JKT == "" && in.Proof != "":
		return Identified{}, pap.Err(pap.CodeInvalidToken) // an unbound token under the DPoP scheme
	case tok.JKT != "" && in.Proof == "":
		return Identified{}, pap.Err(pap.CodeInvalidToken) // a bound token is never bearer (HR-700)
	case tok.JKT != "":
		if err := s.checkDPoP(ctx, org, in, tok); err != nil {
			return Identified{}, err
		}
		out.Proof, out.JKT = mcptoken.ProofDPoP, tok.JKT
	}
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetInstance(ctx, org, tok.Instance.Instance)
		if db.IsNoRows(err) || (err == nil && (r.AgentID != tok.Instance.Agent || r.State != "ADMITTED")) {
			return pap.Err(pap.CodeInstanceNotAdmitted)
		} else if err != nil {
			return err
		}
		var live bool
		switch tok.ClientKind {
		case ports.ClientAssertion:
			live, err = q.AssertionClientLive(ctx, org, tok.Client)
		case ports.ClientMcp:
			if r.EnrolledVia != EnrolledMcpClient {
				return pap.Err(pap.CodeInvalidToken)
			}
			live, err = q.McpClientLive(ctx, org, tok.Client)
		}
		if err != nil {
			return err
		}
		if !live {
			return pap.Err(pap.CodeInstanceNotAdmitted) // removed or disabled: cut off at once (HR-141)
		}
		access, err := q.GetOrgMcpAccess(ctx, org)
		if db.IsNoRows(err) || (err == nil && (!access.Enabled || access.GatewayUrl == nil)) {
			return pap.Err(pap.CodeInvalidToken)
		} else if err != nil {
			return err
		}
		if name, ok := iddomain.ConnectionOf(*access.GatewayUrl, tok.Resource); !ok || name != tok.Connection {
			return pap.Err(pap.CodeInvalidToken)
		}
		a, err := q.GetAgent(ctx, org, r.AgentID)
		if err != nil {
			return err
		}
		out.AgentState = a.State // the caller refuses an unusable agent
		return nil
	}, db.ReadOnly())
	var pe *pap.Error
	if errors.As(err, &pe) {
		return Identified{}, err
	}
	return out, err
}

// checkDPoP verifies the DPoP proof of a call with a DPoP-bound token (RFC
// 9449 §4.3, §7.1; G0 M30 D913): its key is the token's cnf.jkt, htm the
// request's method, htu the URL the token's aud was checked against, ath
// the token's hash; then its nonce must be live and its jti unseen, which
// Consume records in its own committed transaction (HR-090).
func (s *Service) checkDPoP(ctx context.Context, org ids.OrgID, in IdentifyInput, tok mcptoken.Token) error {
	c, err := pap.VerifyDPoP(in.Proof, pap.DPoPRequest{Method: in.Request.Method, URL: in.Request.URL, Token: in.Request.Token}, s.clk.Now())
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(c.JKT()), []byte(tok.JKT)) != 1 {
		return pap.Err(pap.CodeKeyMismatch)
	}
	if c.Nonce() == "" {
		return pap.Err(pap.CodeUseNonce)
	}
	return s.Consume(ctx, org, c)
}
