// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
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
func (s *Service) identifyBearer(ctx context.Context, org ids.OrgID, in IdentifyInput) (Identified, error) {
	if in.Proof != "" {
		return Identified{}, pap.Err(pap.CodeInvalidToken) // a bearer token carries no PAP/1 proof
	}
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
