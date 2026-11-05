// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/subtle"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// IdentifyInput are a workload request's PAP/1 credentials as a gateway
// forwarded them (PAP-1 §7.1). Request.URL comes from the gateway's
// configured public URL, never from a Host header.
type IdentifyInput struct {
	Request pap.Request
	Proof   string
	// ClientAddress is UNTRUSTED; it only feeds the network alert (HR-092).
	ClientAddress string
}

// Identified is the workload behind a verified request.
type Identified struct {
	Instance    pap.Instance
	Environment ids.UUID
	Level       int
	// JKT is the RFC 7638 thumbprint of the key that signed the proof.
	JKT string
	// AgentState is the agent's state after this request.
	AgentState string
	// Proof is how the request was proven: "" for a PAP/1 proof, "bearer"
	// for a pap-mcp+jwt (G0 M26 D402, HR-627), "dpop" for a DPoP-bound one
	// (G0 M30 D913; JKT is then its key).
	Proof string
	// Bearer is the verified MCP access token, set only when Proof is
	// "bearer" or "dpop".
	Bearer *mcptoken.Token
}

// Identify verifies a forwarded request for org (PAP-1 §4, §7.1; HR-021):
// the workload token and proof in the fixed order, a token of this org,
// then the proof is consumed in its own committed transaction, before any
// decision (HR-090). The token's instance must still be ADMITTED with the
// proof's key. A verified request is recorded: last seen, the HR-092
// network alert, and an agent's first verified request (VERIFIED →
// OBSERVED). Failures are pap errors: the request is unverifiable.
func (s *Service) Identify(ctx context.Context, org ids.OrgID, in IdentifyInput) (Identified, error) {
	if in.Request.Token == "" {
		return Identified{}, pap.Err(pap.CodeInvalidToken) // a key-only proof is an unknown workload
	}
	// The mode comes from the token's type alone, never from a missing
	// proof (D408): a pap-mcp+jwt is bearer, anything else is PAP/1, which
	// still requires its proof and refuses the OAuth route.
	if _, typ, err := jws.Unverified(in.Request.Token); err == nil && typ == mcptoken.TokenType {
		return s.identifyBearer(ctx, org, in)
	}
	if OAuthRoute(in.Request.URL) {
		return Identified{}, pap.Err(pap.CodeInvalidToken)
	}
	verifier, err := s.TokenVerifier()
	if err != nil {
		return Identified{}, err
	}
	c, err := pap.VerifyRequest(verifier, s.issuer, in.Request, in.Proof, s.clk.Now())
	if err != nil {
		return Identified{}, err
	}
	tok, ok := c.Token()
	if !ok || tok.Instance.Org != org {
		return Identified{}, pap.Err(pap.CodeInvalidToken)
	}
	if err := s.Consume(ctx, org, c); err != nil {
		return Identified{}, err
	}
	out := Identified{Instance: tok.Instance, Environment: tok.Environment, Level: tok.Level, JKT: c.JKT()}
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetInstance(ctx, org, tok.Instance.Instance)
		if db.IsNoRows(err) || (err == nil && (r.AgentID != tok.Instance.Agent || r.State != "ADMITTED" || r.EnrolledVia == EnrolledMcpClient || r.EnrolledVia == EnrolledFederation)) {
			return pap.Err(pap.CodeInstanceNotAdmitted)
		} else if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(r.Jkt), []byte(c.JKT())) != 1 {
			return pap.Err(pap.CodeKeyMismatch)
		}
		a, err := q.GetAgent(ctx, org, r.AgentID)
		if err != nil {
			return err
		}
		net, last := network(in.ClientAddress), deref(r.LastNetwork)
		if net == "" {
			net = last
		}
		seen, err := q.SeeInstance(ctx, optString(net), org, r.ID)
		if err != nil {
			return err
		}
		if seen == 1 && last != "" && net != last {
			if err := s.networkChanged(ctx, q, tx, r, a, last, net); err != nil {
				return err
			}
		}
		out.AgentState = a.State
		if adomain.State(a.State) == adomain.StateVerified {
			if err := agents.MarkObserved(ctx, q, org, a.ID, adomain.InstanceActor(r.ID)); err != nil {
				return err
			}
			out.AgentState = string(adomain.StateObserved)
		}
		return nil
	})
	return out, err
}
