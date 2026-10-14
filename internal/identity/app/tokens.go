// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/subtle"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// TokenInput is a workload's token request (PAP-1 §3.4).
type TokenInput struct {
	// Proof is the verified key-only proof of the request.
	Proof      pap.Checked
	Identifier string
	// Attestation is an optional fresh attestation that renews L2; it must
	// match the binding the instance enrolled with (HR-147).
	Attestation *Attestation
	// DeclaredRelease is what the workload reports about itself; it is
	// always "declared" and never replaces an attested digest.
	DeclaredRelease string
	ClientAddress   string
}

// Issued is a workload token.
type Issued struct {
	Token     string
	ExpiresAt time.Time
	Level     int
}

// IssueToken issues a workload token to an admitted instance whose key
// signed the proof. The level is L2 only while the instance's attestation
// is current, its issuer entry still active, and never for a desktop
// agent (HR-092, HR-141, HR-143); the token never outlives that
// attestation. A fresh attestation renews L2 only with exactly the binding
// the instance enrolled with (HR-147); its digest, when the preset reads
// one, becomes the attested release. A changed release digest is drift
// (F033): the instance is flagged for review. A request from a new network
// writes the alert event (HR-092).
func (s *Service) IssueToken(ctx context.Context, in TokenInput) (Issued, error) {
	id, err := pap.ParseInstance(in.Identifier)
	if err != nil {
		return Issued{}, err
	}
	if _, ok := in.Proof.Token(); ok {
		return Issued{}, pap.Err(pap.CodeInvalidProof) // token issuance uses a key-only proof
	}
	if err := s.Consume(ctx, id.Org, in.Proof); err != nil {
		return Issued{}, err
	}
	var cands []attested
	if in.Attestation != nil {
		if cands, err = s.attest(ctx, id.Org, *in.Attestation); err != nil {
			return Issued{}, err
		}
	}
	signer, err := s.keys.Signer(keys.PurposeWorkloadTokens)
	if err != nil {
		return Issued{}, err
	}
	var out Issued
	err = s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockInstance(ctx, id.Org, id.Instance)
		if db.IsNoRows(err) || (err == nil && r.AgentID != id.Agent) {
			return pap.Err(pap.CodeInvalidToken)
		} else if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(r.Jkt), []byte(in.Proof.JKT())) != 1 {
			return pap.Err(pap.CodeKeyMismatch)
		}
		if r.State != "ADMITTED" {
			return pap.Err(pap.CodeInstanceNotAdmitted)
		}
		// A sandbox instance acts only inside its open session (G0 M9
		// design decision 9): no token once the session ended or expired.
		if r.EnrollmentTokenID != nil {
			open, err := q.SandboxSessionOpenForToken(ctx, id.Org, *r.EnrollmentTokenID)
			if err == nil && !open {
				return pap.Err(pap.CodeInstanceNotAdmitted)
			} else if err != nil && !db.IsNoRows(err) {
				return err
			}
		}
		a, err := q.GetAgent(ctx, id.Org, r.AgentID)
		if err != nil {
			return err
		}
		if !agentUsable(a) || a.EnvironmentID == nil || a.ExecutionContext == nil {
			return pap.Err(pap.CodeInstanceNotAdmitted)
		}
		var active *dbq.PcTrustedIssuer
		if r.IssuerRevisionID != nil {
			if rev, err := q.ActiveRevisionFor(ctx, id.Org, *r.IssuerRevisionID); err == nil {
				active = &rev
			} else if !db.IsNoRows(err) {
				return err
			}
		}
		relState, relDigest, drift := release(r, in.DeclaredRelease)
		if in.Attestation != nil {
			fresh, err := reattest(cands, r, active)
			if err != nil {
				return err
			}
			if err := fresh.record(ctx, q, id.Org, r.ID); err != nil {
				return err
			}
			if r, err = q.AttestInstance(ctx, &fresh.window.ExpiresAt, id.Org, r.ID); err != nil {
				return err
			}
			if d := fresh.match.ReleaseDigest; d != "" {
				prev := deref(r.ReleaseDigest)
				relState, relDigest, drift = ptr(pap.ReleaseAttested), &d, prev != "" && prev != d
			}
		}
		now := s.clk.Now()
		level, notAfter := 1, time.Time{}
		if r.AttLevel == 2 && active != nil && r.AttestedUntil != nil && r.AttestedUntil.After(now) && maxLevel(a) >= 2 {
			level, notAfter = 2, *r.AttestedUntil
		}
		net := network(in.ClientAddress)
		lastNet := deref(r.LastNetwork)
		if net == "" {
			net = lastNet
		}
		if _, err := q.TouchInstance(ctx, dbq.TouchInstanceParams{
			OrgID: id.Org, ID: r.ID, LastNetwork: optString(net), ReleaseState: relState, ReleaseDigest: relDigest, Drift: drift,
		}); err != nil {
			return err
		}
		if drift {
			if err := agents.RecordChange(ctx, q, id.Org, a.ID, adomain.Change{
				Kind: adomain.ChangeInstanceDrift, Actor: adomain.InstanceActor(r.ID),
				Details: map[string]string{"instance_id": r.ID.String(), "release_digest": deref(relDigest)},
			}); err != nil {
				return err
			}
		}
		if lastNet != "" && net != lastNet {
			if err := s.networkChanged(ctx, q, tx, r, a, lastNet, net); err != nil {
				return err
			}
		}
		compact, tok, err := pap.Issue(signer, s.issuer, pap.Token{
			Instance: id, Environment: *a.EnvironmentID, JKT: r.Jkt, Level: level,
			ReleaseState: deref(relState), ReleaseDigest: deref(relDigest),
		}, now, notAfter)
		if err != nil {
			return err
		}
		out = Issued{Token: compact, ExpiresAt: tok.ExpiresAt, Level: level}
		return nil
	})
	return out, err
}

// release decides the release identity after a token request: an attested
// digest stays; a declared one follows what the workload now reports; any
// change of digest is drift (F033).
func release(r dbq.PcAgentInstance, declared string) (*string, *string, bool) {
	state, digest := deref(r.ReleaseState), deref(r.ReleaseDigest)
	if state == pap.ReleaseAttested || declared == "" {
		return r.ReleaseState, r.ReleaseDigest, false
	}
	drift := digest != "" && digest != declared
	return ptr(pap.ReleaseDeclared), &declared, drift
}

// networkChanged writes the HR-092 alert: the same key from a new network.
// Detections arrive in M10; until then the audit event is the alert.
func (s *Service) networkChanged(ctx context.Context, q *dbq.Queries, tx db.TenantTx, r dbq.PcAgentInstance, a dbq.PcAgent, from, to string) error {
	if err := agents.RecordChange(ctx, q, r.OrgID, a.ID, adomain.Change{
		Kind: adomain.ChangeInstanceNetwork, Actor: adomain.System,
		Details: map[string]string{"instance_id": r.ID.String(), "from_network": from, "to_network": to},
	}); err != nil {
		return err
	}
	return recordAs(ctx, tx, evdomainSystem(), "security.instance_network_changed", "instance", r.ID,
		map[string]string{"agent_id": a.ID.String(), "from_network": from, "to_network": to})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
