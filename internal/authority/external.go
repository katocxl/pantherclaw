// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"errors"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
)

// External decisions (G0 M14 D28; PN-023, ADR-0019; HR-319, HR-320): an
// AuthZEN enforcement point in front of a target asks, and enforces the
// answer itself. This is the only path that decides an action of the
// authzen channel (D61): in one request it verifies the agent's forwarded
// PAP/1 credentials, runs the decision pipeline and its finalization, and
// for a permitted action commits it at BeginDispatch and records the
// outcome DELEGATED, exactly as the gateway does for a cooperative SDK
// call. Every reservation an allow made is committed then and never
// released early: the enforcement point never reports what the target
// did. A decision that cannot be bound tells the point to refuse.

// External outcomes, as the decision endpoint names them.
const (
	ExternalAllow           = "allow"
	ExternalObserve         = "observe"
	ExternalHold            = "hold"
	ExternalDeny            = "deny"
	ExternalCannotAuthorize = "cannot_authorize"
)

// Codes of refusals made after the decision.
const (
	// CodeDuplicate: the action was decided and dispatched already; it never
	// gets a second permit (HR-005).
	CodeDuplicate = "DUPLICATE"
	// CodeObligation: the decision carries obligations an enforcement point
	// cannot apply (HR-186).
	CodeObligation = "OBLIGATION_UNSUPPORTED"
	// CodeDispatchRefused: the commit point refused (kill switch, epoch,
	// expiry).
	CodeDispatchRefused = "DISPATCH_REFUSED"
	// CodeActionToken: a target-enforced connection's action token could
	// not be minted, so the target would refuse the request.
	CodeActionToken = "ACTION_TOKEN_UNAVAILABLE"
	// CodeNotRecorded: committed, but the delegated outcome could not be
	// recorded.
	CodeNotRecorded = "NOT_RECORDED"
	// CodeDecidedVia: who asked for the decision could not be recorded, so
	// nothing is committed (D65).
	CodeDecidedVia = "DECIDED_VIA_NOT_RECORDED"
)

// ExternalRequest is one decision an enforcement point asks for.
type ExternalRequest struct {
	// Gateway is the identity the decision binds to; its org is the
	// enforcement point's.
	Gateway Gateway
	// Action is the canonical ActionIR the server mapped from the request.
	Action actionir.Parsed
	// Credentials are the agent's PAP/1 credentials, rebuilt over the
	// request the point forwarded.
	Credentials *Credentials
	// Outbound is the request the point will forward, which a
	// target-enforced connection's action token binds (HR-188); zero for
	// any other connection.
	Outbound Outbound
	// TargetEnforced: the connection's target checks an action token.
	TargetEnforced bool
	// Decided runs once the decision has a transaction, before anything is
	// committed; an error refuses the action with CodeDecidedVia (it
	// records how the decision was asked for, D28, D65).
	Decided func(ctx context.Context, txn ids.UUID) error
}

// ExternalResult is the answer.
type ExternalResult struct {
	// Allowed is the AuthZEN decision.
	Allowed bool
	Outcome string
	// Code is the decisive reason code.
	Code          string
	Decision      domain.Decision
	TransactionID ids.UUID
	ActionHash    string
	// Receipt is the execution receipt of a delegated action, or else the
	// decision receipt.
	Receipt string
	// ActionToken is what the point attaches as PAP-Action for a
	// target-enforced connection.
	ActionToken string
	// Wait is the wait handle of a held action.
	Wait  *finalize.Wait
	Nonce string
	// Monitor: the route runs in monitor mode.
	Monitor bool
}

// Decide decides one action an enforcement point asks about. Every
// decision is counted by its outcome (pc_decisions_total, G0 M13 D30).
func (s *Service) Decide(ctx context.Context, req ExternalRequest) (ExternalResult, error) {
	res, err := s.decide(ctx, req)
	if err == nil {
		telemetry.Decision(ctx, string(res.Decision))
	}
	return res, err
}

func (s *Service) decide(ctx context.Context, req ExternalRequest) (ExternalResult, error) {
	if s.held {
		return ExternalResult{}, ErrMaintenanceHold
	}
	gw, p := req.Gateway, req.Action
	refuse := func(d domain.Decision, reasons []domain.Reason) ExternalResult {
		out := ExternalResult{Outcome: outcomeOf(d), Decision: d, ActionHash: p.HashHex(), Nonce: s.nonce(ctx, gw)}
		if len(reasons) > 0 {
			out.Code = reasons[0].Code
			for _, r := range reasons {
				if r.Decisive {
					out.Code = r.Code
					break
				}
			}
		}
		return out
	}
	if p.Action.Channel != "authzen" {
		return refuse(domain.CannotAuthorize, []domain.Reason{{Code: domain.ReasonAmbiguousInput, Decisive: true}}), nil
	}
	if org, err := p.Action.OrgID(); err != nil || org != gw.Org {
		return refuse(domain.Deny, []domain.Reason{{Code: domain.ReasonOrgMismatch, Decisive: true}}), nil //nolint:nilerr // a decision, not a failure
	}
	id, o, ok, err := s.identify(ctx, gw, p, req.Credentials)
	if err != nil {
		return ExternalResult{}, err
	}
	if !ok {
		return refuse(o.Decision, o.Reasons), nil
	}
	if s.decider == nil {
		return ExternalResult{}, errors.New("authority: the decision pipeline is not configured")
	}
	res, err := s.decider.Authorize(ctx, gw.final(), pipeline.Request{
		Org: gw.Org, Action: p,
		Identity: pipeline.Identity{InstanceID: id.Instance.Instance, AgentID: id.Instance.Agent, AttestationLevel: id.Level, JKT: id.JKT},
	})
	if err != nil {
		return ExternalResult{}, err
	}
	out := refuse(res.Decision, res.Reasons)
	out.TransactionID, out.Receipt, out.Wait = res.TransactionID, res.Receipt, res.Wait
	out.Monitor = res.Mode == pipeline.ModeMonitor
	if !res.TransactionID.IsZero() && req.Decided != nil {
		if err := req.Decided(ctx, res.TransactionID); err != nil {
			// Nothing is committed: a permit, if any, expires and its
			// reservations are released (D65).
			s.log.ErrorContext(ctx, "authzen.decided_via_not_recorded", slog.String("transaction_id", res.TransactionID.String()), pclog.Err(err))
			return failed(out, CodeDecidedVia), nil
		}
	}
	if res.Permit == "" {
		if res.Decision == domain.Allow || res.Decision == domain.AllowWithObligations {
			// A stored allow: the action was decided already (HR-005).
			out.Outcome, out.Code = ExternalCannotAuthorize, CodeDuplicate
		}
		return out, nil
	}
	if !out.Monitor && !allowed(res.Decision) {
		return failed(out, CodeDispatchRefused), nil
	}
	if !out.Monitor && enforcedObligations(res) {
		// An enforcement point forwards the request as the agent sent it:
		// it can honor no obligation (HR-186). The permit expires unused.
		return failed(out, CodeObligation), nil
	}
	var bound Outbound
	if req.TargetEnforced {
		bound = req.Outbound
	}
	token, err := s.decider.BeginDispatch(ctx, gw.final(), res.PermitID, res.Epoch, bound)
	if err != nil {
		s.log.WarnContext(ctx, "authzen.dispatch_refused", slog.String("transaction_id", res.TransactionID.String()), pclog.Err(err))
		return failed(out, CodeDispatchRefused), nil
	}
	ctx = context.WithoutCancel(ctx)
	outcome := Delegated
	if req.TargetEnforced && token == "" {
		// Committed, but the target would refuse the request: nothing may
		// be sent, so the outcome is FAILED.
		outcome = Failed
	}
	receipt, err := s.decider.RecordExecution(ctx, gw.final(), Execution{Permit: res.PermitID, Outcome: outcome, DispatchMS: -1})
	if err != nil {
		s.log.ErrorContext(ctx, "authzen.outcome_not_recorded", slog.String("transaction_id", res.TransactionID.String()), pclog.Err(err))
		return failed(out, CodeNotRecorded), nil
	}
	out.Receipt = receipt
	if outcome == Failed {
		return failed(out, CodeActionToken), nil
	}
	out.Allowed, out.ActionToken = true, token
	if out.Monitor {
		out.Outcome = ExternalObserve
	} else {
		out.Outcome = ExternalAllow
	}
	return out, nil
}

func allowed(d domain.Decision) bool { return d == domain.Allow || d == domain.AllowWithObligations }

// enforcedObligations reports obligations the enforcement point would have
// to apply: all but those the Authority applies itself after dispatch.
func enforcedObligations(res finalize.Result) bool {
	for _, o := range res.Obligations {
		if !o.ByAuthority() {
			return true
		}
	}
	return false
}

func failed(out ExternalResult, code string) ExternalResult {
	out.Allowed, out.Outcome, out.Code, out.ActionToken = false, ExternalCannotAuthorize, code, ""
	return out
}

// outcomeOf names a decision as the decision endpoint does.
func outcomeOf(d domain.Decision) string {
	switch d {
	case domain.Allow, domain.AllowWithObligations:
		return ExternalAllow
	case domain.RequireApproval, domain.RequireStepUp:
		return ExternalHold
	case domain.Deny:
		return ExternalDeny
	case domain.CannotAuthorize:
	}
	return ExternalCannotAuthorize
}
