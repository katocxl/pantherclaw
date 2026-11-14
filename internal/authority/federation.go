// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Federation calls (G0 M35 D1024c, D1024d, D1025). A peer organization's
// agent reaches one of this org's listed agents through the gateway's
// federation face: the gateway first asks StartFederatedCall, which
// verifies the peer's pap-fed+jwt once, ensures the federated agent's day
// run and stores a 60-second call record. The gateway then maps the request
// and asks Authorize with the call id instead of workload credentials. The
// call is single use and must match the action's run, instance,
// environment, connection and listing and the request's body digest and
// URL. Every decision on it carries a pap-fed-receipt+jwt signed at
// decision time (D1024d). Outbound, the gateway asks IssueFederationToken
// for an ALLOWED action and records the peer's answer receipt with
// RecordFederationReceipt.

// channelFederation is the federation face's channel.
const channelFederation = "federation"

// Federation reasons (decision reason codes).
const (
	ReasonFederationTokenInvalid = "FEDERATION_TOKEN_INVALID"
	ReasonFederationNotTrusted   = "FEDERATION_NOT_TRUSTED"
	ReasonFederationReplay       = "FEDERATION_REPLAY"
)

// FederatedCallInput is the gateway's StartFederatedCall request.
type FederatedCallInput struct {
	Credential string
	BodySHA256 [sha256.Size]byte
	HTU        string
	Listing    string
}

// FederatedCall is an admitted federation call.
type FederatedCall struct {
	ID                                    ids.UUID
	Run, Agent, Instance, Env, Connection ids.UUID
	TrustID, PeerOrg, ReceiptID           ids.UUID
	PeerAgent, PeerActionID, Listing, HTU string
	BodySHA256                            [sha256.Size]byte
	Expires                               time.Time
	AgentState, JKT                       string
	// AttLevel is the attestation level the trusted peer claimed for its
	// agent (R-86); the federated identity carries it.
	AttLevel int
	// PeerToken is the peer's pap-fed+jwt, stored as the IN receipt.
	PeerToken string
}

// FederationReceiptRecord is what RecordFederationReceipt recorded.
type FederationReceiptRecord struct {
	State, Decision, Reason, AgentText string
}

// Federation is the org federation store and signer
// (internal/federationkeys implements it).
type Federation interface {
	// StartCall verifies the token once and admits the call; refusals are
	// *errors.Error with a FEDERATION_* reason.
	StartCall(ctx context.Context, org ids.OrgID, gatewayID string, in FederatedCallInput) (FederatedCall, error)
	// UseCall consumes the call for action once; an unknown, used or
	// expired call, or one whose trust is no longer ACTIVE, is refused.
	UseCall(ctx context.Context, org ids.OrgID, call, action ids.UUID) (FederatedCall, error)
	// SignAnswer signs the pap-fed-receipt+jwt for a decision on the call.
	SignAnswer(ctx context.Context, org ids.OrgID, call FederatedCall, action ids.UUID, decision string) (string, error)
	// IssueToken signs a pap-fed+jwt for an ALLOWED outbound action.
	IssueToken(ctx context.Context, org ids.OrgID, gatewayID string, action ids.UUID, body [sha256.Size]byte, htu string) (string, time.Time, error)
	// RecordReceipt verifies and stores the peer's answer receipt.
	RecordReceipt(ctx context.Context, org ids.OrgID, gatewayID string, action ids.UUID, body [sha256.Size]byte, receipt string) (FederationReceiptRecord, error)
}

// WithFederation sets the federation store and signer and returns s; nil
// refuses every federation call (fail closed).
func (s *Service) WithFederation(f Federation) *Service {
	s.federation = f
	return s
}

var errFederationOff = pcerr.New(pcerr.FailedPrecondition, "FEDERATION_EDITION", "federation is not configured on this server")

// StartFederatedCall admits an inbound federation call.
func (s *Service) StartFederatedCall(ctx context.Context, gw Gateway, in FederatedCallInput) (FederatedCall, error) {
	if s.held {
		return FederatedCall{}, ErrMaintenanceHold
	}
	if s.federation == nil {
		return FederatedCall{}, errFederationOff
	}
	return s.federation.StartCall(ctx, gw.Org, gw.ID, in)
}

// federationChannel reports an action body on the federation channel.
func federationChannel(raw []byte) bool {
	p, err := actionir.Parse(raw)
	return err == nil && p.Action.Channel == channelFederation
}

// receiptDecision is a decision as a federation receipt states it.
func receiptDecision(d domain.Decision) string {
	switch d {
	case domain.Allow, domain.AllowWithObligations:
		return "ALLOW"
	case domain.RequireApproval, domain.RequireStepUp:
		return "HELD"
	case domain.Deny, domain.CannotAuthorize:
	}
	return "DENY"
}

// authorizeFederated decides a federation action admitted by a call. The
// returned receipt is empty only when no call could be tied to it.
func (s *Service) authorizeFederated(ctx context.Context, gw Gateway, raw []byte, callID string, creds *Credentials,
	content []pipeline.PayloadFinding, scan string, findings ...pipeline.PayloadFinding,
) (Result, string, error) {
	if s.held {
		return Result{}, "", ErrMaintenanceHold
	}
	refuse := func(d domain.Decision, code, detail, hash string) Result {
		return Result{Decision: d, ActionHash: hash, Reasons: []domain.Reason{{Code: code, Check: "identity", Detail: detail, Decisive: true}}}
	}
	p, perr := actionir.Parse(raw)
	if perr != nil {
		return refuse(domain.CannotAuthorize, domain.ReasonAmbiguousInput, "", ""), "", nil //nolint:nilerr // decision, not a failure
	}
	if org, oerr := p.Action.OrgID(); oerr != nil || org != gw.Org {
		return refuse(domain.Deny, domain.ReasonOrgMismatch, "", p.HashHex()), "", nil //nolint:nilerr // decision, not a failure
	}
	if p.Action.Channel != channelFederation {
		return refuse(domain.CannotAuthorize, domain.ReasonIdentityUnverified, "a federation call admits only a federation action", p.HashHex()), "", nil
	}
	if s.federation == nil || s.runs == nil || s.decider == nil {
		return Result{}, "", errFederationOff
	}
	callUUID, err1 := ids.ParseUUID(callID)
	action, err2 := ids.ParseUUID(p.Action.ActionID)
	if err1 != nil || err2 != nil {
		return refuse(domain.CannotAuthorize, ReasonFederationTokenInvalid, "", p.HashHex()), "", nil //nolint:nilerr // decision, not a failure
	}
	call, err := s.federation.UseCall(ctx, gw.Org, callUUID, action)
	if err != nil {
		if reason := pcerr.ReasonOf(err); reason != "" {
			return refuse(domain.CannotAuthorize, reason, "", p.HashHex()), "", nil
		}
		return Result{}, "", err
	}
	res, err := s.decideFederated(ctx, gw, p, call, creds, content, scan, findings...)
	if err != nil {
		return Result{}, "", err
	}
	receipt, err := s.federation.SignAnswer(ctx, gw.Org, call, action, receiptDecision(res.Decision))
	if err != nil {
		return Result{}, "", err
	}
	return res, receipt, nil
}

// decideFederated ties the action to its call, then runs the pipeline with
// the federated instance as the verified identity.
func (s *Service) decideFederated(ctx context.Context, gw Gateway, p actionir.Parsed, call FederatedCall, creds *Credentials,
	content []pipeline.PayloadFinding, scan string, findings ...pipeline.PayloadFinding,
) (Result, error) {
	a := p.Action
	mismatch := func(detail string) (Result, error) {
		s.log.WarnContext(ctx, "security.federation_call_mismatch", slog.String("gateway_id", gw.ID), slog.String("call_id", call.ID.String()))
		return Result{Decision: domain.Deny, ActionHash: p.HashHex(), Reasons: []domain.Reason{{
			Code: domain.ReasonIdentityMismatch, Check: "identity", Detail: detail, Decisive: true,
		}}}, nil
	}
	if creds == nil || subtle.ConstantTimeCompare(creds.BodySHA256[:], call.BodySHA256[:]) != 1 || creds.URL != call.HTU {
		return mismatch("the request is not the federation call's")
	}
	if a.RunID != call.Run.String() || a.AgentInstance != call.Instance.String() || a.Env != call.Env.String() ||
		a.Connection != call.Connection.String() || a.Target.ID != call.Listing {
		return mismatch("the action names another run, instance, environment, connection or listing than the federation call")
	}
	if !adomain.State(call.AgentState).Usable() {
		return Result{Decision: domain.Deny, ActionHash: p.HashHex(), Reasons: []domain.Reason{{
			Code: domain.ReasonAgentUnusable, Check: "identity", Detail: "the agent is suspended or retired", Decisive: true,
		}}}, nil
	}
	var pe *pap.Error
	if _, err := s.runs.Bind(ctx, gw.Org, call.Run, call.Agent, call.Instance); errors.As(err, &pe) {
		return Result{Decision: domain.Deny, ActionHash: p.HashHex(), Reasons: []domain.Reason{{
			Code: domain.ReasonRunMismatch, Check: "identity", Detail: string(pe.Code), Decisive: true,
		}}}, nil
	} else if err != nil {
		return Result{}, err
	}
	res, err := s.decider.Authorize(ctx, gw.final(), pipeline.Request{
		Org: gw.Org, Action: p, PayloadFindings: findings, ContentFindings: content, ContentScan: scan,
		Trace: traceFrom(ctx),
		Identity: pipeline.Identity{
			InstanceID: call.Instance, AgentID: call.Agent, AttestationLevel: call.AttLevel, JKT: call.JKT, Proof: channelFederation,
		},
	})
	if err != nil {
		return Result{}, err
	}
	return Result{
		Decision: res.Decision, Reasons: res.Reasons, TransactionID: res.TransactionID, ActionHash: res.ActionHash,
		Permit: res.Permit, PermitID: res.PermitID, Epoch: res.Epoch, Receipt: res.Receipt,
		Checklist: res.Checklist, Obligations: res.Obligations, EffectiveHash: res.EffectiveHash, BasisDigest: res.BasisDigest,
		Evaluation: res.Evaluation, Repeat: res.Repeat, Mode: res.Mode, AccessMode: res.AccessMode, Wait: res.Wait,
		Consequences: res.Consequences,
	}, nil
}

// StartFederatedCall implements AuthorityServiceHandler.
func (h *Handler) StartFederatedCall(ctx context.Context, req *pantherclawv1.StartFederatedCallRequest) (*pantherclawv1.StartFederatedCallResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	in := FederatedCallInput{Credential: req.GetCredential(), HTU: req.GetHtu(), Listing: req.GetListing()}
	copy(in.BodySHA256[:], req.GetBodySha256())
	c, err := h.svc.StartFederatedCall(ctx, gw, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.StartFederatedCallResponse{
		CallId: c.ID.String(), RunId: c.Run.String(), AgentId: c.Agent.String(), InstanceId: c.Instance.String(),
		Env: c.Env.String(), ConnectionId: c.Connection.String(), PeerActionId: c.PeerActionID,
		ExpireTime: timestamppb.New(c.Expires),
	}, nil
}

// IssueFederationToken implements AuthorityServiceHandler.
func (h *Handler) IssueFederationToken(ctx context.Context, req *pantherclawv1.IssueFederationTokenRequest) (*pantherclawv1.IssueFederationTokenResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	if h.svc.held {
		return nil, ErrMaintenanceHold
	}
	if h.svc.federation == nil {
		return nil, errFederationOff
	}
	action, err := ids.ParseUUID(req.GetActionId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "action_id must be a UUID")
	}
	var body [sha256.Size]byte
	copy(body[:], req.GetBodySha256())
	tok, exp, err := h.svc.federation.IssueToken(ctx, gw.Org, gw.ID, action, body, req.GetHtu())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.IssueFederationTokenResponse{Token: tok, ExpireTime: timestamppb.New(exp)}, nil
}

// RecordFederationReceipt implements AuthorityServiceHandler.
func (h *Handler) RecordFederationReceipt(ctx context.Context, req *pantherclawv1.RecordFederationReceiptRequest) (*pantherclawv1.RecordFederationReceiptResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	if h.svc.federation == nil {
		return nil, errFederationOff
	}
	action, err := ids.ParseUUID(req.GetActionId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "action_id must be a UUID")
	}
	var body [sha256.Size]byte
	copy(body[:], req.GetBodySha256())
	r, err := h.svc.federation.RecordReceipt(ctx, gw.Org, gw.ID, action, body, req.GetReceipt())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RecordFederationReceiptResponse{State: r.State, Decision: r.Decision, Reason: r.Reason, AgentText: r.AgentText}, nil
}
