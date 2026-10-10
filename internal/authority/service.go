// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package authority is the Transaction Authority service (ARCHITECTURE §6,
// ADR-0014). An action is first tied to the verified workload that sent it
// and to a run that workload may use (M3; HR-021, HR-022). Then the ten-step
// decision pipeline decides it and the finalization binds the decision
// (M4: internal/authority/pipeline and finalize): idempotency, repeat
// protection, every budget account and counter, the single-use permit and
// the signed decision receipt. The service also owns the BeginDispatch
// commit point, records execution outcomes and sweeps expired permits.
package authority

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// JOSE types of Authority-signed artifacts (PAP-1 §7.2, §9).
const (
	TypePermit           = finalize.TypePermit
	TypeDecisionReceipt  = finalize.TypeDecisionReceipt
	TypeExecutionReceipt = finalize.TypeExecutionReceipt
	DefaultPermitTTL     = finalize.DefaultPermitTTL
	DefaultStaleDispatch = 30 * time.Second
)

// Gateway is the authenticated gateway calling the Authority. Its org comes
// from the gateway's credential, never from the request (HR-020).
type Gateway struct {
	ID  string
	Org ids.OrgID
}

func (g Gateway) final() finalize.Gateway { return finalize.Gateway{ID: g.ID, Org: g.Org} }

// Service is the Transaction Authority.
type Service struct {
	decider *finalize.Authority
	log     *slog.Logger

	workloads Workloads
	runs      Runs
}

// Config configures the Service.
type Config struct {
	// Decider runs the decision pipeline and binds its decisions.
	Decider *finalize.Authority
	Logger  *slog.Logger
}

// New returns a Service.
func New(cfg Config) *Service {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{decider: cfg.Decider, log: log}
}

// Result is the answer to Authorize.
type Result struct {
	Decision      domain.Decision
	Reasons       []domain.Reason
	TransactionID ids.UUID
	ActionHash    string
	Permit        string // JWS; only for a fresh ALLOW
	PermitID      ids.UUID
	Epoch         int64
	Receipt       string // decision receipt JWS
	// Nonce is the org's current PAP/1 nonce, for the PAP-Nonce header.
	Nonce string
	// The explanation and what the decision bound (M4).
	Checklist     []pipeline.Item
	Obligations   []pdomain.Obligation
	EffectiveHash string
	BasisDigest   string
	Evaluation    int
	Repeat        bool
	// Mode is the route's mode and AccessMode the connection's (G0 M6).
	Mode, AccessMode string
	// Wait is the wait handle of a held action (G0 M5 part 2).
	Wait *finalize.Wait
}

// Authorize decides on raw canonical ActionIR bytes sent with the
// workload's PAP/1 credentials; without them it is CANNOT_AUTHORIZE.
func (s *Service) Authorize(ctx context.Context, gw Gateway, raw []byte, creds *Credentials) (Result, error) {
	p, perr := actionir.Parse(raw)
	if perr != nil {
		// Unparseable input cannot be bound to an org or action id: the answer
		// is the decision CANNOT_AUTHORIZE (not an RPC error), and no
		// transaction is recorded.
		return Result{Decision: domain.CannotAuthorize, Reasons: []domain.Reason{{ //nolint:nilerr // decision, not a failure
			Code: domain.ReasonAmbiguousInput, Check: "exact_meaning", Decisive: true,
		}}}, nil
	}
	if org, oerr := p.Action.OrgID(); oerr != nil || org != gw.Org {
		s.log.WarnContext(ctx, "authz.org_mismatch", slog.String("gateway_id", gw.ID))
		// A decision, not an error: the gateway asserted another org (HR-020).
		return Result{Decision: domain.Deny, ActionHash: p.HashHex(), Reasons: []domain.Reason{{ //nolint:nilerr // decision, not a failure
			Code: domain.ReasonOrgMismatch, Check: "identity", Decisive: true,
		}}}, nil
	}
	id, o, ok, err := s.identify(ctx, gw, p, creds)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		s.log.InfoContext(ctx, "authz.decision", slog.String("decision", string(o.Decision)), slog.String("reason_code", o.Decisive()))
		return Result{Decision: o.Decision, ActionHash: p.HashHex(), Reasons: o.Reasons, Nonce: s.nonce(ctx, gw)}, nil
	}
	if s.decider == nil {
		return Result{}, errors.New("authority: the decision pipeline is not configured")
	}
	res, err := s.decider.Authorize(ctx, gw.final(), pipeline.Request{
		Org: gw.Org, Action: p,
		Identity: pipeline.Identity{InstanceID: id.Instance.Instance, AgentID: id.Instance.Agent, AttestationLevel: id.Level, JKT: id.JKT},
	})
	if err != nil {
		return Result{}, err
	}
	return Result{
		Decision: res.Decision, Reasons: res.Reasons, TransactionID: res.TransactionID, ActionHash: res.ActionHash,
		Permit: res.Permit, PermitID: res.PermitID, Epoch: res.Epoch, Receipt: res.Receipt, Nonce: s.nonce(ctx, gw),
		Checklist: res.Checklist, Obligations: res.Obligations, EffectiveHash: res.EffectiveHash, BasisDigest: res.BasisDigest,
		Evaluation: res.Evaluation, Repeat: res.Repeat, Mode: res.Mode, AccessMode: res.AccessMode, Wait: res.Wait,
	}, nil
}

// Dispatch errors (the gateway must not dispatch on any of them).
var (
	ErrPermitUnknown  = finalize.ErrPermitUnknown
	ErrPermitUsed     = finalize.ErrPermitUsed
	ErrPermitExpired  = finalize.ErrPermitExpired
	ErrEpochStale     = finalize.ErrEpochStale
	ErrKillSwitch     = finalize.ErrKillSwitch
	ErrNotDispatching = finalize.ErrNotDispatching
)

// BeginDispatch is the commit point (HR-001). It succeeds only if the
// permit moved ISSUED → DISPATCHING; any error means "do not dispatch". It
// records out and returns the action token of a target-enforced dispatch
// (HR-188).
func (s *Service) BeginDispatch(ctx context.Context, gw Gateway, permit ids.UUID, epoch int64, out Outbound) (string, error) {
	return s.decider.BeginDispatch(ctx, gw.final(), permit, epoch, out)
}

// Outbound is the request a gateway is about to send (PAP-1 §7.3).
type Outbound = finalize.Outbound

// Outcome of a dispatch.
type Outcome = finalize.Outcome

// Dispatch outcomes (PAP-1 §7.4).
const (
	Accepted = finalize.Accepted
	Failed   = finalize.Failed
	Unknown  = finalize.Unknown
	// Delegated: a cooperative channel's agent performed the action (HR-186).
	Delegated = finalize.Delegated
)

// Execution describes one dispatch attempt.
type Execution = finalize.Execution

// RecordExecution records the outcome of a DISPATCHING permit: accepted
// commits every reservation, failed releases them, unknown keeps them held
// and leaves the permit UNKNOWN for reconciliation (HR-003). It returns the
// signed execution receipt.
func (s *Service) RecordExecution(ctx context.Context, gw Gateway, e Execution) (string, error) {
	return s.decider.RecordExecution(ctx, gw.final(), e)
}

// SweepResult counts what one sweep changed.
type SweepResult struct {
	Released int // expired ISSUED permits whose reservations were released
	Unknown  int // stale DISPATCHING permits moved to UNKNOWN (reservations kept)
	Applied  int // settled reservations applied to their budget rows (ADR-0015)
}

// SweepOrg releases expired ISSUED permits and marks stale DISPATCHING ones
// UNKNOWN, never releasing them (HR-003). Then it applies the settled
// reservations, those it released and those outcomes recorded, to their
// budget account and counter rows (ADR-0015).
func (s *Service) SweepOrg(ctx context.Context, org ids.OrgID, staleAfter time.Duration) (SweepResult, error) {
	released, unknown, err := s.decider.Sweep(ctx, org, staleAfter)
	r := SweepResult{Released: released, Unknown: unknown}
	if r.Unknown > 0 {
		s.log.WarnContext(ctx, "authz.dispatch_unknown", slog.String("org_id", org.String()), slog.Int("count", r.Unknown))
	}
	if err != nil {
		return r, err
	}
	r.Applied, err = s.decider.Store.ApplySettlements(ctx, org)
	return r, err
}

// Workloads identifies the workload behind forwarded PAP/1 credentials and
// serves nonces (identity app).
type Workloads interface {
	Identify(ctx context.Context, org ids.OrgID, in iapp.IdentifyInput) (iapp.Identified, error)
	NonceExpiry(ctx context.Context, org ids.OrgID) (string, time.Time, error)
	Discover(ctx context.Context, org ids.OrgID, in iapp.DiscoverInput) (ids.UUID, error)
}

// Runs checks and binds runs (runs app). Bind returns when the run expires.
type Runs interface {
	Bind(ctx context.Context, org ids.OrgID, run, agent, instance ids.UUID) (time.Time, error)
}

// WithWorkloads sets the workload identity and run checks (M3) and returns
// s.
func (s *Service) WithWorkloads(w Workloads, r Runs) *Service {
	s.workloads, s.runs = w, r
	return s
}

// Credentials are a workload request's PAP/1 credentials as the gateway
// received them (WorkloadCredentials, PAP-1 §4).
type Credentials struct {
	Token      string
	Proof      string
	BodySHA256 [sha256.Size]byte
	Method     string
	URL        string
	// ClientAddress is UNTRUSTED (HR-092 network alert only).
	ClientAddress string
}

func identityOutcome(d domain.Decision, code, detail string) domain.Outcome {
	return domain.Outcome{Decision: d, Reasons: []domain.Reason{{Code: code, Check: "identity", Detail: detail, Decisive: true}}}
}

// identify checks the workload behind an action before anything is decided
// or recorded (PAP-1 §7.1; HR-021, HR-022): an unverifiable workload is
// CANNOT_AUTHORIZE, a suspended or retired agent, an action naming another
// instance or environment, and a run it may not use are DENY. None of them
// is finalized, so a workload can never spend the (run, action) key of
// another. ok reports that the action may proceed to the pipeline, with
// the verified identity.
func (s *Service) identify(ctx context.Context, gw Gateway, p actionir.Parsed, c *Credentials) (iapp.Identified, domain.Outcome, bool, error) {
	if c == nil {
		return iapp.Identified{}, identityOutcome(domain.CannotAuthorize, domain.ReasonIdentityUnverified, string(pap.CodeInvalidToken)), false, nil
	}
	if s.workloads == nil || s.runs == nil {
		return iapp.Identified{}, domain.Outcome{}, false, errors.New("authority: workload identity is not configured")
	}
	id, err := s.workloads.Identify(ctx, gw.Org, iapp.IdentifyInput{
		Request: pap.Request{Method: c.Method, URL: c.URL, BodySHA256: c.BodySHA256, Token: c.Token},
		Proof:   c.Proof, ClientAddress: c.ClientAddress,
	})
	var pe *pap.Error
	switch {
	case errors.As(err, &pe):
		return id, identityOutcome(domain.CannotAuthorize, domain.ReasonIdentityUnverified, string(pe.Code)), false, nil
	case err != nil:
		return id, domain.Outcome{}, false, err
	}
	if !adomain.State(id.AgentState).Usable() {
		return id, identityOutcome(domain.Deny, domain.ReasonAgentUnusable, "the agent is suspended or retired"), false, nil
	}
	if p.Action.AgentInstance != id.Instance.Instance.String() || p.Action.Env != id.Environment.String() {
		s.log.WarnContext(ctx, "security.identity_mismatch", slog.String("gateway_id", gw.ID),
			slog.String("instance_id", id.Instance.Instance.String()))
		return id, identityOutcome(domain.Deny, domain.ReasonIdentityMismatch, "the action names another instance or environment"), false, nil
	}
	run, _ := ids.ParseUUID(p.Action.RunID)
	if _, err := s.runs.Bind(ctx, gw.Org, run, id.Instance.Agent, id.Instance.Instance); errors.As(err, &pe) {
		s.log.WarnContext(ctx, "security.run_mismatch", slog.String("gateway_id", gw.ID),
			slog.String("instance_id", id.Instance.Instance.String()), slog.String("run_id", run.String()))
		return id, identityOutcome(domain.Deny, domain.ReasonRunMismatch, string(pe.Code)), false, nil
	} else if err != nil {
		return id, domain.Outcome{}, false, err
	}
	return id, domain.Outcome{}, true, nil
}

// Verified is a workload whose credentials verified for a request that
// decides nothing (VerifyWorkload).
type Verified struct {
	Instance, Environment ids.UUID
	// JKT is the thumbprint of the key that signed the request.
	JKT string
	// RunExpires is when the run named in the request expires; zero when
	// no run was named.
	RunExpires time.Time
}

// ErrAgentUnusable reports a verified workload whose agent is suspended or
// retired.
var ErrAgentUnusable = errors.New("authority: the agent is suspended or retired")

// Verify checks a workload's PAP/1 credentials for a request that decides
// nothing, such as an MCP tools/list (HR-021): the token, the proof over
// this request (consumed, so it cannot be replayed into an action), and
// that the agent is usable. When the request names a run, the instance must
// be allowed to use it, as for an action (HR-022; its first use binds it),
// and Verified says when it expires: an MCP session lives on a run (G0 M6
// design decision 13). Nothing else is recorded. A failed proof or a run
// the instance may not use is a *pap.Error; a suspended or retired agent
// is ErrAgentUnusable.
func (s *Service) Verify(ctx context.Context, gw Gateway, c *Credentials, run ids.UUID) (Verified, error) {
	if c == nil {
		return Verified{}, &pap.Error{Code: pap.CodeInvalidToken}
	}
	if s.workloads == nil || (!run.IsZero() && s.runs == nil) {
		return Verified{}, errors.New("authority: workload identity is not configured")
	}
	id, err := s.workloads.Identify(ctx, gw.Org, iapp.IdentifyInput{
		Request: pap.Request{Method: c.Method, URL: c.URL, BodySHA256: c.BodySHA256, Token: c.Token},
		Proof:   c.Proof, ClientAddress: c.ClientAddress,
	})
	if err != nil {
		return Verified{}, err
	}
	if !adomain.State(id.AgentState).Usable() {
		return Verified{}, ErrAgentUnusable
	}
	v := Verified{Instance: id.Instance.Instance, Environment: id.Environment, JKT: id.JKT}
	if !run.IsZero() {
		if v.RunExpires, err = s.runs.Bind(ctx, gw.Org, run, id.Instance.Agent, id.Instance.Instance); err != nil {
			if errors.As(err, new(*pap.Error)) {
				s.log.WarnContext(ctx, "security.run_mismatch", slog.String("gateway_id", gw.ID),
					slog.String("instance_id", id.Instance.Instance.String()), slog.String("run_id", run.String()))
			}
			return Verified{}, err
		}
	}
	return v, nil
}

// Nonce returns the org's current PAP/1 nonce and its expiry, or "" when
// workload identity is not configured.
func (s *Service) Nonce(ctx context.Context, gw Gateway) (string, time.Time, error) {
	if s.workloads == nil {
		return "", time.Time{}, nil
	}
	return s.workloads.NonceExpiry(ctx, gw.Org)
}

// nonce is Nonce for a response: a failure only leaves the header out.
func (s *Service) nonce(ctx context.Context, gw Gateway) string {
	n, _, err := s.Nonce(ctx, gw)
	if err != nil {
		s.log.WarnContext(ctx, "authz.nonce_unavailable", slog.String("gateway_id", gw.ID))
	}
	return n
}

// UnknownWorkload is a gateway's report of a request it could not tie to an
// admitted instance (HR-148). The observations are UNTRUSTED.
type UnknownWorkload struct {
	Credentials
	Route, UserAgent string
}

// ReportUnknown records the report as a discovery after verifying its
// key-only proof; the request itself stays refused. The zero id means the
// sighting was only counted.
func (s *Service) ReportUnknown(ctx context.Context, gw Gateway, u UnknownWorkload) (ids.UUID, error) {
	if s.workloads == nil {
		return ids.UUID{}, errors.New("authority: workload identity is not configured")
	}
	return s.workloads.Discover(ctx, gw.Org, iapp.DiscoverInput{
		Request: pap.Request{Method: u.Method, URL: u.URL, BodySHA256: u.BodySHA256, Token: u.Token},
		Proof:   u.Proof, Gateway: gw.ID, Route: u.Route, ClientAddress: u.ClientAddress, UserAgent: u.UserAgent,
	})
}
