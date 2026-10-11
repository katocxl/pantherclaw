// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Reason codes of the pipeline itself (the grant, budget and fact codes
// come from their packages).
const (
	ReasonDefinitionNotPinned  = "DEFINITION_NOT_PINNED"
	ReasonRouteUnknown         = "ROUTE_UNKNOWN"
	ReasonRouteReviewed        = "ROUTE_REVIEWED"
	ReasonRunMismatch          = "RUN_MISMATCH"
	ReasonRunNotActive         = "RUN_NOT_ACTIVE"
	ReasonIdentityVerified     = "IDENTITY_VERIFIED"
	ReasonAgentSuspended       = "AGENT_SUSPENDED"
	ReasonPackageQuarantined   = "PACKAGE_QUARANTINED"
	ReasonNotContained         = "NOT_CONTAINED"
	ReasonGrantCovers          = "GRANT_COVERS"
	ReasonDefinitionNotActive  = "DEFINITION_NOT_ACTIVE"
	ReasonDefinitionStale      = "DEFINITION_STALE"
	ReasonMeaningExact         = "MEANING_EXACT"
	ReasonFactsFresh           = "FACTS_FRESH"
	ReasonWithinBoundaries     = "WITHIN_BOUNDARIES"
	ReasonRequirementsMet      = "REQUIREMENTS_MET"
	ReasonReconciliation       = "RECONCILIATION_REQUIRED"
	ReasonEvidenceUnavailable  = "EVIDENCE_UNAVAILABLE"
	ReasonPolicyEvaluation     = "POLICY_EVALUATION_ERROR"
	ReasonRulesNotApplicable   = "RULES_NOT_APPLICABLE"
	ReasonGrantRequiresHold    = "GRANT_REQUIRES_APPROVAL"
	ReasonGrantRequiresStepUp  = "GRANT_REQUIRES_STEP_UP"
	ReasonActionInstanceDiffer = "ACTION_INSTANCE_MISMATCH"
	ReasonConnectionUnknown    = "CONNECTION_UNKNOWN"
	ReasonConnectionRequired   = "CONNECTION_REQUIRED"
	ReasonConnectionContained  = "CONNECTION_QUARANTINED"
	// ReasonVerifierUnsupported: the effect must be verified at a level
	// (the definition's verifier.required, or a policy's verify obligation)
	// that its verifier cannot reach, or through a connection that cannot
	// make the verifier's reads (F497, HR-191).
	ReasonVerifierUnsupported = "VERIFIER_UNSUPPORTED"
)

// Pipeline evaluates steps 1–8.
type Pipeline struct {
	Reader Reader
}

// IdentitySummary is the identity part of a decision receipt (ids only).
type IdentitySummary struct {
	Instance         string `json:"instance"`
	AttestationLevel int    `json:"att_lvl"`
	Agent            string `json:"agent"`
	Run              string `json:"run"`
	Launcher         string `json:"launcher,omitzero"`
	Principal        string `json:"principal,omitzero"`
}

// Evaluation is the result of steps 1–8: the decision before final
// binding, its explanation, and what the finalization must bind.
type Evaluation struct {
	Decision    adomain.Decision
	Checklist   []Item
	Obligations []pdomain.Obligation
	Approvals   []pdomain.ApprovalRequirement
	StepUps     []pdomain.StepUpRequirement
	// Requirements are the same requirements, each with its source (a grant
	// or guardrail level, or a policy rule), as step 8 found them.
	Requirements []apdomain.Input
	// Hold is what step 8 established about approvals: the binding a hold
	// records or an approval must match, or the request that ended the
	// action (G0 M5 part 2). Nil when nothing was required or asked for.
	Hold   *Hold
	Labels map[string]string
	// ActionHash is the requested action; EffectiveHash differs when an
	// obligation clamps a parameter (F104, F107).
	ActionHash    string
	EffectiveHash string
	Basis         Basis
	Identity      IdentitySummary
	// What the finalization binds (step 9).
	Org          ids.OrgID
	RunID        ids.UUID
	ActionID     ids.UUID
	Operation    string
	Chain        gdomain.Chain
	Plan         gdomain.Plan
	Amount       *money.Money
	DedupeKey    string
	RepeatWindow time.Duration
	Epoch        int64
	Now          time.Time
	// Rows are the rows of Plan that step 7 found (a row that does not
	// exist yet has none), so the finalization need not ensure them first.
	Rows Rows
	// Mode is the route's mode on the action's connection: ModeMonitor only
	// when step 1 resolved a connection whose route runs in monitor mode;
	// ModeEnforce otherwise (G0 M6 decision 7, HR-184).
	Mode string
	// Connection is the connection the action came through, when it names
	// one and step 1 accepted it.
	Connection *Connection
	// Channel and Target are the action's, for the transaction record.
	Channel string
	Target  actionir.Target
	// Verify is what the effect of a permit is verified against (G0 M7,
	// HR-191), set when step 8 knew the definition; the permit records it.
	Verify *VerifyPlan
}

// VerifyPlan is fixed when a permit is issued: the digest of the
// definition the decision used, the level it requires, and the values an
// extended verifier must observe, from the effective action. A verification
// task is built from it, never from what a target or an agent says.
type VerifyPlan struct {
	DefinitionDigest string
	Required         defs.Level
	// Expected is nil when the definition's verifier compares no fields.
	Expected map[string]string
}

// Hold is step 8's view of the transaction's approval request.
type Hold struct {
	// Requirements are the merged requirements; Deadline, Display and
	// Binding what a request records (or an approval must match).
	Requirements []apdomain.Requirement
	Deadline     time.Time
	Display      apdomain.Display
	DisplayHash  [32]byte
	Binding      apdomain.Binding
	VariantKey   [32]byte
	// Action is the canonical action held, which a narrower proposal is
	// checked against (HR-172).
	Action []byte
	// Request is the transaction's latest request, as read (nil: none).
	Request *HoldRequest
	// Keep: Request is live and has this binding, so nothing new is
	// recorded. Satisfied: it is APPROVED, so the finalization that issues
	// the permit consumes it (HR-031, HR-171).
	Keep, Satisfied bool
	// Expire: Request expired at use; the finalization records that.
	Expire bool
	// State and Code are what a waiter sees (HR-174).
	State string
	Code  string
}

// Permits reports whether the evaluation allows dispatch.
func (e *Evaluation) Permits() bool { return e.Decision.Permits() }

// MonitorPermit reports whether a monitor-mode permit is issued (HR-184):
// the route runs in monitor mode and neither identity (step 2) nor
// containment (step 3) failed. The decision is then hypothetical: policy,
// budgets and requirements never block, nothing is reserved, and nothing
// is reported as prevented.
func (e *Evaluation) MonitorPermit() bool {
	if e.Mode != ModeMonitor {
		return false
	}
	for _, it := range e.Checklist {
		if (it.Step == StepScope || it.Step == StepIdentity || it.Step == StepContainment) &&
			(it.Status == StatusFailed || it.Status == StatusMissing) {
			return false
		}
	}
	return true
}

// Decisive returns the decisive checklist item.
func (e *Evaluation) Decisive() Item {
	if len(e.Checklist) > 0 && e.Checklist[0].Decisive {
		return e.Checklist[0]
	}
	return Item{Code: "UNEXPLAINED"}
}

// state carries what earlier steps established.
type state struct {
	req     Request
	a       actionir.ActionIR
	cl      checklist
	ev      *Evaluation
	cont    Containment
	pinned  *Pinned
	conn    *Connection
	def     *defs.Definition
	run     *Run
	agent   *Agent
	chain   gdomain.Chain
	policy  *Policy
	vals    defs.Values
	gAction *gdomain.Action
	facts   map[string]fdomain.Value
	used    []fdomain.Fact
	covered bool
}

// Snapshot calls fn with a Reader whose reads all come from one snapshot
// when the Pipeline's Reader is a Snapshotter, and with that Reader itself
// otherwise.
func (p *Pipeline) Snapshot(ctx context.Context, org ids.OrgID, fn func(ctx context.Context, r Reader) error) error {
	if s, ok := p.Reader.(Snapshotter); ok {
		return s.Snapshot(ctx, org, fn)
	}
	return fn(ctx, p.Reader)
}

// Evaluate runs steps 1–8 on one snapshot (see Snapshot).
func (p *Pipeline) Evaluate(ctx context.Context, req Request) (*Evaluation, error) {
	var ev *Evaluation
	err := p.Snapshot(ctx, req.Org, func(ctx context.Context, r Reader) error {
		var err error
		ev, err = p.EvaluateWith(ctx, r, req)
		return err
	})
	return ev, err
}

// EvaluateWith runs steps 1–8, reading through r (a snapshot's Reader). It
// returns an error only when the database time cannot be read; every other
// failure to read evidence is a MISSING item, so the decision cannot be
// ALLOW (fail closed, invariant 8).
func (p *Pipeline) EvaluateWith(ctx context.Context, r Reader, req Request) (*Evaluation, error) {
	in := *p
	in.Reader = r
	return in.evaluate(ctx, req)
}

func (p *Pipeline) evaluate(ctx context.Context, req Request) (*Evaluation, error) {
	cont, err := p.Reader.Containment(ctx, req.Org)
	if err != nil {
		return nil, fmt.Errorf("pipeline: containment: %w", err)
	}
	s := &state{req: req, a: req.Action.Action, cont: cont, ev: &Evaluation{
		Org: req.Org, ActionHash: req.Action.HashHex(), Operation: req.Action.Action.Operation, Epoch: cont.Epoch, Now: cont.Now,
		Mode: ModeEnforce, Channel: req.Action.Action.Channel, Target: req.Action.Action.Target,
	}}
	s.ev.EffectiveHash = s.ev.ActionHash
	s.ev.RunID, _ = ids.ParseUUID(s.a.RunID)
	s.ev.ActionID, _ = ids.ParseUUID(s.a.ActionID)
	p.scope(ctx, s)
	p.identity(ctx, s)
	p.containment(s)
	p.authority(s)
	p.meaning(s)
	p.currentFacts(ctx, s)
	p.boundaries(ctx, s)
	p.requirements(ctx, s)
	s.ev.Decision, s.ev.Checklist = s.cl.compose(s.covered)
	s.ev.Basis = s.basis()
	return s.ev, nil
}

func (s *state) missing(step int, err error, what string) {
	s.cl.add(step, adomain.CannotAuthorize, ReasonEvidenceUnavailable, what+" could not be read", "")
	_ = err // never shown: it may describe storage
}

// Step 1: the action pins a definition the org has pinned, through one of
// its reviewed routes.
func (p *Pipeline) scope(ctx context.Context, s *state) {
	pinned, err := p.Reader.Definition(ctx, s.req.Org, s.a.Definition)
	switch {
	case errors.Is(err, ErrNotFound):
		s.cl.add(StepScope, adomain.CannotAuthorize, ReasonDefinitionNotPinned,
			fmt.Sprintf("%s@%s is not a definition this org has pinned", s.a.Definition.Package, s.a.Definition.Version), "")
		return
	case err != nil:
		s.missing(StepScope, err, "the definition")
		return
	}
	s.pinned = &pinned
	d := pinned.Definition
	if d.Operation != s.a.Operation || d.Digest != s.a.Definition.Digest {
		s.cl.add(StepScope, adomain.CannotAuthorize, ReasonRouteUnknown, "the action does not match the pinned definition", "")
		return
	}
	known := slices.ContainsFunc(d.Mappings, func(m defs.Mapping) bool {
		return m.Route == s.a.Route && (string(m.Channel) == s.a.Channel || (s.a.Channel != "mcp" && s.a.Channel != "http"))
	})
	if !known {
		s.cl.add(StepScope, adomain.CannotAuthorize, ReasonRouteUnknown, "route "+s.a.Route+" is not a reviewed route of "+d.Operation, "")
		return
	}
	switch {
	case s.a.Connection != "":
		if !p.connection(ctx, s, d) {
			return
		}
	case slices.Contains(gatewayChannels, s.a.Channel):
		// A gateway names the connection a call came through (PAP-1 §6), so
		// its mode, quarantine and credential always apply.
		s.cl.add(StepScope, adomain.CannotAuthorize, ReasonConnectionRequired, "an action from the "+s.a.Channel+" channel names its connection", "")
		return
	}
	s.def = d
	s.cl.pass(StepScope, ReasonRouteReviewed)
}

// connection checks the connection an action names (PAP-1 §6): the gateway
// asking serves it, it uses the action's package, and a hook call comes
// through a local connection and nothing else does. A connection of another
// gateway or org looks unknown. The route's mode on it decides whether the
// action runs in monitor mode.
func (p *Pipeline) connection(ctx context.Context, s *state, d *defs.Definition) bool {
	unknown := func() bool {
		s.cl.add(StepScope, adomain.CannotAuthorize, ReasonConnectionUnknown, "the connection is not one this gateway serves", "")
		return false
	}
	id, err := ids.ParseUUID(s.a.Connection)
	if err != nil {
		return unknown()
	}
	c, err := p.Reader.Connection(ctx, s.req.Org, id)
	switch {
	case errors.Is(err, ErrNotFound):
		return unknown()
	case err != nil:
		s.missing(StepScope, err, "the connection")
		return false
	case c.Gateway.String() != s.req.Gateway:
		return unknown()
	}
	if c.Package != s.a.Definition.Package || (c.Kind == "local") != (s.a.Channel == string(defs.ChannelHook)) || !dispatches(c.Kind, d) {
		s.cl.add(StepScope, adomain.CannotAuthorize, ReasonRouteUnknown,
			"route "+s.a.Route+" of "+d.Operation+" is not served by this connection", "")
		return false
	}
	s.conn = &c
	s.ev.Connection = &c
	if c.Mode(s.a.Route) == ModeMonitor {
		s.ev.Mode = ModeMonitor
	}
	return true
}

// gatewayChannels are the channels a gateway serves, whose actions always
// name their connection (PAP-1 §6); cooperative SDKs (sdk) may omit it.
var gatewayChannels = []string{string(defs.ChannelHTTP), string(defs.ChannelMCP), string(defs.ChannelHook)}

// dispatches reports whether a connection of this kind serves the
// definition: an HTTP or MCP connection only definitions with a dispatch
// template of its kind, a local one (the hook) any, because the agent's
// machine executes it.
func dispatches(kind string, d *defs.Definition) bool {
	switch kind {
	case "http":
		return d.Dispatch != nil && d.Dispatch.HTTP != nil
	case "mcp":
		return d.Dispatch != nil && d.Dispatch.MCP != nil
	case "local":
		return true
	}
	return false
}

// Step 2: the verified instance is the run's, and its attestation level
// meets every level's minimum. The run binding was minted by the Authority
// (HR-022); the action's own instance field must agree with the verified
// identity.
func (p *Pipeline) identity(ctx context.Context, s *state) {
	id := s.req.Identity
	run, err := p.Reader.Run(ctx, s.req.Org, s.ev.RunID)
	switch {
	case errors.Is(err, ErrNotFound):
		s.cl.add(StepIdentity, adomain.Deny, ReasonRunMismatch, "the run is unknown", "")
		return
	case err != nil:
		s.missing(StepIdentity, err, "the run")
		return
	}
	s.run = &run
	s.ev.Identity = IdentitySummary{
		Instance: id.InstanceID.String(), AttestationLevel: id.AttestationLevel, Agent: id.AgentID.String(),
		Run: s.ev.RunID.String(), Launcher: run.Launcher.String(), Principal: run.Principal.String(),
	}
	switch {
	case run.AgentID != id.AgentID || (!run.InstanceID.IsZero() && run.InstanceID != id.InstanceID):
		s.cl.add(StepIdentity, adomain.Deny, ReasonRunMismatch, "the run belongs to another agent or instance", "")
		return
	case s.a.AgentInstance != id.InstanceID.String():
		s.cl.add(StepIdentity, adomain.Deny, ReasonActionInstanceDiffer, "the action names another instance than the verified one", "")
		return
	}
	agent, err := p.Reader.Agent(ctx, s.req.Org, run.AgentID)
	if err != nil {
		s.missing(StepIdentity, err, "the agent")
		return
	}
	s.agent = &agent
	if !run.GrantID.IsZero() {
		p.loadChain(ctx, s)
	}
	if need := s.chain.MinAttestation(); id.AttestationLevel < need {
		s.cl.add(StepIdentity, adomain.CannotAuthorize, gdomain.ReasonAttestationTooLow,
			fmt.Sprintf("attestation level %d is below the required %d", id.AttestationLevel, need), "")
		return
	}
	s.cl.pass(StepIdentity, ReasonIdentityVerified)
}

func (p *Pipeline) loadChain(ctx context.Context, s *state) {
	grants, err := p.Reader.Chain(ctx, s.req.Org, s.run.GrantID)
	if err != nil || len(grants) == 0 {
		s.missing(StepAuthority, err, "the grant chain")
		return
	}
	scopes := []gdomain.Scope{
		{Kind: gdomain.ScopeOrg},
		{Kind: gdomain.ScopeBusinessUnit, ID: s.agent.BusinessUnitID},
		{Kind: gdomain.ScopeTeam, ID: s.agent.TeamID},
		{Kind: gdomain.ScopeEnvironment, ID: s.run.EnvironmentID},
		{Kind: gdomain.ScopePrincipal, Principal: s.run.Principal},
	}
	envs, err := p.Reader.Envelopes(ctx, s.req.Org, scopes)
	if err != nil {
		s.missing(StepAuthority, err, "the guardrails")
		return
	}
	s.chain = gdomain.Chain{Envelopes: envs, Grants: grants}
	s.ev.Chain = s.chain
	s.ev.RepeatWindow = gdomain.EffectiveCaps(envs).RepeatWindow
}

// Step 3: nothing on the path is contained.
func (p *Pipeline) containment(s *state) {
	blocked := false
	if s.cont.KillSwitch {
		s.cl.add(StepContainment, adomain.Deny, adomain.ReasonKillSwitch, "the org kill switch is engaged", "")
		blocked = true
	}
	if s.agent != nil && (s.agent.State == "SUSPENDED" || s.agent.State == "RETIRED") {
		s.cl.add(StepContainment, adomain.Deny, ReasonAgentSuspended, "the agent is "+s.agent.State, "")
		blocked = true
	}
	if s.run != nil && !s.run.Active {
		s.cl.add(StepContainment, adomain.Deny, ReasonRunNotActive, "the run has ended or was revoked", "")
		blocked = true
	}
	if s.pinned != nil && (s.pinned.State == defs.StateQuarantined || s.pinned.State == defs.StateRetired) {
		s.cl.add(StepContainment, adomain.Deny, ReasonPackageQuarantined, "the definition is "+string(s.pinned.State), "")
		blocked = true
	}
	if s.conn != nil && s.conn.State != "ACTIVE" {
		s.cl.add(StepContainment, adomain.Deny, ReasonConnectionContained, "the connection is "+s.conn.State, "")
		blocked = true
	}
	if !blocked {
		s.cl.pass(StepContainment, ReasonNotContained)
	}
}

// Step 4 (first part): the run has a grant, every ancestor is valid, and
// the leaf is meant for this agent, principal and environment. Coverage of
// the operation and target is checked once the meaning is known.
func (p *Pipeline) authority(s *state) {
	if s.run == nil {
		s.cl.skip(StepAuthority, "the run is not known")
		return
	}
	if s.run.GrantID.IsZero() {
		s.cl.add(StepAuthority, adomain.Deny, gdomain.ReasonNoGrant, "the run has no grant", "")
		return
	}
	if len(s.chain.Grants) == 0 {
		return // reading the chain already failed
	}
	if code, f := s.chain.Validity(s.cont.Now); f != nil {
		s.cl.add(StepAuthority, adomain.Deny, code, f.Finding.Detail, f.Level.String())
		return
	}
	leaf, _ := s.chain.Leaf()
	if !leaf.Covers(s.run.AgentID, s.run.InstanceID, s.run.Principal, s.run.EnvironmentID) ||
		s.a.Env != leaf.EnvironmentID.String() {
		s.cl.add(StepAuthority, adomain.Deny, gdomain.ReasonGrantMismatch, "the grant is for another agent, principal or environment", "")
		return
	}
	s.covered = true // coverage proper follows in meaning()
}

// Step 5: the definition is active and current, the parameters decode
// exactly, the target fits, and the dedupe key is ours (never the agent's).
// Then the coverage part of step 4 runs on the decoded action.
func (p *Pipeline) meaning(s *state) {
	if s.def == nil {
		s.cl.skip(StepMeaning, "the definition is not known")
		s.covered = false
		return
	}
	d, now := s.def, s.cont.Now
	switch {
	case s.pinned.State != defs.StateActive:
		s.cl.add(StepMeaning, adomain.CannotAuthorize, ReasonDefinitionNotActive, "the definition is "+string(s.pinned.State)+", not ACTIVE", "")
	case d.Assurance.Stale(now):
		s.cl.add(StepMeaning, adomain.CannotAuthorize, ReasonDefinitionStale, "the definition's review expired on "+d.Assurance.ValidUntil, "")
	}
	vals, err := d.DecodeParams(s.a.Params)
	if err != nil {
		s.cl.add(StepMeaning, adomain.CannotAuthorize, adomain.ReasonAmbiguousInput, "the parameters are ambiguous or unsupported", "")
		s.covered = false
		return
	}
	t := s.a.Target
	switch {
	case t.Type != d.Target.Type || !d.Target.MatchID(t.ID):
		s.cl.add(StepMeaning, adomain.CannotAuthorize, adomain.ReasonAmbiguousInput, "the target is not a "+d.Target.Type, "")
		s.covered = false
		return
	case (d.Target.Account == defs.PresenceRequired && t.Account == "") || (d.Target.Account == defs.PresenceNone && t.Account != "") ||
		(t.Account != "" && !d.Target.MatchAccount(t.Account)):
		s.cl.add(StepMeaning, adomain.CannotAuthorize, adomain.ReasonAmbiguousInput, "the target account is missing or unexpected", "")
		s.covered = false
		return
	}
	key, err := d.DedupeKey(t, vals)
	if err != nil || (s.a.DedupeKey != "" && s.a.DedupeKey != key) {
		s.cl.add(StepMeaning, adomain.CannotAuthorize, adomain.ReasonAmbiguousInput, "the dedupe key does not match the canonical action", "")
		s.covered = false
		return
	}
	s.vals, s.ev.DedupeKey = vals, key
	dests := make([]string, 0, len(s.a.Destinations))
	for _, dst := range s.a.Destinations {
		dests = append(dests, dst.ID)
	}
	s.gAction = &gdomain.Action{
		Operation: s.a.Operation, Access: d.Access, TargetType: t.Type, TargetID: t.ID, Account: t.Account,
		AccountDeclared: d.Target.Account != defs.PresenceNone, Destinations: dests, Params: vals, Time: now,
	}
	if m, err := moneyValue(vals); err == nil {
		s.ev.Amount = m
	}
	s.cl.pass(StepMeaning, ReasonMeaningExact)
	if !s.covered {
		return
	}
	findings := s.chain.Coverage(*s.gAction)
	for _, f := range findings {
		s.cl.add(StepAuthority, effectOf(f), f.Reason(), f.Finding.Detail, f.Level.String())
	}
	if len(findings) > 0 {
		s.covered = false
		return
	}
	s.cl.pass(StepAuthority, ReasonGrantCovers)
}

func effectOf(f gdomain.LevelFinding) adomain.Decision {
	if f.Finding.Outcome == gdomain.Unknown {
		return adomain.CannotAuthorize
	}
	return adomain.Deny
}

func moneyValue(vals defs.Values) (*money.Money, error) {
	var out *money.Money
	for _, v := range vals {
		if v.Type == defs.TypeMoney {
			if out != nil {
				return nil, errors.New("several money parameters")
			}
			m := v.Money
			out = &m
		}
	}
	return out, nil
}

// Step 6: the facts the definition and the policy need are present, from
// their providers, and fresh (HR-160). Facts are about the action's target.
func (p *Pipeline) currentFacts(ctx context.Context, s *state) {
	if s.gAction == nil {
		s.cl.skip(StepFacts, "the meaning is not known")
		return
	}
	pol, err := p.Reader.Policy(ctx, s.req.Org)
	if err != nil {
		s.missing(StepFacts, err, "the policy")
		return
	}
	s.policy = pol
	var reqs []fdomain.Requirement
	for _, pr := range s.def.Prerequisites {
		reqs = append(reqs, fdomain.Requirement{Name: pr.Fact, MaxAge: time.Duration(pr.MaxAgeSeconds) * time.Second, Source: "definition"})
	}
	if pol != nil {
		reqs = append(reqs, pol.Compiled.FactRequirements(s.a.Operation, s.a.Env)...)
	}
	s.facts = map[string]fdomain.Value{}
	if len(reqs) == 0 {
		s.cl.note(StepFacts, StatusNotApplicable, ReasonFactsFresh, "no facts are required")
		return
	}
	names := make([]string, 0, len(reqs))
	for _, r := range fdomain.Merge(reqs) {
		names = append(names, r.Name)
	}
	recorded, err := p.Reader.Facts(ctx, s.req.Org, s.a.Target.Type, s.a.Target.ID, names)
	if err != nil {
		s.missing(StepFacts, err, "the facts")
		return
	}
	ok := true
	for _, c := range fdomain.Evaluate(reqs, recorded, s.cont.Now) {
		switch c.Status {
		case fdomain.Missing:
			ok = false
			s.cl.add(StepFacts, adomain.CannotAuthorize, fdomain.ReasonFactMissing, c.Requirement.Name+" is not known (needed by "+c.Requirement.Source+")", "")
		case fdomain.Stale:
			ok = false
			s.cl.add(StepFacts, adomain.CannotAuthorize, fdomain.ReasonFactStale,
				fmt.Sprintf("%s is %s old; at most %s is accepted", c.Requirement.Name, c.Age.Round(time.Second), c.Requirement.MaxAge), "")
		case fdomain.Present:
			s.facts[c.Requirement.Name] = c.Fact.Value
			s.used = append(s.used, *c.Fact)
		}
	}
	if ok {
		s.cl.pass(StepFacts, ReasonFactsFresh)
	}
}

// Step 7: every level's limits, FORBID rules, counters and budgets (a
// read-only check; step 9 reserves), and repeat protection (a pre-check;
// step 9 claims the key).
func (p *Pipeline) boundaries(ctx context.Context, s *state) {
	if s.gAction == nil || len(s.chain.Grants) == 0 {
		s.cl.skip(StepBoundaries, "the meaning or the grant is not known")
		return
	}
	start := len(s.cl.items)
	for _, f := range s.chain.Limits(*s.gAction) {
		s.cl.add(StepBoundaries, effectOf(f), f.Reason(), f.Finding.Detail, f.Level.String())
	}
	p.policyRules(ctx, s)
	p.budgets(ctx, s)
	p.repeats(ctx, s)
	if !slices.ContainsFunc(s.cl.items[start:], func(it Item) bool { return it.Step == StepBoundaries && it.Status != StatusPassed }) {
		s.cl.pass(StepBoundaries, ReasonWithinBoundaries)
	}
}

// policyRules evaluates the published policy and files its items: FORBID
// rules and violated limits under step 7, the rest under step 8.
func (p *Pipeline) policyRules(ctx context.Context, s *state) {
	if s.policy == nil {
		return
	}
	in := papp.Input{Budget: s.policy.Budget, Facts: s.facts, Now: s.cont.Now}
	if s.conn != nil {
		// The class comes from the connection's record, never from the
		// gateway or the agent (HR-079).
		in.DestinationClass = s.conn.DestinationClass
	}
	out, err := s.policy.Compiled.Evaluate(ctx, s.def, s.a, in)
	if err != nil {
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonPolicyEvaluation, "the policy could not be evaluated", "")
		return
	}
	notApplicable := 0
	for _, it := range out.Checklist {
		if it.Status == pdomain.StatusNotApplicable {
			notApplicable++
			continue
		}
		step := StepRequirements
		if it.Kind == pdomain.Forbid || it.Status == pdomain.StatusFailed {
			step = StepBoundaries
		}
		level := "policy " + s.policy.Version + " rule " + it.Rule
		switch it.Status { //nolint:exhaustive // the remaining statuses only explain
		case pdomain.StatusPassed:
			continue // passing rules are summarized by the step's own item
		case pdomain.StatusAnnotated:
			s.cl.items = append(s.cl.items, Item{Step: step, Check: stepChecks[step], Status: StatusAnnotated, Code: it.Reason, Level: level, effect: adomain.Allow})
			continue
		case pdomain.StatusNotEvaluated:
			if it.Verdict == pdomain.VerdictPass {
				s.cl.items = append(s.cl.items, Item{Step: step, Check: stepChecks[step], Status: StatusNotEvaluated, Code: it.Reason, Detail: it.Detail, Level: level, effect: adomain.Allow})
				continue
			}
		}
		s.cl.add(step, verdictEffect(it.Verdict), it.Reason, it.Detail, level)
	}
	if notApplicable > 0 {
		s.cl.note(StepRequirements, StatusNotApplicable, ReasonRulesNotApplicable, strconv.Itoa(notApplicable)+" rules do not apply")
	}
	s.ev.Obligations, s.ev.Labels = out.Obligations, out.Labels
	s.ev.Approvals = append(s.ev.Approvals, out.Approvals...)
	s.ev.StepUps = append(s.ev.StepUps, out.StepUps...)
	for _, r := range out.Required {
		s.ev.Requirements = append(s.ev.Requirements, input(r.Approval, r.StepUp,
			apdomain.Source{Level: "policy " + s.policy.Version + " rule " + r.Rule, Reason: r.Reason}))
	}
}

// input turns a policy or grant requirement into an approvals input with
// its source.
func input(a *pdomain.ApprovalRequirement, su *pdomain.StepUpRequirement, src apdomain.Source) apdomain.Input {
	in := apdomain.Input{Source: src}
	if a != nil {
		in.Kind, in.Role, in.Count, in.Independent = apdomain.KindApproval, a.Role, a.Count, a.Independent
		in.Deadline = time.Duration(a.DeadlineSeconds) * time.Second
	}
	if su != nil {
		in.Kind, in.Subject, in.Method = apdomain.KindStepUp, su.Subject, su.Method
		in.Deadline = time.Duration(su.DeadlineSeconds) * time.Second
	}
	return in
}

func verdictEffect(v pdomain.Verdict) adomain.Decision {
	switch v {
	case pdomain.VerdictDeny:
		return adomain.Deny
	case pdomain.VerdictCannotAuthorize:
		return adomain.CannotAuthorize
	case pdomain.VerdictRequireApproval:
		return adomain.RequireApproval
	case pdomain.VerdictRequireStepUp:
		return adomain.RequireStepUp
	case pdomain.VerdictConstrain:
		return adomain.AllowWithObligations
	case pdomain.VerdictPass:
		return adomain.Allow
	}
	return adomain.CannotAuthorize
}

// budgets plans every reservation (ancestor debiting, HR-048) and checks it
// against current usage. The binding reservation is in step 9.
func (p *Pipeline) budgets(ctx context.Context, s *state) {
	plan, f := s.chain.Debits(*s.gAction, gdomain.DebitContext{Now: s.cont.Now, RunID: s.ev.RunID, Principal: s.run.Principal, TeamID: s.agent.TeamID})
	if f != nil {
		s.cl.add(StepBoundaries, effectOf(*f), f.Reason(), f.Finding.Detail, f.Level.String())
		return
	}
	s.ev.Plan = plan
	if len(plan.Budgets)+len(plan.Counters) == 0 {
		return
	}
	usage, err := p.Reader.Usage(ctx, s.req.Org, plan)
	if err != nil {
		s.missing(StepBoundaries, err, "the budgets")
		return
	}
	book := bdomain.NewBook()
	var lines []bdomain.Line
	labels := map[ids.UUID]string{}
	s.ev.Rows = Rows{Accounts: map[bdomain.Ref]ids.UUID{}, Counters: map[bdomain.Ref]ids.UUID{}}
	for _, d := range plan.Budgets {
		acc := usage.Accounts[d.Ref]
		if !acc.ID.IsZero() {
			s.ev.Rows.Accounts[d.Ref] = acc.ID
		}
		acc.ID, acc.Rank, acc.Currency, acc.Limit, acc.MaxCount = ids.NewV7(), d.Ref.Owner.Rank, d.Currency, d.Limit, d.MaxCount
		book.Accounts[acc.ID] = &acc
		lines = append(lines, bdomain.Line{Kind: bdomain.KindBudget, ID: acc.ID, Rank: acc.Rank, Amount: d.Amount})
		labels[acc.ID] = levelOf(s.chain, d.Ref.Owner) + " budget " + d.Ref.Rule
	}
	for _, d := range plan.Counters {
		c, exists := usage.Counters[d.Ref]
		capRef := d.Ref
		capRef.Key = [32]byte{}
		if !exists && usage.CounterRows[capRef] >= bdomain.MaxCounterRows {
			s.cl.add(StepBoundaries, adomain.CannotAuthorize, gdomain.ReasonCounterCapacityExceed, "counter "+d.Ref.Rule+" tracks too many keys in this window", levelOf(s.chain, d.Ref.Owner))
			return
		}
		if !c.ID.IsZero() {
			s.ev.Rows.Counters[d.Ref] = c.ID
		}
		c.ID, c.Rank, c.Max, c.MaxOutstanding = ids.NewV7(), d.Ref.Owner.Rank, d.Max, d.MaxOutstanding
		book.Counters[c.ID] = &c
		lines = append(lines, bdomain.Line{Kind: bdomain.KindCounter, ID: c.ID, Rank: c.Rank})
		labels[c.ID] = levelOf(s.chain, d.Ref.Owner) + " counter " + d.Ref.Rule
	}
	if failed, err := book.Check(lines); err != nil {
		code := gdomain.ReasonBudgetExhausted
		if failed.Kind == bdomain.KindCounter {
			code = gdomain.ReasonCountLimitReached
		}
		s.cl.add(StepBoundaries, adomain.Deny, code, labels[failed.ID]+": "+err.Error(), "")
	}
}

func levelOf(c gdomain.Chain, o bdomain.Owner) string {
	for _, l := range c.Levels() {
		if l.ID == o.ID {
			return l.String()
		}
	}
	return o.Kind
}

// repeats parks a repeat of an irreversible action while an earlier attempt
// on its dedupe key is in flight or UNKNOWN, or for the repeat window after
// it succeeded (HR-007).
func (p *Pipeline) repeats(ctx context.Context, s *state) {
	if s.ev.DedupeKey == "" {
		return
	}
	c, err := p.Reader.Claim(ctx, s.req.Org, s.ev.DedupeKey)
	if err != nil {
		s.missing(StepBoundaries, err, "earlier attempts")
		return
	}
	if parked, why := Parked(c, s.ev.ActionID, s.cont.Now, s.ev.RepeatWindow); parked {
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonReconciliation, why, "")
	}
}

// Parked reports whether an earlier claim parks a new attempt (shared with
// the finalization, which decides again under the claim's lock).
func Parked(c *Claim, self ids.UUID, now time.Time, window time.Duration) (bool, string) {
	if c == nil || c.TransactionID == self {
		return false, ""
	}
	switch c.State {
	case ClaimHeld:
		return true, "an identical irreversible action (transaction " + c.TransactionID.String() + ") is in flight or its outcome is unknown"
	case ClaimSucceeded:
		if now.Sub(c.At) < window {
			return true, fmt.Sprintf("an identical irreversible action (transaction %s) succeeded %s ago; repeats wait %s", c.TransactionID, now.Sub(c.At).Round(time.Second), window)
		}
	case ClaimReleased:
	}
	return false, ""
}

// Step 8: approvals and step-ups from every level and the policy, each with
// its source, the effective action when an obligation clamps a parameter,
// and the transaction's approval request (G0 M5 part 2). A request that
// was declined or expired ends the action as DENY, whatever else changed
// (HR-171); an approved request whose binding this evaluation recomputes
// satisfies the requirements, and the finalization that permits consumes
// it (HR-031).
func (p *Pipeline) requirements(ctx context.Context, s *state) {
	if s.gAction == nil || len(s.chain.Grants) == 0 {
		s.cl.skip(StepRequirements, "the meaning or the grant is not known")
		return
	}
	for _, r := range s.chain.Requirements(*s.gAction) {
		if a := r.Requirement.Approval; a != nil {
			s.ev.Approvals = append(s.ev.Approvals, *a)
			s.cl.add(StepRequirements, adomain.RequireApproval, r.Requirement.Reason, "approval by "+a.Role+" is required", r.Level.String())
		} else {
			s.ev.StepUps = append(s.ev.StepUps, *r.Requirement.StepUp)
			s.cl.add(StepRequirements, adomain.RequireStepUp, r.Requirement.Reason, "step-up by the "+r.Requirement.StepUp.Subject+" is required", r.Level.String())
		}
		s.ev.Requirements = append(s.ev.Requirements, input(r.Requirement.Approval, r.Requirement.StepUp,
			apdomain.Source{Level: r.Level.String(), Reason: r.Requirement.Reason}))
	}
	effective := s.vals
	if eff, vals, ok := s.effective(); ok {
		s.ev.EffectiveHash, effective = eff, vals
	}
	s.verification(effective)
	latest, err := p.Reader.Hold(ctx, s.req.Org, s.ev.RunID, s.ev.ActionID)
	if err != nil {
		s.missing(StepRequirements, err, "the approval request")
		return
	}
	if latest != nil {
		st, code := apdomain.At(latest.State, latest.times(), s.cont.Now)
		if apdomain.Terminal(st) {
			if code == "" {
				code = latest.EndReason
			}
			s.cl.add(StepRequirements, adomain.Deny, code, "the approval request "+latest.ID.String()+" ended: "+strings.ToLower(string(st)), "")
			s.ev.Hold = &Hold{Request: latest, State: apdomain.WaitState(st, code), Code: code, Expire: st != latest.State}
			return
		}
	}
	if len(s.ev.Requirements) == 0 {
		if !slices.ContainsFunc(s.cl.items, func(it Item) bool { return it.Step == StepRequirements && it.effect != adomain.Allow }) {
			s.cl.pass(StepRequirements, ReasonRequirementsMet)
		}
		return
	}
	h, err := p.hold(ctx, s, latest, effective)
	switch {
	case errors.Is(err, apdomain.ErrRequirementInvalid):
		s.cl.add(StepRequirements, adomain.CannotAuthorize, apdomain.ReasonRequirementInvalid,
			"a requirement names a role, subject, method or deadline that cannot be satisfied", "")
		return
	case errors.Is(err, apdomain.ErrStepUpSubjectNotAPerson):
		s.cl.add(StepRequirements, adomain.CannotAuthorize, apdomain.ReasonStepUpSubjectNotAPerson,
			"a step-up names the launcher or principal, which is not a person here; use an approval for automation", "")
		return
	case err != nil:
		s.missing(StepRequirements, err, "the approval request")
		return
	}
	s.ev.Hold = h
	if h.Satisfied {
		for i, it := range s.cl.items {
			if it.Step == StepRequirements && (it.effect == adomain.RequireApproval || it.effect == adomain.RequireStepUp) {
				it.effect, it.Status, it.Detail = adomain.Allow, StatusPassed, "satisfied by approval request "+latest.ID.String()
				s.cl.items[i] = it
			}
		}
		s.cl.pass(StepRequirements, apdomain.ReasonApprovalSatisfied)
	}
}

func (h *HoldRequest) times() apdomain.Times {
	return apdomain.Times{Deadline: h.Deadline, EvidenceDeadline: h.EvidenceDeadline, ConsumeBy: h.ConsumeBy}
}

// hold merges the requirements, checks the step-up subjects and computes
// the display and the binding (HR-030, HR-034). While the transaction has
// a live request, the binding is recomputed with that request's deadline
// and context, so an unchanged action, basis and requirement keep it; any
// change gives a new binding and a new request with a fresh deadline.
func (p *Pipeline) hold(ctx context.Context, s *state, latest *HoldRequest, effective defs.Values) (*Hold, error) {
	reqs, deadline, err := apdomain.Merge(s.ev.Requirements)
	if err != nil {
		return nil, err
	}
	people := apdomain.RunPeople{Launcher: s.run.Launcher, Principal: s.run.Principal, Ancestors: s.run.Ancestors}
	for _, r := range reqs {
		if r.Kind == apdomain.KindStepUp {
			if _, err := apdomain.StepUpUser(r, people); err != nil {
				return nil, err
			}
		}
	}
	leaf, _ := s.chain.Leaf()
	t := s.a.Target
	key, err := apdomain.VariantKey(leaf.ID.UUID(), s.a.Operation, apdomain.Target{Type: t.Type, ID: t.ID, Account: t.Account})
	if err != nil {
		return nil, err
	}
	h := &Hold{Requirements: reqs, VariantKey: key, Request: latest, State: apdomain.WaitPending, Action: s.req.Action.Canonical}
	if latest != nil && latest.State.Live() {
		if err := p.bind(s, h, effective, latest.Deadline, latest.Variants, latest.Context); err != nil {
			return nil, err
		}
		if h.Binding.Hash == latest.Binding {
			st, _ := apdomain.At(latest.State, latest.times(), s.cont.Now)
			h.Keep, h.Satisfied, h.State = true, st == apdomain.StateApproved, apdomain.WaitState(st, "")
			return h, nil
		}
	}
	settings, err := p.Reader.HoldSettings(ctx, s.req.Org)
	if err != nil {
		return nil, err
	}
	variants, approved, err := p.Reader.Variants(ctx, s.req.Org, key, s.a.Operation, t, s.cont.Now)
	if err != nil {
		return nil, err
	}
	return h, p.bind(s, h, effective, apdomain.Deadline(s.cont.Now, deadline, settings.HoldDeadline), variants, approved)
}

// bind renders the display for the given deadline and context and computes
// the binding over it.
func (p *Pipeline) bind(s *state, h *Hold, effective defs.Values, deadline time.Time, variants []apdomain.VariantLine,
	approved []apdomain.ContextLine,
) error {
	disp, err := apdomain.RenderAction(apdomain.ActionInput{
		Definition: s.def, Target: s.a.Target, Requested: s.vals, Effective: effective, Facts: s.used,
		Run: apdomain.RunLine{
			Run: s.ev.RunID.String(), Agent: s.run.AgentID.String(), Instance: s.req.Identity.InstanceID.String(),
			Launcher: s.run.Launcher.String(), Principal: s.run.Principal.String(),
		},
		TaskLabel: s.run.TaskRef, Requirements: h.Requirements, Deadline: deadline, Variants: variants, Context: approved,
	})
	if err != nil {
		return err
	}
	c, err := disp.Canonical()
	if err != nil {
		return err
	}
	leaf, _ := s.chain.Leaf()
	b, err := apdomain.ActionParts{
		ActionHash: s.ev.ActionHash, EffectiveActionHash: s.ev.EffectiveHash, BasisDigest: s.basis().Digest(),
		FactsDigest: fdomain.Digest(s.used), DefinitionDigest: s.a.Definition.Digest, GrantID: leaf.ID.UUID(),
		GrantRevision: leaf.Revision, RunID: s.ev.RunID, Instance: s.req.Identity.InstanceID, JKT: s.req.Identity.JKT,
		Requirements: h.Requirements, ExpiresAt: deadline, DisplayHash: c.Hash,
	}.Binding()
	if err != nil {
		return err
	}
	h.Deadline, h.Display, h.DisplayHash, h.Binding = deadline, disp, c.Hash, b
	return nil
}

// verification fixes the verify plan of the effective action (G0 M7 design
// decision 2): the definition's digest, the level its effect must be
// verified at, and an extended verifier's expected values. The level is the
// definition's verifier.required, raised by any verify obligation of the
// policy. A level above the target's acceptance needs a verifier that
// reaches it, a connection through which the gateway can make the
// verifier's reads, and the values it must observe; without them nothing
// could ever show the effect at that level, so the action cannot be
// authorized (F497, HR-191).
func (s *state) verification(effective defs.Values) {
	if s.def == nil || s.pinned == nil {
		return
	}
	plan := &VerifyPlan{DefinitionDigest: s.pinned.Definition.Digest, Required: defs.LevelAcceptance}
	v := s.def.Verifier
	if v != nil && v.Extended() {
		plan.Required = v.RequiredLevel()
	}
	source := "" // the definition
	for _, o := range s.ev.Obligations {
		if o.Kind == pdomain.Verify && o.Level.Rank() > plan.Required.Rank() && s.policy != nil {
			plan.Required, source = o.Level, "policy "+s.policy.Version+" rule "+o.Rule
		}
	}
	if plan.Required != defs.LevelAcceptance {
		if why := s.unverifiable(plan.Required); why != "" {
			s.cl.add(StepRequirements, adomain.CannotAuthorize, ReasonVerifierUnsupported, why, source)
			return
		}
	}
	if v != nil && v.Extended() && len(v.Expect) > 0 {
		exp, ok := v.Expected(s.a.Target, effective)
		if !ok && plan.Required != defs.LevelAcceptance {
			s.cl.add(StepRequirements, adomain.CannotAuthorize, ReasonVerifierUnsupported,
				"the verifier cannot compute what it must observe, and the effect must be verified at "+string(plan.Required)+" level", source)
			return
		}
		plan.Expected = exp
	}
	s.ev.Verify = plan
}

// unverifiable says why no verification of this action can reach level, or
// "" when one can: the definition's verifier reaches the level, and the
// action came through an HTTP connection whose pinned package serves every
// read the verifier names, which only the gateway serving it makes
// (HR-190).
func (s *state) unverifiable(level defs.Level) string {
	v, op := s.def.Verifier, s.def.Operation
	switch {
	case v == nil || !v.Extended():
		return op + " has no verifier that can run, and its effect must be verified at " + string(level) + " level"
	case v.Reaches().Rank() < level.Rank():
		return fmt.Sprintf("the verifier of %s reaches %s; the effect must be verified at %s level", op, v.Reaches(), level)
	case s.conn == nil:
		return "the action names no connection, so no gateway can read its effect at the target"
	case s.conn.Kind != "http":
		return "the verifier reads over HTTP, and the action's connection is " + s.conn.Kind
	}
	reads := []string{v.Operation}
	if v.Lookup != nil {
		reads = append(reads, v.Lookup.Operation)
	}
	for _, r := range reads {
		if !slices.Contains(s.conn.Reads, r) {
			return "the connection's pinned package does not serve the verifier's read " + r
		}
	}
	return ""
}

// effective applies clamping obligations to the action and returns the
// effective action's hash and parameters (F104, F107).
func (s *state) effective() (string, defs.Values, bool) {
	vals := maps.Clone(s.vals)
	changed := false
	for _, o := range s.ev.Obligations {
		if !o.Clamp {
			continue
		}
		v, ok := vals[o.Param]
		limit, err := strconv.ParseInt(o.Max, 10, 64)
		if !ok || err != nil || v.Type != defs.TypeInteger || v.Int <= limit {
			continue
		}
		v.Int = limit
		vals[o.Param] = v
		changed = true
	}
	if !changed {
		return "", nil, false
	}
	raw, err := s.def.EncodeParams(vals)
	if err != nil {
		return "", nil, false
	}
	eff := s.a
	eff.Params = raw
	parsed, err := actionir.Encode(eff)
	if err != nil {
		return "", nil, false
	}
	return parsed.HashHex(), vals, true
}
