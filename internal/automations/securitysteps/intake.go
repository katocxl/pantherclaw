// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Intake reasons, stable codes.
const (
	ReasonNoBaseline = "BASELINE_MISSING"
	ReasonRetired    = "AGENT_RETIRED"
)

// Baseline sources (DraftBaselineWith.From).
const (
	BaselineCohort   = "COHORT_BASELINE"
	BaselineTemplate = "TEMPLATE"
)

// MaxClaimWait bounds wait_claim's timeout (D31).
const MaxClaimWait = 30 * 24 * time.Hour

// ErrTriggerAgentNotFound reports a trigger agent that is not in the org.
var ErrTriggerAgentNotFound = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")

// AgentInfo is what the intake kinds read of the trigger's agent.
type AgentInfo struct {
	ID        ids.UUID
	State     string
	Owner     *ids.UUID
	ClaimedAt *time.Time
}

// Claimed reports an agent claimed with an owner (F016) and not retired.
func (a AgentInfo) Claimed() bool {
	return a.ClaimedAt != nil && a.Owner != nil && a.State != "RETIRED"
}

// OwnerCandidate is one person who may own the agent, and why.
type OwnerCandidate struct {
	User ids.UUID `json:"user"`
	Why  []string `json:"why"`
}

// Why an owner candidate is proposed.
const (
	WhyDiscovered = "discovered the agent"
	whyRolePrefix = "holds "
)

// Discovery is the scan metadata of how the agent was found. Observed
// attributes are untrusted: their names are listed, never their values.
type Discovery struct {
	Source       string    `json:"source"`
	SubmittedBy  string    `json:"submitted_by,omitzero"`
	SeenCount    int64     `json:"seen_count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	ObservedKeys []string  `json:"observed_keys,omitzero"`
}

// CoverageSummary counts an agent's routes and its coverage scopes by
// state, as last assessed.
type CoverageSummary struct {
	Routes    int
	Scopes    int
	ByState   map[string]int
	Truncated bool
}

// Baseline is a grant template an automation proposes: bounds, limits
// and a time to live. It is never issued (HR-286); a person may issue a
// grant from it on the grants' own path.
type Baseline struct {
	From            string         `json:"from"`
	Bounds          gdomain.Bounds `json:"bounds"`
	Limits          gdomain.Limits `json:"limits,omitzero"`
	TTLSeconds      int            `json:"ttl_seconds"`
	DelegationDepth int            `json:"delegation_depth"`
	Basis           string         `json:"basis"`
}

// Operations lists the baseline's operation patterns.
func (b Baseline) Operations() []string {
	if b.Bounds.Operations == nil {
		return nil
	}
	return slices.Clone(*b.Bounds.Operations)
}

// TestCounts are a scenario run's case results over baseline operations.
type TestCounts struct {
	Bundle  string `json:"bundle,omitzero"`
	Version int    `json:"version,omitzero"`
	Cases   int    `json:"cases"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	// Error is the run's error code (NO_CASES, NO_PUBLISHED_POLICY, …).
	Error string `json:"error,omitzero"`
}

// IntakeAgents reads the trigger's agent; ErrTriggerAgentNotFound when absent.
type IntakeAgents interface {
	Agent(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) (AgentInfo, error)
}

// OwnerCandidates lists who may own an agent: the person who discovered
// it, the owners and admins on its path, and its scan metadata.
type OwnerCandidates interface {
	Candidates(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) ([]OwnerCandidate, *Discovery, error)
}

// RouteCoverage summarizes an agent's route coverage.
type RouteCoverage interface {
	Summary(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) (CoverageSummary, error)
}

// CohortBaselines returns the baseline of the fleet cohort an agent falls
// in (the govern stream).
type CohortBaselines interface {
	CohortBaseline(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) (Baseline, error)
}

// ObservedOperations lists the read operations an agent was seen using.
type ObservedOperations interface {
	ReadOperations(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) ([]string, error)
}

// ScenarioTests runs the published policy's scenario cases for operations
// (read only).
type ScenarioTests interface {
	Run(ctx context.Context, tx pgx.Tx, org ids.OrgID, operations []string) (TestCounts, error)
}

// IntakeDeps are the agent intake kinds' ties to the platform (D31).
type IntakeDeps struct {
	Agents     IntakeAgents
	Candidates OwnerCandidates
	Routes     RouteCoverage
	// Cohorts serves draft_baseline COHORT_BASELINE; nil until fleet
	// cohorts are in.
	Cohorts    CohortBaselines
	Operations ObservedOperations
	Tests      ScenarioTests
	// Proposals nil is the proposals table.
	Proposals Proposals
}

func intakeSteps(d Deps) autoports.StepRegistry {
	in := d.Intake
	return autoports.StepRegistry{
		autodomain.KindProposeOwner:  &proposeOwner{d: in},
		autodomain.KindInspectRoutes: &inspectRoutes{d: in},
		autodomain.KindDraftBaseline: &draftBaseline{d: in},
		autodomain.KindRunSafeTests:  &runSafeTests{d: in},
		autodomain.KindWaitClaim:     &waitClaim{d: in},
	}
}

// triggerAgent is the trigger's agent, when the version's platform section
// lets kind act on it (TRIGGER_AGENT, HR-284).
func triggerAgent(sc autodomain.StepContext, kind string) (ids.UUID, string) {
	if !inScope(sc.Def, kind, autodomain.ScopeTriggerAgent) {
		return ids.UUID{}, ReasonOutsideScope
	}
	a, ok := triggerSubject(sc, reflexdomain.SubjectAgent)
	if !ok {
		return ids.UUID{}, ReasonNoSubject
	}
	return a, ""
}

// previewAgent is the preview of an intake kind that only needs its agent.
func previewAgent(sc autodomain.StepContext, kind string, out map[string]string) (autodomain.StepResult, error) {
	a, reason := triggerAgent(sc, kind)
	if reason != "" {
		return previewRefused(reason)
	}
	if out == nil {
		out = map[string]string{}
	}
	out["agent"] = a.String()
	return shadowed(out)
}

// refused maps a use case's refusal to FAILED, anything else to an error.
func refusalOr(err error) (autodomain.StepResult, error) {
	if r, ok := refusal(err); ok {
		return failed(r)
	}
	return autodomain.StepResult{}, err
}

func proposalDone(out map[string]string, refs ...reflexdomain.EvidenceRef) (autodomain.StepResult, error) {
	return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Output: out, Refs: refs}, nil
}

// proposeOwner proposes owners for the trigger's agent (F692): an OWNER
// proposal, never a claim.
type proposeOwner struct{ d IntakeDeps }

func (*proposeOwner) Kind() string { return autodomain.KindProposeOwner }

// ownerBody is an OWNER proposal's body.
type ownerBody struct {
	Agent      string           `json:"agent"`
	Candidates []OwnerCandidate `json:"candidates"`
	Discovery  *Discovery       `json:"discovery,omitzero"`
	Note       string           `json:"note"`
}

// maxCandidates bounds an OWNER proposal's candidates.
const maxCandidates = 20

func (s *proposeOwner) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	agent, reason := triggerAgent(sc, s.Kind())
	if reason != "" {
		return failed(reason)
	}
	if s.d.Candidates == nil {
		return unwired()
	}
	cands, disc, err := s.d.Candidates.Candidates(ctx, tx, sc.Org, agent)
	if err != nil {
		return refusalOr(err)
	}
	if len(cands) > maxCandidates {
		cands = cands[:maxCandidates]
	}
	id, err := proposalsOr(s.d.Proposals).Propose(ctx, tx, sc, ProposalOwner, ProposalAboutAgent, agent, ownerBody{
		Agent: agent.String(), Candidates: cands, Discovery: disc,
		Note: "a proposal only: claiming the agent and naming its owner stay a person's action",
	})
	if err != nil {
		return autodomain.StepResult{}, err
	}
	return proposalDone(map[string]string{OutProposal: id.String(), "agent": agent.String(), "candidates": strconv.Itoa(len(cands))},
		ref(RefProposal, id), ref(RefAgent, agent))
}

func (s *proposeOwner) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *proposeOwner) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return previewAgent(sc, s.Kind(), map[string]string{"would": ProposalOwner})
}

// inspectRoutes summarizes the trigger agent's route coverage in its
// output: counts by coverage state, no proposal and no writes.
type inspectRoutes struct{ d IntakeDeps }

func (*inspectRoutes) Kind() string { return autodomain.KindInspectRoutes }

// coverageKey is a coverage state's output key: ENFORCED → enforced.
func coverageKey(state string) string { return strings.ToLower(state) }

func (s *inspectRoutes) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	agent, reason := triggerAgent(sc, s.Kind())
	if reason != "" {
		return failed(reason)
	}
	if s.d.Routes == nil {
		return unwired()
	}
	sum, err := s.d.Routes.Summary(ctx, tx, sc.Org, agent)
	if err != nil {
		return refusalOr(err)
	}
	out := map[string]string{
		"agent": agent.String(), "routes": strconv.Itoa(sum.Routes), "scopes": strconv.Itoa(sum.Scopes),
		"truncated": strconv.FormatBool(sum.Truncated),
	}
	for _, st := range []string{"ENFORCED", "PARTIAL", "OBSERVE_ONLY", "UNKNOWN"} {
		out[coverageKey(st)] = strconv.Itoa(sum.ByState[st])
	}
	return proposalDone(out, ref(RefAgent, agent))
}

func (s *inspectRoutes) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *inspectRoutes) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return previewAgent(sc, s.Kind(), nil)
}

// draftBaseline proposes a grant baseline for the trigger's agent: a
// BASELINE proposal, never an issued grant (HR-286).
type draftBaseline struct{ d IntakeDeps }

func (*draftBaseline) Kind() string { return autodomain.KindDraftBaseline }

// baselineBody is a BASELINE proposal's body.
type baselineBody struct {
	Agent    string   `json:"agent"`
	Baseline Baseline `json:"baseline"`
	Note     string   `json:"note"`
}

// The TEMPLATE baseline (D31) is deliberately conservative: the read
// operations the agent was seen using in the last 30 days, read access
// only, a day to live and no delegation. An agent seen using none gets an
// empty baseline, which allows nothing.
const (
	TemplateObserveDays = 30
	templateTTL         = 24 * time.Hour
	maxBaselineOps      = 64
)

// TemplateBaseline is the TEMPLATE baseline over ops.
func TemplateBaseline(ops []string) Baseline {
	ops = slices.Clone(ops)
	slices.Sort(ops)
	ops = slices.Compact(ops)
	if len(ops) > maxBaselineOps {
		ops = ops[:maxBaselineOps]
	}
	o := gdomain.Ops(ops)
	return Baseline{
		From:       BaselineTemplate,
		Bounds:     gdomain.Bounds{Operations: &o, Access: &gdomain.Match{IDs: []string{string(defs.AccessRead)}}},
		TTLSeconds: int(templateTTL / time.Second), DelegationDepth: 0,
		Basis: "read operations observed in the last " + strconv.Itoa(TemplateObserveDays) + " days",
	}
}

func (s *draftBaseline) with(sc autodomain.StepContext) (ids.UUID, string, string) {
	w, ok := sc.With.(*autodomain.DraftBaselineWith)
	if !ok || (w.From != BaselineCohort && w.From != BaselineTemplate) {
		return ids.UUID{}, "", ReasonBadWith
	}
	agent, reason := triggerAgent(sc, s.Kind())
	return agent, w.From, reason
}

func (s *draftBaseline) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	agent, from, reason := s.with(sc)
	if reason != "" {
		return failed(reason)
	}
	var b Baseline
	switch from {
	case BaselineCohort:
		if s.d.Cohorts == nil {
			return unwired()
		}
		var err error
		if b, err = s.d.Cohorts.CohortBaseline(ctx, tx, sc.Org, agent); err != nil {
			return refusalOr(err)
		}
		b.From = BaselineCohort
	default:
		if s.d.Operations == nil {
			return unwired()
		}
		ops, err := s.d.Operations.ReadOperations(ctx, tx, sc.Org, agent)
		if err != nil {
			return refusalOr(err)
		}
		b = TemplateBaseline(ops)
	}
	id, err := proposalsOr(s.d.Proposals).Propose(ctx, tx, sc, ProposalBaseline, ProposalAboutAgent, agent, baselineBody{
		Agent: agent.String(), Baseline: b,
		Note: "a grant template only: it is never issued; issuing a grant stays a person's action",
	})
	if err != nil {
		return autodomain.StepResult{}, err
	}
	return proposalDone(map[string]string{
		OutProposal: id.String(), "agent": agent.String(), "from": from, "operations": strconv.Itoa(len(b.Operations())),
	}, ref(RefProposal, id), ref(RefAgent, agent))
}

func (s *draftBaseline) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *draftBaseline) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	agent, from, reason := s.with(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"agent": agent.String(), "from": from, "would": ProposalBaseline})
}

// runSafeTests runs the published policy's scenario cases for the
// baseline's operations (pure: policy/scenario.Runner) and proposes the
// result: a TESTS proposal with pass and fail counts.
type runSafeTests struct{ d IntakeDeps }

func (*runSafeTests) Kind() string { return autodomain.KindRunSafeTests }

// testsBody is a TESTS proposal's body.
type testsBody struct {
	Agent      string     `json:"agent"`
	Baseline   string     `json:"baseline_proposal"`
	Operations []string   `json:"operations"`
	Results    TestCounts `json:"results"`
}

// baselineStep is the draft_baseline step before this one whose proposal
// run_safe_tests tests: the latest that recorded one.
func baselineStep(sc autodomain.StepContext) (ids.UUID, bool) {
	if sc.Def == nil {
		return ids.UUID{}, false
	}
	for i := min(sc.Index, len(sc.Def.Do)) - 1; i >= 0; i-- {
		st := sc.Def.Do[i]
		if st.Step != autodomain.KindDraftBaseline {
			continue
		}
		if id, ok := parseID(sc.Outputs[st.ID][OutProposal]); ok {
			return id, true
		}
	}
	return ids.UUID{}, false
}

func (s *runSafeTests) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	agent, reason := triggerAgent(sc, s.Kind())
	if reason != "" {
		return failed(reason)
	}
	if s.d.Tests == nil {
		return unwired()
	}
	bid, ok := baselineStep(sc)
	if !ok {
		return failed(ReasonNoBaseline)
	}
	props := proposalsOr(s.d.Proposals)
	kind, raw, err := props.Body(ctx, tx, sc.Org, bid)
	if db.IsNoRows(err) {
		return failed(ReasonNoBaseline)
	} else if err != nil {
		return autodomain.StepResult{}, err
	}
	var bb baselineBody
	if kind != ProposalBaseline || json.Unmarshal(raw, &bb) != nil || bb.Agent != agent.String() {
		return failed(ReasonNoBaseline)
	}
	ops := bb.Baseline.Operations()
	res, err := s.d.Tests.Run(ctx, tx, sc.Org, ops)
	if err != nil {
		return refusalOr(err)
	}
	id, err := props.Propose(ctx, tx, sc, ProposalTests, ProposalAboutAgent, agent, testsBody{
		Agent: agent.String(), Baseline: bid.String(), Operations: ops, Results: res,
	})
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out := map[string]string{
		OutProposal: id.String(), "agent": agent.String(), "cases": strconv.Itoa(res.Cases),
		"passed": strconv.Itoa(res.Passed), "failed": strconv.Itoa(res.Failed),
	}
	if res.Error != "" {
		out["error"] = res.Error
	}
	return proposalDone(out, ref(RefProposal, id), ref(RefProposal, bid), ref(RefAgent, agent))
}

func (s *runSafeTests) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *runSafeTests) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return previewAgent(sc, s.Kind(), map[string]string{"would": ProposalTests})
}

// waitClaim waits until the trigger's agent is claimed with an owner
// (AGENT_CLAIMED); past its timeout it fails AGENT_NOT_CLAIMED. Claiming
// stays a person's action: this only watches.
type waitClaim struct{ d IntakeDeps }

func (*waitClaim) Kind() string { return autodomain.KindWaitClaim }

func (s *waitClaim) with(sc autodomain.StepContext) (ids.UUID, time.Duration, string) {
	w, ok := sc.With.(*autodomain.WaitClaimWith)
	if !ok || w.Timeout.D() <= 0 || w.Timeout.D() > MaxClaimWait {
		return ids.UUID{}, 0, ReasonBadWith
	}
	agent, reason := triggerAgent(sc, s.Kind())
	return agent, w.Timeout.D(), reason
}

// check is one look at the agent: DONE when claimed, FAILED when retired
// or past until, else WAITING.
func (s *waitClaim) check(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, agent ids.UUID, until time.Time) (autodomain.StepResult, error) {
	a, err := s.d.Agents.Agent(ctx, tx, sc.Org, agent)
	if err != nil {
		return refusalOr(err)
	}
	out := map[string]string{"agent": agent.String(), steps.OutUntil: rfc(until)}
	refs := []reflexdomain.EvidenceRef{ref(RefAgent, agent)}
	switch {
	case a.Claimed():
		out["owner"] = a.Owner.String()
		return proposalDone(out, refs...)
	case a.State == "RETIRED":
		return autodomain.StepResult{State: autodomain.StepFailed, Reason: ReasonRetired, Effect: autodomain.EffectNone, Output: out, Refs: refs}, nil
	case !sc.Now.Before(until):
		return autodomain.StepResult{State: autodomain.StepFailed, Reason: ReasonNotClaimed, Effect: autodomain.EffectNone, Output: out, Refs: refs}, nil
	}
	return waiting(out, refs, sc.Now.Add(min(pollEvery, until.Sub(sc.Now))))
}

func (s *waitClaim) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	agent, timeout, reason := s.with(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Agents == nil {
		return unwired()
	}
	return s.check(ctx, tx, sc, agent, sc.Now.Add(timeout).UTC().Truncate(time.Second))
}

func (s *waitClaim) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	agent, _, reason := s.with(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Agents == nil {
		return unwired()
	}
	o := own(sc)
	until, ok := parseRFC(o[steps.OutUntil])
	if !ok || o["agent"] != agent.String() {
		return failed(ReasonBadWith)
	}
	return s.check(ctx, tx, sc, agent, until)
}

func (s *waitClaim) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	agent, timeout, reason := s.with(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"agent": agent.String(), "timeout": timeout.String()})
}

// IntakeReads implements IntakeAgents, OwnerCandidates, RouteCoverage and
// ObservedOperations over the database, in the driver's transaction. It
// only reads.
type IntakeReads struct {
	defs DefinitionsInTx
}

// DefinitionsInTx returns the definitions of the org's active packages in
// the caller's transaction (definitions pgstore.Store).
type DefinitionsInTx interface {
	ActiveDefinitionsInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) ([]*defs.Definition, error)
}

// NewIntakeReads returns the intake reads; definitions classifies the
// observed operations (only reads go into a TEMPLATE baseline).
func NewIntakeReads(definitions DefinitionsInTx) *IntakeReads { return &IntakeReads{defs: definitions} }

// Bounds of the intake reads.
const (
	intakePage    = 500
	intakePages   = 4
	maxObservedKV = 16
)

// Agent implements IntakeAgents.
func (r *IntakeReads) Agent(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) (AgentInfo, error) {
	a, err := dbq.New(tx).GetAgent(ctx, org, agent)
	if db.IsNoRows(err) {
		return AgentInfo{}, ErrTriggerAgentNotFound
	} else if err != nil {
		return AgentInfo{}, err
	}
	return AgentInfo{ID: a.ID, State: a.State, Owner: a.OwnerUserID, ClaimedAt: a.ClaimedAt}, nil
}

// pathRoles are the roles whose holders on an agent's path are proposed
// as its owners.
var pathRoles = []td.RoleName{td.RoleOrgAdmin, td.RoleSecurityAdmin, td.RoleAgentOwner}

// Candidates implements OwnerCandidates: the person who discovered the
// agent (its creator, when a person), the active holders of an owner or
// admin role on its path (the org, and once claimed its business unit,
// team and environment), and the discovery's scan metadata.
func (r *IntakeReads) Candidates(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) ([]OwnerCandidate, *Discovery, error) {
	q := dbq.New(tx)
	a, err := q.GetAgent(ctx, org, agent)
	if db.IsNoRows(err) {
		return nil, nil, ErrTriggerAgentNotFound
	} else if err != nil {
		return nil, nil, err
	}
	why := map[ids.UUID][]string{}
	var order []ids.UUID
	add := func(u ids.UUID, w string) {
		if _, ok := why[u]; !ok {
			order = append(order, u)
		}
		if !slices.Contains(why[u], w) {
			why[u] = append(why[u], w)
		}
	}
	if s, ok := strings.CutPrefix(a.CreatedBy, string(td.KindUser)+":"); ok {
		if u, ok := parseID(s); ok {
			add(u, WhyDiscovered)
		}
	}
	onPath, err := agentPath(ctx, q, org, a)
	if err != nil {
		return nil, nil, err
	}
	var after ids.UUID
	for range intakePages {
		bs, err := q.ListRoleBindings(ctx, dbq.ListRoleBindingsParams{OrgID: org, After: after, PageLimit: intakePage})
		if err != nil {
			return nil, nil, err
		}
		for _, b := range bs {
			if b.UserID != nil && slices.Contains(pathRoles, td.RoleName(b.Role)) && onPath(b) {
				add(*b.UserID, whyRolePrefix+b.Role+" at "+strings.ToLower(b.ScopeType))
			}
		}
		if len(bs) < intakePage {
			break
		}
		after = bs[len(bs)-1].ID
	}
	out := make([]OwnerCandidate, 0, len(order))
	for _, u := range order {
		p, err := q.GetUser(ctx, org, u)
		if db.IsNoRows(err) {
			continue
		} else if err != nil {
			return nil, nil, err
		}
		if p.State == "ACTIVE" {
			out = append(out, OwnerCandidate{User: u, Why: why[u]})
		}
	}
	disc, err := agentDiscovery(ctx, q, org, a)
	return out, disc, err
}

// pathOf reports whether a binding is on the agent's path.
func agentPath(ctx context.Context, q *dbq.Queries, org ids.OrgID, a dbq.PcAgent) (func(dbq.PcRoleBinding) bool, error) {
	var bu *ids.UUID
	if a.TeamID != nil {
		t, err := q.GetTeam(ctx, org, *a.TeamID)
		if err != nil && !db.IsNoRows(err) {
			return nil, err
		}
		bu = t.BusinessUnitID
	}
	same := func(x, y *ids.UUID) bool { return x != nil && y != nil && *x == *y }
	return func(b dbq.PcRoleBinding) bool {
		switch td.ScopeType(b.ScopeType) {
		case td.ScopeOrg:
			return true
		case td.ScopeBusinessUnit:
			return same(b.BusinessUnitID, bu)
		case td.ScopeTeam:
			return same(b.TeamID, a.TeamID)
		case td.ScopeEnvironment:
			return same(b.EnvironmentID, a.EnvironmentID)
		}
		return false
	}, nil
}

func agentDiscovery(ctx context.Context, q *dbq.Queries, org ids.OrgID, a dbq.PcAgent) (*Discovery, error) {
	d, err := q.GetAgentDiscovery(ctx, org, a.ID)
	if db.IsNoRows(err) {
		return nil, nil //nolint:nilnil // an agent created by a person has no discovery
	} else if err != nil {
		return nil, err
	}
	out := &Discovery{Source: d.Source, SubmittedBy: a.CreatedBy, SeenCount: d.SeenCount, FirstSeen: d.FirstSeenAt, LastSeen: d.LastSeenAt}
	var observed map[string]jsontext.Value
	if json.Unmarshal(d.Observed, &observed) == nil {
		for k := range observed {
			if len(k) <= 64 {
				out.ObservedKeys = append(out.ObservedKeys, k)
			}
		}
		slices.Sort(out.ObservedKeys)
		if len(out.ObservedKeys) > maxObservedKV {
			out.ObservedKeys = out.ObservedKeys[:maxObservedKV]
		}
	}
	return out, nil
}

// Summary implements RouteCoverage: the agent's routes (its own and those
// of every agent of a connection) and its current coverage snapshots by
// state, as last assessed. It never reassesses (that would write).
func (r *IntakeReads) Summary(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) (CoverageSummary, error) {
	q := dbq.New(tx)
	sum := CoverageSummary{ByState: map[string]int{}}
	var after *ids.UUID
	for page := 0; ; page++ {
		rs, err := q.ListCoverageRoutesPage(ctx, dbq.ListCoverageRoutesPageParams{OrgID: org, AgentID: &agent, After: after, MaxRows: intakePage})
		if err != nil {
			return sum, err
		}
		sum.Routes += len(rs)
		if len(rs) < intakePage {
			break
		}
		if page == intakePages-1 {
			sum.Truncated = true
			break
		}
		after = &rs[len(rs)-1].ID
	}
	p := dbq.ListCurrentCoverageSnapshotsPageParams{OrgID: org, AgentID: &agent, MaxRows: intakePage}
	for page := 0; ; page++ {
		ss, err := q.ListCurrentCoverageSnapshotsPage(ctx, p)
		if err != nil {
			return sum, err
		}
		for _, s := range ss {
			sum.Scopes++
			sum.ByState[s.State]++
		}
		if len(ss) < intakePage {
			break
		}
		if page == intakePages-1 {
			sum.Truncated = true
			break
		}
		last := ss[len(ss)-1]
		p.AfterAgent, p.AfterConnection, p.AfterOperation = &last.AgentID, &last.ConnectionID, &last.Operation
	}
	return sum, nil
}

// observedOperations lists the operations of the agent's recorded
// decisions since a time, bounded.
const observedOperations = `SELECT DISTINCT t.operation FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = $1 AND r.agent_id = $2 AND t.created_at >= $3
ORDER BY t.operation LIMIT 500`

// ReadOperations implements ObservedOperations: the operations the agent's
// recorded decisions of the last TemplateObserveDays days name whose
// active definition is a read.
func (r *IntakeReads) ReadOperations(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) ([]string, error) {
	if r.defs == nil {
		return nil, ErrUnwired
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return nil, err
	}
	ds, err := r.defs.ActiveDefinitionsInTx(ctx, ttx, org)
	if err != nil {
		return nil, err
	}
	reads := map[string]bool{}
	for _, d := range ds {
		if d.Access == defs.AccessRead {
			reads[d.Operation] = true
		}
	}
	rows, err := ttx.Query(ctx, observedOperations, org, agent, time.Now().Add(-TemplateObserveDays*24*time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var op string
		if err := rows.Scan(&op); err != nil {
			return nil, err
		}
		if reads[op] {
			out = append(out, op)
		}
	}
	return out, rows.Err()
}

// ScenarioRunner runs the published policy's scenario cases for a
// baseline's operations through the pure policy/scenario.Runner (read
// only, HR-232).
type ScenarioRunner struct {
	runner *scenario.Runner
}

// NewScenarioTests returns ScenarioTests over the M11.1 scenario runner.
func NewScenarioTests(runner *scenario.Runner) *ScenarioRunner {
	return &ScenarioRunner{runner: runner}
}

// NoPublishedPolicy is TestCounts.Error when the org has no published
// policy to test against.
const NoPublishedPolicy = "NO_PUBLISHED_POLICY"

// covers reports whether an operation pattern (exact or "x.*") covers op.
func opCovers(pattern, op string) bool {
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(op, p)
	}
	return pattern == op
}

// Run implements ScenarioTests: the published bundle's cases whose
// operation one of operations covers, run as the publish gate runs them;
// the counts are the cases' (the mutation gate is not reported).
func (r *ScenarioRunner) Run(ctx context.Context, tx pgx.Tx, org ids.OrgID, operations []string) (TestCounts, error) {
	if r.runner == nil {
		return TestCounts{}, ErrUnwired
	}
	row, err := dbq.New(tx).GetPublishedPolicy(ctx, org)
	if db.IsNoRows(err) {
		return TestCounts{Error: NoPublishedPolicy}, nil
	} else if err != nil {
		return TestCounts{}, err
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(row.Bundle, &b); err != nil {
		return TestCounts{}, err
	}
	out := TestCounts{Bundle: b.ID, Version: b.Version}
	b.Tests = slices.DeleteFunc(b.Tests, func(tc pdomain.TestCase) bool {
		return !slices.ContainsFunc(operations, func(p string) bool { return opCovers(p, tc.Action.Operation) })
	})
	if len(b.Tests) == 0 {
		out.Error = pdomain.ErrNoCases
		return out, nil
	}
	res, err := r.runner.Run(ctx, org, &b)
	if err != nil {
		return TestCounts{}, err
	}
	out.Error = res.Error
	for _, c := range res.Cases {
		out.Cases++
		if c.Passed {
			out.Passed++
		} else {
			out.Failed++
		}
	}
	return out, nil
}
