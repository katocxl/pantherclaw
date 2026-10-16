// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"encoding/json/v2"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// recProposals records proposals in memory; a call while frozen fails
// the test (a preview must write nothing, HR-288).
type recProposals struct {
	t      *testing.T
	frozen bool
	rows   []recProposal
}

type recProposal struct {
	id         ids.UUID
	step, kind string
	about      string
	subject    ids.UUID
	body       []byte
	execution  ids.UUID
}

func (p *recProposals) Propose(_ context.Context, _ pgx.Tx, sc autodomain.StepContext, kind, about string, subject ids.UUID, body any) (ids.UUID, error) {
	if p.frozen {
		p.t.Fatalf("proposal %s written in a preview", kind)
	}
	raw, err := json.Marshal(body, json.Deterministic(true))
	if err != nil {
		return ids.UUID{}, err
	}
	for i := range p.rows {
		r := &p.rows[i]
		if r.execution == sc.Execution.ID && r.step == sc.Spec.ID && r.subject == subject {
			return r.id, nil
		}
	}
	id := ids.NewV7()
	p.rows = append(p.rows, recProposal{id: id, step: sc.Spec.ID, kind: kind, about: about, subject: subject, body: raw, execution: sc.Execution.ID})
	return id, nil
}

func (p *recProposals) Body(_ context.Context, _ pgx.Tx, _ ids.OrgID, id ids.UUID) (string, []byte, error) {
	for _, r := range p.rows {
		if r.id == id {
			return r.kind, r.body, nil
		}
	}
	return "", nil, pgx.ErrNoRows
}

// intakeFakes serve every intake tie; calls counts every read.
type intakeFakes struct {
	t      *testing.T
	frozen bool
	calls  int
	agent  AgentInfo
	cands  []OwnerCandidate
	disc   *Discovery
	sum    CoverageSummary
	ops    []string
	cohort Baseline
	tested [][]string
	counts TestCounts
}

func (f *intakeFakes) touch() {
	f.calls++
	if f.frozen {
		f.t.Fatal("a preview called a platform tie")
	}
}

func (f *intakeFakes) Agent(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (AgentInfo, error) {
	f.touch()
	return f.agent, nil
}

func (f *intakeFakes) Candidates(context.Context, pgx.Tx, ids.OrgID, ids.UUID) ([]OwnerCandidate, *Discovery, error) {
	f.touch()
	return f.cands, f.disc, nil
}

func (f *intakeFakes) Summary(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (CoverageSummary, error) {
	f.touch()
	return f.sum, nil
}

func (f *intakeFakes) CohortBaseline(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (Baseline, error) {
	f.touch()
	return f.cohort, nil
}

func (f *intakeFakes) ReadOperations(context.Context, pgx.Tx, ids.OrgID, ids.UUID) ([]string, error) {
	f.touch()
	return f.ops, nil
}

func (f *intakeFakes) Run(_ context.Context, _ pgx.Tx, _ ids.OrgID, ops []string) (TestCounts, error) {
	f.touch()
	f.tested = append(f.tested, ops)
	return f.counts, nil
}

// noGrants fails the test on any grant issue or revoke: intake and review
// kinds never touch grants (HR-286).
type noGrants struct{ t *testing.T }

func (g noGrants) IssueForAutomation(context.Context, pgx.Tx, steps.LaunchIssue) (ids.UUID, error) {
	g.t.Fatal("a grant was issued")
	return ids.UUID{}, nil
}

func (g noGrants) RevokeForAutomation(context.Context, pgx.Tx, steps.GrantRevoke) ([]ids.UUID, error) {
	g.t.Fatal("a grant was revoked")
	return nil, nil
}

func newIntake(t *testing.T) (*intakeFakes, *recProposals, autoports.StepRegistry) {
	t.Helper()
	f := &intakeFakes{t: t}
	p := &recProposals{t: t}
	reg := intakeSteps(Deps{Grants: noGrants{t}, Intake: IntakeDeps{
		Agents: f, Candidates: f, Routes: f, Cohorts: f, Operations: f, Tests: f, Proposals: p,
	}})
	return f, p, reg
}

// stepCtx is a step context of kind with the given platform scopes
// (none: the kind is not in the platform section) and trigger subjects.
func stepCtx(kind, id string, with any, scopes []string, subjects ...reflexdomain.Subject) autodomain.StepContext {
	def := &autodomain.Definition{Do: []autodomain.StepSpec{{ID: id, Step: kind}}}
	if scopes != nil {
		def.Authority.Platform = []autodomain.PlatformScope{{Step: kind, Scopes: scopes}}
	}
	exec := autodomain.ExecutionView{
		ID: ids.NewV7(), Automation: ids.NewV7(), Owner: ids.NewV7(),
		Trigger: autodomain.TriggerRef{Subjects: subjects},
	}
	return autodomain.StepContext{
		Org: ids.New[ids.Org](), Execution: exec, Def: def, Spec: def.Do[0], With: with,
		Outputs: map[string]map[string]string{id: {engine.OutputAttempt: ids.NewV7().String()}},
		Mode:    autodomain.ModeLive, Now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC),
	}
}

func agentSubject(a ids.UUID) reflexdomain.Subject {
	return reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: a.String()}
}

var intakeKinds = []string{
	autodomain.KindProposeOwner, autodomain.KindInspectRoutes, autodomain.KindDraftBaseline,
	autodomain.KindRunSafeTests, autodomain.KindWaitClaim,
}

// intakeWith is a valid `with` of an intake kind.
func intakeWith(kind string) any {
	switch kind {
	case autodomain.KindDraftBaseline:
		return &autodomain.DraftBaselineWith{From: BaselineTemplate}
	case autodomain.KindWaitClaim:
		return &autodomain.WaitClaimWith{Timeout: autodomain.Duration(24 * time.Hour)}
	}
	return &autodomain.IntakeWith{}
}

func mustState(t *testing.T, r autodomain.StepResult, err error, want autodomain.StepState, reason string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if r.State != want || r.Reason != reason {
		t.Fatalf("result %s %q, want %s %q (%+v)", r.State, r.Reason, want, reason, r)
	}
	if !r.Valid() {
		t.Fatalf("output out of bounds: %+v", r.Output)
	}
}

func hasRef(r autodomain.StepResult, kind string, id ids.UUID) bool {
	return slices.Contains(r.Refs, reflexdomain.EvidenceRef{Kind: kind, ID: id})
}

// TestIntake_RefusesOutsideTheTriggerAgent: every intake kind needs
// TRIGGER_AGENT in the platform section and an agent among the trigger's
// subjects (HR-284), and refuses in Run and Preview alike.
func TestIntake_RefusesOutsideTheTriggerAgent(t *testing.T) {
	ctx := context.Background()
	for _, kind := range intakeKinds {
		f, p, reg := newIntake(t)
		agent := ids.NewV7()
		sc := stepCtx(kind, "s", intakeWith(kind), []string{autodomain.ScopeOrg}, agentSubject(agent))
		r, err := reg[kind].Run(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, ReasonOutsideScope)
		r, err = reg[kind].Preview(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, ReasonOutsideScope)
		if r.Output["decision"] != "REFUSED" {
			t.Fatalf("%s preview: %+v", kind, r.Output)
		}
		sc = stepCtx(kind, "s", intakeWith(kind), []string{autodomain.ScopeTriggerAgent},
			reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: ids.NewV7().String()})
		r, err = reg[kind].Run(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, ReasonNoSubject)
		if f.calls != 0 || len(p.rows) != 0 {
			t.Fatalf("%s acted outside its scope: %d calls, %d proposals", kind, f.calls, len(p.rows))
		}
	}
}

// TestIntake_PreviewWritesNothing: a preview validates and returns the
// would-be result without reading or writing anything (HR-288).
func TestIntake_PreviewWritesNothing(t *testing.T) {
	ctx := context.Background()
	for _, kind := range intakeKinds {
		f, p, reg := newIntake(t)
		f.frozen, p.frozen = true, true
		sc := stepCtx(kind, "s", intakeWith(kind), []string{autodomain.ScopeTriggerAgent}, agentSubject(ids.NewV7()))
		sc.Mode = autodomain.ModeShadow
		r, err := reg[kind].Preview(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepShadowed, "")
		if r.Output["shadow"] != "true" || r.Effect != autodomain.EffectNone {
			t.Fatalf("%s preview: %+v", kind, r)
		}
	}
}

// TestIntake_UnwiredIsUnsupported: a kind whose tie is not wired fails
// UNSUPPORTED_CAPABILITY rather than pretend.
func TestIntake_UnwiredIsUnsupported(t *testing.T) {
	ctx := context.Background()
	reg := intakeSteps(Deps{})
	for _, kind := range intakeKinds {
		sc := stepCtx(kind, "s", intakeWith(kind), []string{autodomain.ScopeTriggerAgent}, agentSubject(ids.NewV7()))
		if kind == autodomain.KindRunSafeTests {
			continue // needs its baseline first; covered below
		}
		r, err := reg[kind].Run(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, ReasonDependency)
	}
	cohort := stepCtx(autodomain.KindDraftBaseline, "b", &autodomain.DraftBaselineWith{From: BaselineCohort},
		[]string{autodomain.ScopeTriggerAgent}, agentSubject(ids.NewV7()))
	f := &intakeFakes{t: t}
	reg = intakeSteps(Deps{Intake: IntakeDeps{Operations: f, Proposals: &recProposals{t: t}}})
	r, err := reg[autodomain.KindDraftBaseline].Run(ctx, nil, cohort)
	mustState(t, r, err, autodomain.StepFailed, ReasonDependency)
}

// TestIntake_ProposeOwner records an OWNER proposal about the trigger's
// agent with its candidates and why.
func TestIntake_ProposeOwner(t *testing.T) {
	f, p, reg := newIntake(t)
	agent, alice := ids.NewV7(), ids.NewV7()
	f.cands = []OwnerCandidate{{User: alice, Why: []string{WhyDiscovered}}}
	f.disc = &Discovery{Source: "scan", ObservedKeys: []string{"path"}}
	sc := stepCtx(autodomain.KindProposeOwner, "owner", &autodomain.IntakeWith{}, []string{autodomain.ScopeTriggerAgent}, agentSubject(agent))
	r, err := reg[autodomain.KindProposeOwner].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if len(p.rows) != 1 || p.rows[0].kind != ProposalOwner || p.rows[0].about != ProposalAboutAgent || p.rows[0].subject != agent {
		t.Fatalf("proposals: %+v", p.rows)
	}
	var body ownerBody
	if err := json.Unmarshal(p.rows[0].body, &body); err != nil || len(body.Candidates) != 1 || body.Candidates[0].User != alice ||
		body.Discovery == nil || body.Agent != agent.String() {
		t.Fatalf("body %s: %v", p.rows[0].body, err)
	}
	if r.Output[OutProposal] != p.rows[0].id.String() || r.Output["candidates"] != "1" || r.Effect != autodomain.EffectNone ||
		!hasRef(r, RefProposal, p.rows[0].id) || !hasRef(r, RefAgent, agent) {
		t.Fatalf("result: %+v", r)
	}
	// A repeat of the step returns the same proposal.
	r2, err := reg[autodomain.KindProposeOwner].Poll(context.Background(), nil, sc)
	mustState(t, r2, err, autodomain.StepDone, "")
	if r2.Output[OutProposal] != r.Output[OutProposal] || len(p.rows) != 1 {
		t.Fatalf("repeat: %+v, %d proposals", r2.Output, len(p.rows))
	}
}

// TestIntake_InspectRoutes puts the coverage summary in the output and
// proposes nothing.
func TestIntake_InspectRoutes(t *testing.T) {
	f, p, reg := newIntake(t)
	f.sum = CoverageSummary{Routes: 3, Scopes: 4, ByState: map[string]int{"ENFORCED": 1, "PARTIAL": 1, "UNKNOWN": 2}}
	agent := ids.NewV7()
	sc := stepCtx(autodomain.KindInspectRoutes, "routes", &autodomain.IntakeWith{}, []string{autodomain.ScopeTriggerAgent}, agentSubject(agent))
	r, err := reg[autodomain.KindInspectRoutes].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	want := map[string]string{"routes": "3", "scopes": "4", "enforced": "1", "partial": "1", "observe_only": "0", "unknown": "2", "truncated": "false"}
	for k, v := range want {
		if r.Output[k] != v {
			t.Fatalf("output %s = %q, want %q (%+v)", k, r.Output[k], v, r.Output)
		}
	}
	if len(p.rows) != 0 || r.Effect != autodomain.EffectNone {
		t.Fatalf("inspect_routes wrote: %d proposals, effect %s", len(p.rows), r.Effect)
	}
}

// TestHR286_DraftBaselineIsAProposalNeverAGrant: draft_baseline records a
// BASELINE proposal (a template: read access, a day, no delegation) and
// issues nothing; COHORT_BASELINE proposes the cohort's baseline.
func TestHR286_DraftBaselineIsAProposalNeverAGrant(t *testing.T) {
	f, p, reg := newIntake(t)
	f.ops = []string{"repo.read", "issues.list", "repo.read"}
	agent := ids.NewV7()
	sc := stepCtx(autodomain.KindDraftBaseline, "baseline", &autodomain.DraftBaselineWith{From: BaselineTemplate},
		[]string{autodomain.ScopeTriggerAgent}, agentSubject(agent))
	r, err := reg[autodomain.KindDraftBaseline].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if len(p.rows) != 1 || p.rows[0].kind != ProposalBaseline || r.Effect != autodomain.EffectNone || r.Output["operations"] != "2" {
		t.Fatalf("result %+v, proposals %+v", r, p.rows)
	}
	var body baselineBody
	if err := json.Unmarshal(p.rows[0].body, &body); err != nil {
		t.Fatal(err)
	}
	b := body.Baseline
	if b.From != BaselineTemplate || !slices.Equal(b.Operations(), []string{"issues.list", "repo.read"}) ||
		b.Bounds.Access == nil || !slices.Equal(b.Bounds.Access.IDs, []string{"read"}) || b.TTLSeconds != 86400 || b.DelegationDepth != 0 {
		t.Fatalf("baseline: %+v", b)
	}

	f2, p2, reg2 := newIntake(t)
	f2.cohort = TemplateBaseline([]string{"repo.*"})
	sc = stepCtx(autodomain.KindDraftBaseline, "baseline", &autodomain.DraftBaselineWith{From: BaselineCohort},
		[]string{autodomain.ScopeTriggerAgent}, agentSubject(agent))
	r, err = reg2[autodomain.KindDraftBaseline].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if json.Unmarshal(p2.rows[0].body, &body) != nil || body.Baseline.From != BaselineCohort || r.Output["from"] != BaselineCohort {
		t.Fatalf("cohort baseline: %s", p2.rows[0].body)
	}

	sc.With = &autodomain.DraftBaselineWith{From: "GRANT"}
	r, err = reg2[autodomain.KindDraftBaseline].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
}

// TestIntake_RunSafeTests tests the operations of the draft_baseline
// step's proposal and proposes the counts; without a baseline it fails.
func TestIntake_RunSafeTests(t *testing.T) {
	ctx := context.Background()
	f, p, reg := newIntake(t)
	f.ops = []string{"repo.read"}
	f.counts = TestCounts{Bundle: "main", Version: 3, Cases: 4, Passed: 3, Failed: 1}
	agent := ids.NewV7()
	base := stepCtx(autodomain.KindDraftBaseline, "baseline", &autodomain.DraftBaselineWith{From: BaselineTemplate},
		[]string{autodomain.ScopeTriggerAgent}, agentSubject(agent))
	br, err := reg[autodomain.KindDraftBaseline].Run(ctx, nil, base)
	mustState(t, br, err, autodomain.StepDone, "")

	sc := stepCtx(autodomain.KindRunSafeTests, "tests", &autodomain.IntakeWith{}, []string{autodomain.ScopeTriggerAgent}, agentSubject(agent))
	sc.Execution = base.Execution
	sc.Def.Do = append([]autodomain.StepSpec{{ID: "baseline", Step: autodomain.KindDraftBaseline}}, sc.Def.Do...)
	sc.Def.Authority.Platform = append(sc.Def.Authority.Platform, base.Def.Authority.Platform...)
	sc.Index, sc.Spec = 1, sc.Def.Do[1]
	// Without the baseline step's output, nothing is tested.
	r, err := reg[autodomain.KindRunSafeTests].Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonNoBaseline)

	sc.Outputs["baseline"] = br.Output
	r, err = reg[autodomain.KindRunSafeTests].Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if len(f.tested) != 1 || !slices.Equal(f.tested[0], []string{"repo.read"}) {
		t.Fatalf("tested: %v", f.tested)
	}
	if r.Output["cases"] != "4" || r.Output["passed"] != "3" || r.Output["failed"] != "1" || len(p.rows) != 2 || p.rows[1].kind != ProposalTests {
		t.Fatalf("result %+v, proposals %d", r.Output, len(p.rows))
	}
	// A baseline of another agent is not this step's baseline.
	sc.Execution.Trigger.Subjects = []reflexdomain.Subject{agentSubject(ids.NewV7())}
	r, err = reg[autodomain.KindRunSafeTests].Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonNoBaseline)
}

// TestIntake_WaitClaim waits until the agent is claimed with an owner,
// and fails past its timeout or when the agent is retired.
func TestIntake_WaitClaim(t *testing.T) {
	ctx := context.Background()
	f, p, reg := newIntake(t)
	s := reg[autodomain.KindWaitClaim]
	agent := ids.NewV7()
	f.agent = AgentInfo{ID: agent, State: "DISCOVERED"}
	sc := stepCtx(autodomain.KindWaitClaim, "claim", &autodomain.WaitClaimWith{Timeout: autodomain.Duration(time.Hour)},
		[]string{autodomain.ScopeTriggerAgent}, agentSubject(agent))
	r, err := s.Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepWaiting, "")
	if !r.WakeAt.Equal(sc.Now.Add(15*time.Second)) || r.Output[steps.OutUntil] != rfc(sc.Now.Add(time.Hour)) {
		t.Fatalf("waiting: %+v", r)
	}
	sc.Outputs["claim"] = r.Output
	owner, at := ids.NewV7(), sc.Now
	f.agent = AgentInfo{ID: agent, State: "CLAIMED", Owner: &owner, ClaimedAt: &at}
	sc.Now = sc.Now.Add(time.Minute)
	r, err = s.Poll(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if r.Output["owner"] != owner.String() || !hasRef(r, RefAgent, agent) || len(p.rows) != 0 {
		t.Fatalf("claimed: %+v", r)
	}
	// Claimed without an owner is not claimed; past the timeout it fails.
	f.agent = AgentInfo{ID: agent, State: "CLAIMED", ClaimedAt: &at}
	sc.Now = sc.Now.Add(2 * time.Hour)
	r, err = s.Poll(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonNotClaimed)
	f.agent = AgentInfo{ID: agent, State: "RETIRED"}
	sc.Now = sc.Now.Add(-2 * time.Hour)
	r, err = s.Poll(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonRetired)
	// The timeout is at most 30 days.
	sc.With = &autodomain.WaitClaimWith{Timeout: autodomain.Duration(31 * 24 * time.Hour)}
	r, err = s.Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
	r, err = s.Preview(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
}

// TestIntake_TemplateBaseline is bounded, sorted and read only.
func TestIntake_TemplateBaseline(t *testing.T) {
	ops := make([]string, 0, 100)
	for i := range 100 {
		ops = append(ops, "x.op"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	b := TemplateBaseline(ops)
	if n := len(b.Operations()); n != maxBaselineOps {
		t.Fatalf("operations: %d", n)
	}
	if !slices.IsSorted(b.Operations()) {
		t.Fatal("not sorted")
	}
	if e := TemplateBaseline(nil); len(e.Operations()) != 0 || e.Bounds.Operations == nil {
		t.Fatalf("empty baseline allows something: %+v", e.Bounds)
	}
}

// TestIntake_OpCovers matches exact operations and prefixes.
func TestIntake_OpCovers(t *testing.T) {
	for _, c := range []struct {
		p, op string
		want  bool
	}{{"repo.read", "repo.read", true}, {"repo.*", "repo.read", true}, {"repo.*", "repository.read", false}, {"repo.read", "repo.reads", false}} {
		if got := opCovers(c.p, c.op); got != c.want {
			t.Fatalf("opCovers(%q, %q) = %v", c.p, c.op, got)
		}
	}
}
