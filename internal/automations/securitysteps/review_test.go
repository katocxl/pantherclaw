// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"encoding/json/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// reviewFakes serve every review tie. They record what was asked; none
// can validate, test or publish a policy (HR-286).
type reviewFakes struct {
	t         *testing.T
	frozen    bool
	calls     int
	unused    []UnusedGrant
	published *pdomain.Bundle
	pubID     ids.UUID
	drafts    []*pdomain.Bundle
	authors   []evdomain.Actor
	draftID   ids.UUID
	sims      []SimulationRequest
	simID     ids.UUID
	status    SimulationStatus
	counts    map[string]map[string]int64
	countedIn [][]ids.UUID
	cs        CaseScope
	packs     []evapp.AutomationPack
	packID    ids.UUID
}

func (f *reviewFakes) touch() {
	f.calls++
	if f.frozen {
		f.t.Fatal("a preview called a platform tie")
	}
}

func (f *reviewFakes) Unused(context.Context, pgx.Tx, ids.OrgID, time.Time, int) ([]UnusedGrant, error) {
	f.touch()
	return f.unused, nil
}

func (f *reviewFakes) Published(context.Context, pgx.Tx, ids.OrgID) (*pdomain.Bundle, ids.UUID, error) {
	f.touch()
	return f.published, f.pubID, nil
}

func (f *reviewFakes) CreateDraft(_ context.Context, _ pgx.Tx, _ ids.OrgID, b *pdomain.Bundle, author evdomain.Actor) (ids.UUID, int, error) {
	f.touch()
	f.drafts, f.authors = append(f.drafts, b), append(f.authors, author)
	return f.draftID, 2, nil
}

func (f *reviewFakes) Request(_ context.Context, _ pgx.Tx, in SimulationRequest) (ids.UUID, error) {
	f.touch()
	f.sims = append(f.sims, in)
	return f.simID, nil
}

func (f *reviewFakes) Status(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (SimulationStatus, error) {
	f.touch()
	return f.status, nil
}

func (f *reviewFakes) Counts(_ context.Context, _ pgx.Tx, _ ids.OrgID, section string, _, _ time.Time, agents []ids.UUID) (map[string]int64, error) {
	f.touch()
	f.countedIn = append(f.countedIn, agents)
	return f.counts[section], nil
}

func (f *reviewFakes) Case(context.Context, pgx.Tx, ids.OrgID, ids.UUID, int) (CaseScope, error) {
	f.touch()
	return f.cs, nil
}

func (f *reviewFakes) CreateForAutomationTx(_ context.Context, _ pgx.Tx, in evapp.AutomationPack) (ids.UUID, error) {
	f.touch()
	f.packs = append(f.packs, in)
	return f.packID, nil
}

func newReview(t *testing.T) (*reviewFakes, *recProposals, autoports.StepRegistry) {
	t.Helper()
	f := &reviewFakes{t: t, draftID: ids.NewV7(), simID: ids.NewV7(), packID: ids.NewV7(), pubID: ids.NewV7()}
	p := &recProposals{t: t}
	reg := reviewSteps(Deps{Grants: noGrants{t}, Review: ReviewDeps{
		Unused: f, Drafts: f, Simulations: f, Digests: f, Packs: f, Proposals: p,
	}})
	return f, p, reg
}

func reviewWith(kind string) any {
	switch kind {
	case autodomain.KindDraftRestriction:
		return &autodomain.DraftRestrictionWith{From: "UNUSED_GRANTS", Days: 30}
	case autodomain.KindSimulateRestriction:
		return &autodomain.SimulateRestrictionWith{Step: "draft", Days: 14}
	}
	return &autodomain.BuildDigestWith{Scope: autodomain.ScopeTimeRange, Days: 7, Sections: []string{SectionDecisions}, Evidence: allAgents}
}

func reviewScope(kind string) string {
	if kind == autodomain.KindBuildDigest {
		return autodomain.ScopeTimeRange
	}
	return autodomain.ScopeOrg
}

var reviewKinds = []string{autodomain.KindDraftRestriction, autodomain.KindSimulateRestriction, autodomain.KindBuildDigest}

// simulateCtx is a simulate_restriction step after a draft_restriction
// step "draft" with output out.
func simulateCtx(out map[string]string) autodomain.StepContext {
	sc := stepCtx(autodomain.KindSimulateRestriction, "sim", reviewWith(autodomain.KindSimulateRestriction), []string{autodomain.ScopeOrg})
	sc.Def.Do = append([]autodomain.StepSpec{{ID: "draft", Step: autodomain.KindDraftRestriction}}, sc.Def.Do...)
	sc.Index, sc.Spec = 1, sc.Def.Do[1]
	if out != nil {
		sc.Outputs["draft"] = out
	}
	return sc
}

// TestReview_RefusesOutsideItsScope: draft and simulate need ORG, a digest
// its scope, in the platform section (HR-279).
func TestReview_RefusesOutsideItsScope(t *testing.T) {
	ctx := context.Background()
	for _, kind := range reviewKinds {
		f, p, reg := newReview(t)
		sc := stepCtx(kind, "s", reviewWith(kind), []string{autodomain.ScopeTriggerAgent})
		if kind == autodomain.KindSimulateRestriction {
			sc = simulateCtx(map[string]string{OutPolicyVersion: ids.NewV7().String()})
			sc.Def.Authority.Platform = nil
		}
		r, err := reg[kind].Run(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, ReasonOutsideScope)
		r, err = reg[kind].Preview(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, ReasonOutsideScope)
		if f.calls != 0 || len(p.rows) != 0 {
			t.Fatalf("%s acted outside its scope", kind)
		}
	}
	// A digest of the trigger's case needs TRIGGER_CASE, not TIME_RANGE.
	_, _, reg := newReview(t)
	sc := stepCtx(autodomain.KindBuildDigest, "d",
		&autodomain.BuildDigestWith{Scope: autodomain.ScopeTriggerCase, Sections: []string{SectionHolds}, Evidence: allAgents}, []string{autodomain.ScopeTimeRange},
		reflexdomain.Subject{Type: reflexdomain.SubjectCase, ID: ids.NewV7().String()})
	r, err := reg[autodomain.KindBuildDigest].Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonOutsideScope)
}

// TestReview_PreviewWritesNothing: previews validate only (HR-288).
func TestReview_PreviewWritesNothing(t *testing.T) {
	ctx := context.Background()
	for _, kind := range reviewKinds {
		f, p, reg := newReview(t)
		f.frozen, p.frozen = true, true
		sc := stepCtx(kind, "s", reviewWith(kind), []string{reviewScope(kind)})
		if kind == autodomain.KindSimulateRestriction {
			sc = simulateCtx(nil)
		}
		sc.Mode = autodomain.ModeTest
		r, err := reg[kind].Preview(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepShadowed, "")
		if r.Output["shadow"] != "true" || r.Effect != autodomain.EffectNone {
			t.Fatalf("%s preview: %+v", kind, r)
		}
	}
}

// TestReview_UnwiredIsUnsupported fails closed without its ties.
func TestReview_UnwiredIsUnsupported(t *testing.T) {
	ctx := context.Background()
	reg := reviewSteps(Deps{})
	for _, kind := range reviewKinds {
		sc := stepCtx(kind, "s", reviewWith(kind), []string{reviewScope(kind)})
		if kind == autodomain.KindSimulateRestriction {
			sc = simulateCtx(map[string]string{OutPolicyVersion: ids.NewV7().String(), "drafted": "true"})
		}
		r, err := reg[kind].Run(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, engine.ReasonUnsupported)
	}
}

// TestHR286_DraftRestrictionIsNeverPublished: draft_restriction writes a
// DRAFT through PolicyDrafts (which has no validate, test or publish
// method), authored by the automation, keeps the published rules and
// proposes it; it never touches a grant.
func TestHR286_DraftRestrictionIsNeverPublished(t *testing.T) {
	f, p, reg := newReview(t)
	a1, a2 := ids.NewV7(), ids.NewV7()
	f.published = &pdomain.Bundle{ID: "main", Version: 4, Rules: []pdomain.Rule{{ID: "keep", Kind: pdomain.Forbid}}}
	f.unused = []UnusedGrant{
		{ID: ids.NewV7(), Agent: a1, Operations: []string{"repo.write", "repo.*"}},
		{ID: ids.NewV7(), Agent: a1, Operations: []string{"repo.write"}},
		{ID: ids.NewV7(), Agent: a2, Operations: []string{"payments.refund.create"}},
		{ID: ids.NewV7(), Agent: a2}, // not bounded by operation: not restricted
	}
	sc := stepCtx(autodomain.KindDraftRestriction, "draft", reviewWith(autodomain.KindDraftRestriction), []string{autodomain.ScopeOrg})
	r, err := reg[autodomain.KindDraftRestriction].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if len(f.drafts) != 1 {
		t.Fatalf("drafts: %d", len(f.drafts))
	}
	d := f.drafts[0]
	if d.ID != "main" || len(d.Rules) != 3 || d.Rules[0].ID != "keep" || f.published.Rules[0].ID != "keep" || len(f.published.Rules) != 1 {
		t.Fatalf("draft: %+v (published %+v)", d, f.published)
	}
	for _, r := range d.Rules[1:] {
		if r.Kind != pdomain.Forbid || r.Reason != RestrictionReason || !strings.HasPrefix(r.ID, restrictionPrefix) ||
			!strings.Contains(r.When, "run.agent_id ==") || r.Validate() != nil {
			t.Fatalf("restriction rule: %+v (%v)", r, r.Validate())
		}
	}
	if i := slices.IndexFunc(d.Rules, func(r pdomain.Rule) bool { return r.ID == restrictionPrefix+a1.String() }); i < 0 ||
		!slices.Equal(d.Rules[i].Operations, []string{"repo.*", "repo.write"}) {
		t.Fatalf("agent rule: %+v", d.Rules)
	}
	if f.authors[0].Type != "automation" || f.authors[0].ID != sc.Execution.Automation.String() {
		t.Fatalf("author: %+v", f.authors[0])
	}
	if len(p.rows) != 1 || p.rows[0].kind != ProposalRestriction || p.rows[0].about != ProposalAboutPolicy || p.rows[0].subject != f.draftID {
		t.Fatalf("proposals: %+v", p.rows)
	}
	var body restrictionBody
	if err := json.Unmarshal(p.rows[0].body, &body); err != nil || body.UnusedGrants != 4 || body.Unbounded != 1 || len(body.Agents) != 2 ||
		body.Base != f.pubID.String() {
		t.Fatalf("body %s: %v", p.rows[0].body, err)
	}
	if r.Output[OutPolicyVersion] != f.draftID.String() || r.Output[OutProposal] != p.rows[0].id.String() || r.Output["drafted"] != "true" ||
		r.Effect != autodomain.EffectNone || !hasRef(r, RefPolicyVersion, f.draftID) || !hasRef(r, RefProposal, p.rows[0].id) {
		t.Fatalf("result: %+v", r)
	}

	// Nothing unused: nothing drafted.
	f2, p2, reg2 := newReview(t)
	r, err = reg2[autodomain.KindDraftRestriction].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if r.Output["drafted"] != "false" || len(f2.drafts) != 0 || len(p2.rows) != 0 {
		t.Fatalf("nothing unused: %+v", r)
	}
	// Fewer than 7 days is refused.
	sc.With = &autodomain.DraftRestrictionWith{From: "UNUSED_GRANTS", Days: 6}
	r, err = reg2[autodomain.KindDraftRestriction].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
}

// TestReview_RestrictionDraftReplacesItsRule: a later draft replaces the
// rule an earlier one wrote for the same agent and leaves the base alone.
func TestReview_RestrictionDraftReplacesItsRule(t *testing.T) {
	a := ids.NewV7()
	first := RestrictionDraft(nil, map[ids.UUID][]string{a: {"x.read"}}, 30)
	if first.ID != DraftBundleID || len(first.Rules) != 1 {
		t.Fatalf("first: %+v", first)
	}
	second := RestrictionDraft(first, map[ids.UUID][]string{a: {"y.read"}}, 14)
	if len(second.Rules) != 1 || second.Rules[0].Operations[0] != "y.read" || first.Rules[0].Operations[0] != "x.read" {
		t.Fatalf("second: %+v, first %+v", second.Rules, first.Rules)
	}
	if err := second.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestReview_SimulateRestriction simulates the named draft step's version,
// waits, and reports the counts; a failed simulation fails the step.
func TestReview_SimulateRestriction(t *testing.T) {
	ctx := context.Background()
	f, p, reg := newReview(t)
	s := reg[autodomain.KindSimulateRestriction]
	version := ids.NewV7()
	sc := simulateCtx(map[string]string{OutPolicyVersion: version.String(), "drafted": "true"})
	r, err := s.Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepWaiting, "")
	if len(f.sims) != 1 || f.sims[0].Version != version || f.sims[0].Days != 14 || f.sims[0].Actor.Type != "automation" {
		t.Fatalf("requests: %+v", f.sims)
	}
	if r.Output[OutSimulation] != f.simID.String() || !r.WakeAt.Equal(sc.Now.Add(15*time.Second)) {
		t.Fatalf("waiting: %+v", r)
	}
	sc.Outputs["sim"] = r.Output
	f.status = SimulationStatus{State: simulation.Running}
	r, err = s.Poll(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepWaiting, "")
	f.status = SimulationStatus{State: simulation.Done, Evaluated: 10, Counts: map[replay.Category]int{
		replay.NewlyDenied: 3, replay.NewlyHeld: 1, replay.Unchanged: 6,
	}}
	r, err = s.Poll(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if r.Output["newly_denied"] != "3" || r.Output["newly_held"] != "1" || r.Output["newly_allowed"] != "0" || r.Output["evaluated"] != "10" ||
		!hasRef(r, RefSimulation, f.simID) || !hasRef(r, RefPolicyVersion, version) || len(p.rows) != 0 {
		t.Fatalf("done: %+v", r)
	}
	f.status = SimulationStatus{State: simulation.Failed}
	r, err = s.Poll(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonSimulation)

	// Nothing drafted: nothing simulated.
	r, err = s.Run(ctx, nil, simulateCtx(map[string]string{"drafted": "false"}))
	mustState(t, r, err, autodomain.StepDone, "")
	if r.Output["simulated"] != "false" || len(f.sims) != 1 {
		t.Fatalf("nothing drafted: %+v", r)
	}
	// The step must name an earlier draft_restriction step.
	bad := simulateCtx(map[string]string{OutPolicyVersion: version.String()})
	bad.Def.Do[0].Step = autodomain.KindDraftBaseline
	r, err = s.Run(ctx, nil, bad)
	mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
	bad = simulateCtx(map[string]string{OutPolicyVersion: version.String()})
	bad.With = &autodomain.SimulateRestrictionWith{Step: "draft", Days: 31}
	r, err = s.Run(ctx, nil, bad)
	mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
}

// TestReview_BuildDigest builds a report of counts and links within the
// declared agents and a pack the automation's service account creates;
// its output carries what deliver reads (D85).
func TestReview_BuildDigest(t *testing.T) {
	ctx := context.Background()
	f, _, reg := newReview(t)
	s := reg[autodomain.KindBuildDigest]
	f.counts = map[string]map[string]int64{
		SectionDecisions: {"ALLOW": 5, "DENY": 2},
		SectionHolds:     {"PENDING": 1},
	}
	declared := []ids.UUID{ids.NewV7()}
	w := &autodomain.BuildDigestWith{
		Scope: autodomain.ScopeTimeRange, Days: 7, Sections: []string{SectionDecisions, SectionHolds}, Title: "Weekly", Evidence: agentsOf(declared...),
	}
	sc := stepCtx(autodomain.KindBuildDigest, "digest", w, []string{autodomain.ScopeTimeRange})
	sc.Execution.ServiceAccount = ids.NewV7()
	r, err := s.Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if r.Output[OutPack] != f.packID.String() || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(r.Output[OutReportDigest]) ||
		r.Output["decisions_total"] != "7" || r.Output["holds_total"] != "1" || r.Output["agents"] != "1" ||
		r.Effect != autodomain.EffectChanged || !hasRef(r, RefPack, f.packID) {
		t.Fatalf("digest: %+v", r)
	}
	if len(f.packs) != 1 {
		t.Fatalf("packs: %+v", f.packs)
	}
	pk := f.packs[0]
	if pk.ServiceAccount != sc.Execution.ServiceAccount || pk.Automation != sc.Execution.Automation || pk.Execution != sc.Execution.ID ||
		!slices.Equal(pk.Agents, declared) || pk.Request.Kind != "time_range" || pk.Request.From == nil || pk.Request.To == nil ||
		pk.Request.To.Sub(*pk.Request.From) != 7*24*time.Hour || !pk.Request.To.Equal(sc.Now) {
		t.Fatalf("pack: %+v", pk)
	}
	for _, in := range f.countedIn {
		if !slices.Equal(in, declared) {
			t.Fatalf("counted outside the declared agents: %v", in)
		}
	}
	// The same counts make the same report.
	r2, err := s.Run(ctx, nil, sc)
	mustState(t, r2, err, autodomain.StepDone, "")
	if r2.Output[OutReportDigest] != r.Output[OutReportDigest] {
		t.Fatal("report digest is not deterministic")
	}
	// All agents: no agent list on the pack or the counts.
	w.Evidence, f.countedIn = allAgents, nil
	r, err = s.Run(ctx, nil, sc)
	mustState(t, r, err, autodomain.StepDone, "")
	if r.Output["agents"] != "all" || f.packs[2].Agents != nil || f.countedIn[0] != nil {
		t.Fatalf("all agents: %+v, %+v", r.Output, f.packs[2])
	}

	// The trigger's case: a pack of its linked transactions, its link.
	cse, txn := ids.NewV7(), ids.NewV7()
	f.cs = CaseScope{From: sc.Now.Add(-48 * time.Hour), To: sc.Now.Add(-time.Hour), Transactions: []ids.UUID{txn}}
	cw := &autodomain.BuildDigestWith{Scope: autodomain.ScopeTriggerCase, Sections: []string{SectionOpenItems}, Evidence: allAgents}
	csc := stepCtx(autodomain.KindBuildDigest, "digest", cw, []string{autodomain.ScopeTriggerCase},
		reflexdomain.Subject{Type: reflexdomain.SubjectCase, ID: cse.String()})
	csc.Execution.ServiceAccount = ids.NewV7()
	r, err = s.Run(ctx, nil, csc)
	mustState(t, r, err, autodomain.StepDone, "")
	pk = f.packs[3]
	if r.Output[OutCase] != cse.String() || !hasRef(r, RefCase, cse) || r.Output["transactions"] != "1" ||
		pk.Request.Kind != "transactions" || !slices.Equal(pk.Request.Transactions, []ids.UUID{txn}) || pk.Request.From != nil {
		t.Fatalf("case digest: %+v, %+v", r, pk)
	}
	// A case that links no transaction: the report only, no pack.
	f.cs.Transactions = nil
	r, err = s.Run(ctx, nil, csc)
	mustState(t, r, err, autodomain.StepDone, "")
	if r.Output[OutPack] != OutPackNone || len(f.packs) != 4 || r.Output[OutReportDigest] == "" || r.Effect != autodomain.EffectNone {
		t.Fatalf("case without transactions: %+v", r)
	}
	// No case among the trigger's subjects.
	csc.Execution.Trigger.Subjects = nil
	r, err = s.Run(ctx, nil, csc)
	mustState(t, r, err, autodomain.StepFailed, ReasonNoSubject)
	r, err = s.Preview(ctx, nil, csc)
	mustState(t, r, err, autodomain.StepFailed, ReasonNoSubject)

	// Bad sections and days.
	for _, bad := range []*autodomain.BuildDigestWith{
		{Scope: autodomain.ScopeTimeRange, Days: 7, Evidence: allAgents},
		{Scope: autodomain.ScopeTimeRange, Days: 7, Sections: []string{"payloads"}, Evidence: allAgents},
		{Scope: autodomain.ScopeTimeRange, Days: 7, Sections: []string{SectionAlerts, SectionAlerts}, Evidence: allAgents},
		{Scope: autodomain.ScopeTimeRange, Days: 32, Sections: []string{SectionAlerts}, Evidence: allAgents},
		{Scope: "EVERYTHING", Sections: []string{SectionAlerts}, Evidence: allAgents},
	} {
		sc.With = bad
		r, err = s.Run(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
	}
	// No scope, an empty or oversized agent list, or both agents and all
	// is no declared scope.
	tooMany := make([]ids.UUID, evapp.MaxAutomationPackAgents+1)
	for i := range tooMany {
		tooMany[i] = ids.NewV7()
	}
	for _, ev := range []autodomain.DigestEvidence{{}, {Agents: []autodomain.RefID{}}, agentsOf(tooMany...), {Agents: agentsOf(declared...).Agents, All: true}} {
		bad := *w
		bad.Evidence = ev
		sc.With = &bad
		r, err = s.Run(ctx, nil, sc)
		mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
	}
}

// TestReview_DigestNeedsADeclaredScope: a build_digest that declares no
// evidence scope is refused WITH_INVALID, in the step and its preview,
// and nothing is read or written (D85).
func TestReview_DigestNeedsADeclaredScope(t *testing.T) {
	f, _, _ := newReview(t)
	reg := reviewSteps(Deps{Review: ReviewDeps{Digests: f, Packs: f}})
	w := reviewWith(autodomain.KindBuildDigest).(*autodomain.BuildDigestWith)
	w.Evidence = autodomain.DigestEvidence{}
	sc := stepCtx(autodomain.KindBuildDigest, "d", w, []string{autodomain.ScopeTimeRange})
	r, err := reg[autodomain.KindBuildDigest].Run(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
	r, err = reg[autodomain.KindBuildDigest].Preview(context.Background(), nil, sc)
	mustState(t, r, err, autodomain.StepFailed, ReasonBadWith)
	if f.calls != 0 {
		t.Fatalf("calls: %d", f.calls)
	}
}

// TestReview_DigestReportHoldsNoContent: the report is counts and links;
// its digest is the canonical JSON's SHA-256.
func TestReview_DigestReportHoldsNoContent(t *testing.T) {
	rep := digestReport{Format: DigestFormat, Sections: map[string]map[string]int64{"alerts": {"HIGH": 2}}, Links: []digestLink{{Kind: RefPack, ID: "x"}}}
	a, err := DigestReportDigest(rep)
	if err != nil {
		t.Fatal(err)
	}
	rep.Sections["alerts"]["HIGH"] = 3
	b, _ := DigestReportDigest(rep)
	if a == b || len(a) != 64 {
		t.Fatalf("digests %s %s", a, b)
	}
}

// allAgents is `evidence: {all: true}`.
var allAgents = autodomain.DigestEvidence{All: true}

// agentsOf is `evidence: {agents: [...]}`.
func agentsOf(agents ...ids.UUID) autodomain.DigestEvidence {
	ev := autodomain.DigestEvidence{Agents: make([]autodomain.RefID, 0, len(agents))}
	for _, a := range agents {
		ev.Agents = append(ev.Agents, autodomain.RefID(a))
	}
	return ev
}
