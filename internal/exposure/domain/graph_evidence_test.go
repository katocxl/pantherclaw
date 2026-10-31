// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func all(domain.Node) bool { return true }

func kinds(es []domain.Edge, kind string) []domain.Edge {
	return slices.DeleteFunc(slices.Clone(es), func(e domain.Edge) bool { return e.Kind != kind })
}

func gapOf(es []domain.Edge, missing string) bool {
	return slices.ContainsFunc(es, func(e domain.Edge) bool { return e.Kind == domain.EdgeGap && e.Provenance == missing })
}

func evidenced() domain.CausalEvidence {
	at := now.Add(time.Second)
	return domain.CausalEvidence{
		Activity: domain.Activity{Run: "r", Agent: "a", Transaction: "t", Operation: "github.pull_request.merge", Decision: "ALLOW", At: now},
		Grant:    "g", Permit: "p", Dispatched: &at, Attempt: "x", AttemptAt: &at, ExecutionReceipt: true,
		EffectSeq: 2, EffectState: "CONFIRMED", EffectBasis: "verifier", EffectAt: &at, Downstream: "PENDING",
		Approvals: []domain.ApprovalEvidence{{ID: "ap", At: &at}},
	}
}

// TestHR551_ACausalLinkAppearsOnlyWithItsEvidence: every causal kind names
// the record behind it, and removing the record leaves a gap, not a link
// (F272, F279, F280).
// Covers: F272, F279, F280, F281
func TestHR551_ACausalLinkAppearsOnlyWithItsEvidence(t *testing.T) {
	es := domain.CausalLinks([]domain.CausalEvidence{evidenced()})
	want := map[string]string{
		domain.EdgeAuthorized: "decision_receipt:t", domain.EdgeApproved: "approval_request:ap",
		domain.EdgeCustody: "execution_receipt:x", domain.EdgeEffect: "effect_receipt:t/2",
	}
	for kind, ref := range want {
		got := kinds(es, kind)
		if len(got) != 1 || got[0].EvidenceRef != ref || got[0].Basis != "OBSERVED" {
			t.Errorf("%s: %+v, want the one edge with %s", kind, got, ref)
		}
	}
	if e := kinds(es, domain.EdgeEffect)[0]; e.Downstream != "PENDING" || e.Effect != "CONFIRMED" {
		t.Errorf("a confirmed merge with a pending deployment reads %+v", e)
	}
	if len(kinds(es, domain.EdgeGap)) != 0 {
		t.Errorf("gaps with all the evidence: %+v", kinds(es, domain.EdgeGap))
	}
}

// TestT239_ACauseWithNoEvidenceIsAGap: each missing record removes its
// link and leaves the matching gap.
// Covers: F279, F280
func TestT239_ACauseWithNoEvidenceIsAGap(t *testing.T) {
	for _, c := range []struct {
		name    string
		change  func(*domain.CausalEvidence)
		gone    string
		missing string
	}{
		{"no receipt", func(c *domain.CausalEvidence) { c.Activity.Missing = "NO_DECISION_RECEIPT" }, domain.EdgeAuthorized, "NO_DECISION_RECEIPT"},
		{"no grant", func(c *domain.CausalEvidence) { c.Grant = "" }, domain.EdgeAuthorized, domain.GapNoGrant},
		{"no execution receipt", func(c *domain.CausalEvidence) { c.ExecutionReceipt = false }, domain.EdgeCustody, domain.GapNoExecution},
		{"no effect receipt", func(c *domain.CausalEvidence) { c.EffectSeq = 0 }, domain.EdgeEffect, domain.GapNoEffect},
		{"no approval", func(c *domain.CausalEvidence) { c.Activity.Decision, c.Approvals = "REQUIRE_APPROVAL", nil }, domain.EdgeApproved, domain.GapNoApproval},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev := evidenced()
			c.change(&ev)
			es := domain.CausalLinks([]domain.CausalEvidence{ev})
			if got := kinds(es, c.gone); len(got) != 0 {
				t.Errorf("a %s link with no evidence: %+v", c.gone, got)
			}
			if !gapOf(es, c.missing) {
				t.Errorf("no gap %s in %+v", c.missing, es)
			}
			for _, e := range kinds(es, domain.EdgeGap) {
				if e.EvidenceRef != "" {
					t.Errorf("a gap names evidence: %+v", e)
				}
			}
		})
	}
	// A denied action was authorized by nothing, and that is not a gap.
	ev := evidenced()
	ev.Activity.Decision, ev.Approvals, ev.Dispatched, ev.Attempt, ev.EffectSeq = "DENY", nil, nil, "", 0
	if es := domain.CausalLinks([]domain.CausalEvidence{ev}); len(es) != 0 {
		t.Errorf("a denied action: %+v", es)
	}
}

// TestHR551_PredictedAuthorizedAndConfirmedStayApart: a rule's prediction
// is possible and proves nothing; an opened transaction is authorized, and
// only an effect receipt confirms (D12, F280, F281).
// Covers: F279, F280, F281
func TestHR551_PredictedAuthorizedAndConfirmedStayApart(t *testing.T) {
	ev := evidenced()
	ev.Consequences = []domain.ConsequenceEvidence{
		{Evaluation: 1, Position: 0, Parent: -1, State: "PREDICTED", Operation: "github.deployment.trigger", At: now},
		{Evaluation: 1, Position: 1, Parent: -1, State: "PREDICTED", Transaction: "c1", Linked: "t", Effect: "PROPAGATION_PENDING", At: now},
		{Evaluation: 1, Position: 2, Parent: 1, State: "PREDICTED", Transaction: "c2", Linked: "c1", Effect: "CONFIRMED", EffectSeq: 3, At: now},
		{Evaluation: 1, Position: 3, Parent: -1, State: "PREDICTED", Transaction: "c3", Linked: "t", Effect: "CONFIRMED", At: now},
		{Evaluation: 1, Position: 4, Parent: -1, State: "UNKNOWN", Operation: "x.y", At: now},
	}
	got := map[string]domain.Edge{}
	for _, e := range kinds(domain.CausalLinks([]domain.CausalEvidence{ev}), domain.EdgeTriggered) {
		got[e.To.ID] = e
	}
	if len(got) != 4 {
		t.Fatalf("triggered edges: %+v", got)
	}
	p := got["t/0"]
	if p.Stage != domain.StagePredicted || p.State != domain.EdgePossible || p.Basis != "RULE_MATCH" || p.To.Type != domain.NodeConsequence ||
		p.EvidenceRef != "decision_consequence:t/1/0" {
		t.Errorf("predicted: %+v", p)
	}
	if a := got["c1"]; a.Stage != domain.StageAuthorized || a.Basis != "OBSERVED" || a.EvidenceRef != "transaction_link:t/c1" {
		t.Errorf("authorized: %+v", a)
	}
	if c := got["c2"]; c.Stage != domain.StageConfirmed || c.From.ID != "c1" || c.EvidenceRef != "effect_receipt:c2/3" {
		t.Errorf("confirmed down the chain: %+v", c)
	}
	// CONFIRMED with no receipt to name stays authorized.
	if c := got["c3"]; c.Stage != domain.StageAuthorized {
		t.Errorf("confirmed with no receipt: %+v", c)
	}
	if !gapOf(domain.CausalLinks([]domain.CausalEvidence{ev}), domain.GapConsequence) {
		t.Error("a consequence the rule could not rule out is no gap")
	}
}

// TestHR551_ObservedNeverReadsAsPossible: an observed right whose reach is
// now uncertain is what happened, not what might (D12, F273).
// Covers: F273
func TestHR551_ObservedNeverReadsAsPossible(t *testing.T) {
	agent, seen := ids.NewV7(), now
	es := domain.ExposureEdges([]domain.Right{{View: domain.Observed, Label: domain.Uncertain, Agent: &agent, ResourceGroup: "g", ObservedAt: &seen}})
	if len(es) != 1 || es[0].State != domain.EdgeHistorical || es[0].Basis != "OBSERVED" {
		t.Fatalf("observed: %+v", es)
	}
	g := domain.Build(domain.ModeExposure, es, all, domain.GraphFilter{}, false, domain.DefaultLimits)
	if s := g.Edges[0].Status; s == domain.StatusPossibleBypass || s == domain.StatusUnknown || g.Edges[0].State == domain.EdgePossible {
		t.Fatalf("observed reads as %s", s)
	}
}

// TestHR552_EveryModeReturnsItsGapsAndCollapseKeepsThem: each mode builds
// gaps from its own records, collapsing leaves each one, and history is no
// gap (D13, F294).
// Covers: F293, F294
func TestHR552_EveryModeReturnsItsGapsAndCollapseKeepsThem(t *testing.T) {
	agent, conn := ids.NewV7(), ids.NewV7()
	unknown := domain.Right{View: domain.Effective, Label: domain.Uncertain, Agent: &agent, Connection: &conn, ResourceGroup: "g"}
	unchecked := domain.Right{View: domain.Effective, Label: domain.Usable, Agent: &agent, Connection: &conn, ResourceGroup: "h", Coverage: domain.CoverageUnknown}
	revoked := unknown
	revoked.Reasons, revoked.ResourceGroup = []string{domain.ReasonGrantRevoked}, "old"
	seen := unknown
	seen.View, seen.ResourceGroup = domain.Observed, "seen"
	reach := domain.ReachGaps([]domain.Right{unknown, unknown, unchecked, revoked, seen})
	if len(reach) != 2 || !gapOf(reach, domain.GapReachUnknown) || !gapOf(reach, domain.GapCoverage) {
		t.Fatalf("reach gaps: %+v", reach)
	}
	acts := []domain.Activity{{Run: "r", Agent: agent.String(), Transaction: "t", Missing: "NO_DECISION_RECEIPT", At: now}}
	ev := evidenced()
	ev.Grant = ""
	change := domain.CompareEdges([]domain.BoundsChange{{Grant: domain.Node{Type: "grant", ID: "g"}, At: now, Unreadable: true}})
	for mode, edges := range map[domain.Mode][]domain.Edge{
		domain.ModeActivity: domain.ActivityEdges(acts), domain.ModeCausal: domain.CausalLinks([]domain.CausalEvidence{ev}),
		domain.ModeAuthority: reach, domain.ModeExposure: reach, domain.ModeChange: change,
	} {
		twice := slices.Concat(edges, edges)
		g := domain.Build(mode, twice, all, domain.GraphFilter{}, true, domain.DefaultLimits)
		if got, want := len(kinds(g.Edges, domain.EdgeGap)), len(kinds(twice, domain.EdgeGap)); got == 0 || got != want {
			t.Errorf("%s: %d gaps after collapsing, want %d", mode, got, want)
		}
	}
}

// TestF291_EdgesCarryTheirExplicitState: each state comes from the stored
// field that says it, and a monitor-mode decision prevented nothing.
// Covers: F289, F291, F297
func TestF291_EdgesCarryTheirExplicitState(t *testing.T) {
	for _, c := range []struct {
		e         domain.Edge
		status    domain.EdgeStatus
		assurance string
	}{
		{domain.Edge{Decision: "ALLOW", Basis: "OBSERVED"}, domain.StatusAllowed, domain.AssuranceAuthoritative},
		{domain.Edge{Decision: "REQUIRE_STEP_UP", Basis: "OBSERVED"}, domain.StatusApprovalRequired, domain.AssuranceAuthoritative},
		{domain.Edge{Decision: "CANNOT_AUTHORIZE", Basis: "OBSERVED"}, domain.StatusDenied, domain.AssuranceAuthoritative},
		{domain.Edge{Basis: "OBSERVED"}, domain.StatusObserved, domain.AssuranceAuthoritative},
		{domain.Edge{Basis: "RULE_MATCH", Coverage: domain.CoverageEnforced, Provenance: string(domain.Effective)}, domain.StatusEnforced, domain.AssuranceTested},
		{domain.Edge{Basis: "RULE_MATCH", Provenance: string(domain.Effective)}, domain.StatusAllowed, domain.AssuranceDeclared},
		{domain.Edge{Basis: "RULE_MATCH", Provenance: string(domain.Credential)}, domain.StatusPossibleBypass, domain.AssuranceDeclared},
		{domain.Edge{Basis: "INFERRED", State: domain.EdgePossible}, domain.StatusUnknown, domain.AssuranceInferred},
		{domain.Edge{Basis: "RULE_MATCH", Freshness: "STALE"}, domain.StatusStale, domain.AssuranceDeclared},
		{domain.Edge{Basis: "OBSERVED", Effect: "PARTIAL", Decision: "ALLOW"}, domain.StatusEffectPartial, domain.AssuranceAuthoritative},
		{domain.Edge{Basis: "OBSERVED", Effect: "PROPAGATION_PENDING"}, domain.StatusEffectPending, domain.AssuranceAuthoritative},
		{domain.Edge{Basis: "OBSERVED", Effect: "CONFLICTING"}, domain.StatusEffectConflicting, domain.AssuranceAuthoritative},
		{domain.Edge{Basis: "OBSERVED", Effect: "UNVERIFIABLE"}, domain.StatusEffectUnverifiable, domain.AssuranceAuthoritative},
		{domain.Edge{Kind: domain.EdgeGap, Basis: "OBSERVED"}, domain.StatusUnknown, domain.AssuranceUnverified},
	} {
		c.e.From, c.e.To = domain.Node{Type: "a", ID: "1"}, domain.Node{Type: "b", ID: "2"}
		g := domain.Build(domain.ModeActivity, []domain.Edge{c.e}, all, domain.GraphFilter{}, false, domain.DefaultLimits)
		if got := g.Edges[0]; got.Status != c.status || got.Assurance != c.assurance {
			t.Errorf("%+v: %s %s, want %s %s", c.e, got.Status, got.Assurance, c.status, c.assurance)
		}
	}
	monitored := domain.ActivityEdges([]domain.Activity{{Run: "r", Agent: "a", Transaction: "t", Decision: "DENY", Monitor: true, At: now}})
	g := domain.Build(domain.ModeActivity, monitored, all, domain.GraphFilter{}, false, domain.DefaultLimits)
	for _, e := range g.Edges {
		if e.Decision != "" && e.Status != domain.StatusObserved {
			t.Errorf("a monitor-mode decision reads %s", e.Status)
		}
	}
}

// TestF293_EveryEdgeNamesItsSource: no mode builds an edge without one.
// Covers: F293, F297
func TestF293_EveryEdgeNamesItsSource(t *testing.T) {
	acts := []domain.Activity{
		{Run: "c", ParentRun: "r", Agent: "a", Transaction: "t1", Resource: "x", At: now},
		{Run: "c", ParentRun: "r", Agent: "a", Transaction: "t2", Missing: "NO_DECISION_RECEIPT", At: now.Add(time.Second)},
	}
	for _, e := range slices.Concat(domain.ActivityEdges(acts), domain.CausalEdges(acts), domain.CausalLinks([]domain.CausalEvidence{evidenced()})) {
		if e.Provenance == "" {
			t.Errorf("no source: %+v", e)
		}
	}
}

// TestF276_ChangesCompareBeforeAndAfter: operations are added, removed and
// kept, a revocation removes everything, and an unreadable document is a
// gap, never read as allowing nothing.
// Covers: F274, F276
func TestF276_ChangesCompareBeforeAndAfter(t *testing.T) {
	grant := domain.Node{Type: "grant", ID: "g"}
	es := domain.CompareEdges([]domain.BoundsChange{{
		Grant: grant, Revision: 2, At: now, Current: true, Before: []string{"a.b.c", "a.b.d"}, After: []string{"a.b.d", "a.b.e"}, Ref: "grant_revision:g/2",
	}})
	got := map[string]domain.ChangeKind{}
	for _, e := range es {
		got[e.To.ID] = e.Change
		if e.Change == domain.ChangeRemoved && e.State.Current() {
			t.Errorf("a removed operation counts as current: %+v", e)
		}
		if e.EvidenceRef != "grant_revision:g/2" {
			t.Errorf("no record: %+v", e)
		}
	}
	if got["a.b.c"] != domain.ChangeRemoved || got["a.b.d"] != domain.ChangeKept || got["a.b.e"] != domain.ChangeAdded {
		t.Fatalf("changes: %v", got)
	}
	revoked := domain.CompareEdges([]domain.BoundsChange{{Grant: grant, At: now, Before: []string{"a.b.c"}}})
	if len(revoked) != 1 || revoked[0].Change != domain.ChangeRemoved {
		t.Fatalf("revocation: %+v", revoked)
	}
	unreadable := domain.CompareEdges([]domain.BoundsChange{{Grant: grant, At: now, Unreadable: true, Before: []string{"a.b.c"}}})
	if len(unreadable) != 1 || !gapOf(unreadable, domain.GapBoundsUnknown) {
		t.Fatalf("unreadable: %+v", unreadable)
	}
}

// TestHR550_LabelsArePlainTextAndBounded: control, format and markup
// characters never reach a label, and a label holds at most 200 characters
// (HR-340: the console renders them as text).
// Covers: F290, F298
func TestHR550_LabelsArePlainTextAndBounded(t *testing.T) {
	for in, want := range map[string]string{
		"payments agent":                       "payments agent",
		"  spaced\n":                           "spaced",
		"<img src=x onerror=alert(1)>":         "img src=x onerror=alert(1)",
		"a‮b​c\x00d":                           "abc d",
		"‮":                                    "",
		"<script>x</script>":                   "scriptx/script",
		strings.Repeat("é", 2*domain.MaxLabel): strings.Repeat("é", domain.MaxLabel),
	} {
		got := domain.PlainLabel(in)
		if got != want {
			t.Errorf("PlainLabel(%q) = %q, want %q", in, got, want)
		}
		if n := utf8.RuneCountInString(got); n > domain.MaxLabel {
			t.Errorf("%d characters", n)
		}
	}
}

// TestHR254_ABuiltGraphDropsEvidenceEdgesOfHiddenAgents: the causal links
// carry their agent as context, so a hidden agent's approval, permit and
// effect nodes never reach the viewer (D8).
// Covers: F298, F300
func TestHR254_ABuiltGraphDropsEvidenceEdgesOfHiddenAgents(t *testing.T) {
	hidden := func(n domain.Node) bool { return !(n.Type == "agent" && n.ID == "a") }
	g := domain.Build(domain.ModeCausal, domain.CausalLinks([]domain.CausalEvidence{evidenced()}), hidden, domain.GraphFilter{}, false, domain.DefaultLimits)
	if len(g.Edges) != 0 || len(g.Nodes) != 0 {
		t.Fatalf("hidden agent's evidence: %+v", g)
	}
}
