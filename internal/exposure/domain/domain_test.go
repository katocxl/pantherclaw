// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

type world struct {
	agent, other, grant, conn, gh ids.UUID
	in                            domain.Inputs
}

func newWorld() *world {
	w := &world{agent: ids.NewV7(), other: ids.NewV7(), grant: ids.NewV7(), conn: ids.NewV7(), gh: ids.NewV7()}
	ops := gdomain.Ops{"payments.*"}
	w.in = domain.Inputs{
		Now: now,
		Grants: []domain.Grant{{
			ID: w.grant, Agent: w.agent, Bounds: gdomain.Bounds{Operations: &ops},
			NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		}},
		Connections: []domain.Connection{
			{
				ID: w.conn, Name: "payments", State: "ACTIVE", AccessMode: "pantherclaw_held", DestinationClass: "internal",
				Known: true,
				Operations: []domain.Operation{
					{Name: "payments.charge.read", Access: defs.AccessRead, TargetType: "charge"},
					{
						Name: "payments.refund.create", Access: defs.AccessWrite, TargetType: "charge", Effects: []string{"funds.transfer"},
						Reversibility: defs.Irreversible,
					},
					{
						Name: "payments.customer.delete", Access: defs.AccessWrite, TargetType: "customer",
						Effects: []string{"customer.delete"},
					},
				},
				Credential: &domain.CredentialInfo{Kind: "static", Version: 1, CreatedAt: now.Add(-time.Hour)},
			},
			{
				ID: w.gh, Name: "github", State: "ACTIVE", AccessMode: "pantherclaw_held", DestinationClass: "public", Known: true,
				Operations: []domain.Operation{{Name: "repository.contents.read", Access: defs.AccessRead, TargetType: "repository"}},
				Credential: &domain.CredentialInfo{
					Kind: "github_app", Version: 1, ScopeKnown: true,
					Scopes: map[string]string{"contents": "write", "administration": "write"}, Overreach: []string{"administration:write"},
				},
			},
		},
		Policy:   domain.Policy{Known: true},
		Coverage: map[domain.CoverageKey]domain.Coverage{},
	}
	return w
}

func find(rs []domain.Right, view domain.View, agent *ids.UUID, op string, verb domain.Verb) (domain.Right, bool) {
	i := slices.IndexFunc(rs, func(r domain.Right) bool {
		return r.View == view && r.Operation == op && r.Verb == verb &&
			((agent == nil && r.Agent == nil) || (agent != nil && r.Agent != nil && *r.Agent == *agent))
	})
	if i < 0 {
		return domain.Right{}, false
	}
	return rs[i], true
}

func TestVerbsFromDefinitions(t *testing.T) {
	internal := domain.Connection{DestinationClass: "internal"}
	public := domain.Connection{DestinationClass: "public"}
	for _, c := range []struct {
		name string
		op   domain.Operation
		conn domain.Connection
		want []domain.Verb
	}{
		{"read", domain.Operation{Access: defs.AccessRead}, internal, []domain.Verb{domain.VerbRead}},
		{"public read exports", domain.Operation{Access: defs.AccessRead}, public, []domain.Verb{domain.VerbRead, domain.VerbExport}},
		{"bare write updates", domain.Operation{Access: defs.AccessWrite}, internal, []domain.Verb{domain.VerbUpdate}},
		{"delete", domain.Operation{Access: defs.AccessWrite, Effects: []string{"repo.branch.delete"}}, internal, []domain.Verb{domain.VerbDelete}},
		{"transfer", domain.Operation{Access: defs.AccessWrite, Effects: []string{"funds.transfer"}}, internal, []domain.Verb{domain.VerbTransfer}},
		{
			"mixed",
			domain.Operation{Access: defs.AccessWrite, Effects: []string{"a.write", "b.remove"}},
			internal,
			[]domain.Verb{domain.VerbUpdate, domain.VerbDelete},
		},
		{"unknown access is a write", domain.Operation{}, internal, []domain.Verb{domain.VerbUpdate}},
		{
			"refund transfers, any case",
			domain.Operation{Access: defs.AccessWrite, Effects: []string{"payments.REFUND"}},
			internal,
			[]domain.Verb{domain.VerbTransfer},
		},
		{
			"publish exports and updates",
			domain.Operation{Access: defs.AccessWrite, Effects: []string{"site.page.publish"}},
			internal,
			[]domain.Verb{domain.VerbExport, domain.VerbUpdate},
		},
		{
			"read with an upload effect exports",
			domain.Operation{Access: defs.AccessRead, Effects: []string{"file.Upload"}},
			internal,
			[]domain.Verb{domain.VerbRead, domain.VerbExport},
		},
		{
			"write with no effect but none",
			domain.Operation{Access: defs.AccessWrite, Effects: []string{"none"}},
			internal,
			[]domain.Verb{domain.VerbUpdate},
		},
	} {
		if got := domain.Verbs(c.op, c.conn); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// Each verb says why (D45).
	for _, c := range []struct {
		op   domain.Operation
		want []string
	}{
		{domain.Operation{Access: defs.AccessRead}, []string{"ACCESS"}},
		{domain.Operation{Access: defs.AccessWrite, Effects: []string{"funds.transfer"}}, []string{"EFFECT_KIND:funds.transfer"}},
		{domain.Operation{Access: defs.AccessWrite}, []string{"DEFAULT_UPDATE"}},
		{domain.Operation{Access: defs.AccessWrite, Effects: []string{"a.share"}}, []string{"EFFECT_KIND:a.share", "EFFECT_KIND:a.share"}},
	} {
		var got []string
		for _, x := range domain.Classify(c.op, internal) {
			got = append(got, x.Explain())
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%v: bases %v, want %v", c.op.Effects, got, c.want)
		}
	}
}

// TestMatrixCellsExplainTheirVerb: a cell carries its bases and flags an
// irreversible operation behind it.
func TestMatrixCellsExplainTheirVerb(t *testing.T) {
	w := newWorld()
	m := domain.BuildMatrix(domain.Compute(w.in).Rights)
	i := slices.IndexFunc(m.Cells, func(c domain.Cell) bool {
		return c.View == domain.Effective && c.Verb == domain.VerbTransfer
	})
	if i < 0 || !m.Cells[i].Irreversible || !slices.Equal(m.Cells[i].Bases, []string{"EFFECT_KIND:funds.transfer"}) {
		t.Fatalf("transfer cell: %+v", m.Cells[i])
	}
	j := slices.IndexFunc(m.Cells, func(c domain.Cell) bool {
		return c.View == domain.Effective && c.Verb == domain.VerbRead
	})
	if j < 0 || m.Cells[j].Irreversible || !slices.Equal(m.Cells[j].Bases, []string{"ACCESS"}) {
		t.Fatalf("read cell: %+v", m.Cells[j])
	}
}

// TestHR253_ViewsStaySeparate: the effective view carries the grant's
// reach, labelled with coverage; the credential view carries the
// credential's scopes (with overreach) and the unknown routes; the
// observed view carries only dispatches. None stands in for another.
func TestHR253_ViewsStaySeparate(t *testing.T) {
	w := newWorld()
	w.in.Coverage[domain.CoverageKey{Agent: w.agent, Connection: w.conn, Operation: "payments.refund.create"}] = domain.CoverageEnforced
	w.in.Dispatches = []domain.Dispatch{{Agent: w.agent, Connection: w.conn, Operation: "payments.charge.read", Count: 3, Last: now}}
	rs := domain.Compute(w.in).Rights

	r, ok := find(rs, domain.Effective, &w.agent, "payments.refund.create", domain.VerbTransfer)
	if !ok || r.Label != domain.Usable || r.Coverage != domain.CoverageEnforced || r.Grant == nil || *r.Grant != w.grant {
		t.Fatalf("effective transfer: %+v %v", r, ok)
	}
	if _, ok := find(rs, domain.Effective, &w.agent, "repository.contents.read", domain.VerbRead); ok {
		t.Fatal("the grant does not reach github")
	}
	if _, ok := find(rs, domain.Observed, &w.agent, "payments.refund.create", domain.VerbTransfer); ok {
		t.Fatal("an undispatched operation in the observed view")
	}
	o, ok := find(rs, domain.Observed, &w.agent, "payments.charge.read", domain.VerbRead)
	if !ok || o.Observations != 3 || o.Label != domain.Usable {
		t.Fatalf("observed read: %+v %v", o, ok)
	}
	// The GitHub credential's scopes, overreach marked, held by whoever
	// holds the credential.
	adm := slices.IndexFunc(rs, func(r domain.Right) bool {
		return r.View == domain.Credential && r.ResourceGroup == "scope:administration" && r.Verb == domain.VerbUpdate
	})
	if adm < 0 || rs[adm].Agent != nil || !slices.Contains(rs[adm].Reasons, domain.ReasonOverreach) {
		t.Fatalf("credential scope: %d", adm)
	}
	// An operation with no assessed coverage is an uncertain bypass route.
	u, ok := find(rs, domain.Credential, &w.agent, "payments.customer.delete", domain.VerbDelete)
	if !ok || u.Label != domain.Uncertain || u.Coverage != domain.CoverageUnknown {
		t.Fatalf("unknown route: %+v %v", u, ok)
	}
	// The enforced one is not a bypass.
	if _, ok := find(rs, domain.Credential, &w.agent, "payments.refund.create", domain.VerbTransfer); ok {
		t.Fatal("an enforced path listed as a bypass")
	}
}

// TestT111_UnknownReachIsUncertainNeverAbsent: a static credential whose
// scope was never read, a connection whose package cannot be read, an
// unreadable policy and an agent-held credential all show up as UNCERTAIN
// or CONDITIONAL reach, never as nothing.
func TestT111_UnknownReachIsUncertainNeverAbsent(t *testing.T) {
	w := newWorld()
	w.in.Policy = domain.Policy{Known: false}
	w.in.Connections[1].Known, w.in.Connections[1].Operations = false, nil
	w.in.Connections[1].AccessMode = "agent_held"
	w.in.Grants[0].Bounds = gdomain.Bounds{}
	res := domain.Compute(w.in)
	rs := res.Rights

	static := slices.IndexFunc(rs, func(r domain.Right) bool {
		return r.View == domain.Credential && r.ResourceGroup == "credential:payments" && r.Verb == domain.VerbDelete
	})
	if static < 0 || rs[static].Label != domain.Uncertain || !slices.Contains(rs[static].Reasons, domain.ReasonScopeUnknown) {
		t.Fatalf("static credential scope: %d", static)
	}
	eff := slices.IndexFunc(rs, func(r domain.Right) bool {
		return r.View == domain.Effective && r.ResourceGroup == "connection:github" && r.Verb == domain.VerbUpdate
	})
	if eff < 0 || rs[eff].Label != domain.Uncertain {
		t.Fatalf("unknown package: %d", eff)
	}
	held := slices.IndexFunc(rs, func(r domain.Right) bool {
		return r.View == domain.Credential && r.Agent != nil && *r.Agent == w.agent &&
			slices.Contains(r.Reasons, domain.ReasonAgentHeld)
	})
	if held < 0 || rs[held].Label != domain.Uncertain {
		t.Fatalf("agent held: %d", held)
	}
	r, ok := find(rs, domain.Effective, &w.agent, "payments.refund.create", domain.VerbTransfer)
	if !ok || r.Label != domain.Conditional || !slices.Contains(r.Reasons, domain.ReasonPolicyUnknown) {
		t.Fatalf("policy unknown: %+v", r)
	}
	if !slices.Contains(res.Gaps, "POLICY_UNKNOWN") || !slices.Contains(res.Gaps, "PACKAGE_UNKNOWN:"+w.gh.String()) {
		t.Fatalf("gaps: %v", res.Gaps)
	}
}

func TestLabels(t *testing.T) {
	w := newWorld()
	w.in.Policy.Rules = []domain.PolicyRule{
		{ID: "hold", Kind: "REQUIRE_APPROVAL", Operations: []string{"payments.refund.*"}},
		{ID: "no", Kind: "FORBID", Operations: []string{"payments.customer.delete"}, Unconditional: true},
		{ID: "note", Kind: "ANNOTATE", Operations: []string{"payments.charge.read"}},
	}
	rs := domain.Compute(w.in).Rights
	for op, want := range map[string]domain.Label{
		"payments.refund.create": domain.Conditional, "payments.customer.delete": domain.Conditional,
		"payments.charge.read": domain.Usable,
	} {
		i := slices.IndexFunc(rs, func(r domain.Right) bool { return r.View == domain.Effective && r.Operation == op })
		if i < 0 || rs[i].Label != want {
			t.Errorf("%s: %v", op, i)
		}
	}
	// An expired grant is history; a quarantined connection conditional.
	w.in.Policy.Rules = nil
	w.in.Grants[0].ExpiresAt = now.Add(-time.Minute)
	w.in.Dispatches = []domain.Dispatch{{Agent: w.agent, Connection: w.conn, Operation: "payments.charge.read", Count: 1, Last: now}}
	rs = domain.Compute(w.in).Rights
	if r, _ := find(rs, domain.Effective, &w.agent, "payments.charge.read", domain.VerbRead); r.Label != domain.Expired {
		t.Fatalf("expired grant: %v", r.Label)
	}
	if r, _ := find(rs, domain.Observed, &w.agent, "payments.charge.read", domain.VerbRead); r.Label != domain.Expired ||
		!slices.Contains(r.Reasons, domain.ReasonNoLongerAuthorized) {
		t.Fatalf("observed after expiry: %+v", r)
	}
	w = newWorld()
	w.in.Connections[0].State = "QUARANTINED"
	rs = domain.Compute(w.in).Rights
	if r, _ := find(rs, domain.Effective, &w.agent, "payments.charge.read", domain.VerbRead); r.Label != domain.Conditional {
		t.Fatalf("quarantined: %v", r.Label)
	}
}

func TestBoundsNarrowReach(t *testing.T) {
	w := newWorld()
	read := gdomain.Match{IDs: []string{"read"}}
	targets := map[string]gdomain.Match{"charge": {Prefixes: []string{""}}}
	w.in.Grants[0].Bounds.Access, w.in.Grants[0].Bounds.Targets = &read, &targets
	w.in.Grants[0].DelegationDepth = 2
	rs := domain.Compute(w.in).Rights
	var eff []string
	for _, r := range rs {
		if r.View == domain.Effective {
			eff = append(eff, string(r.Verb)+":"+r.Operation)
		}
	}
	slices.Sort(eff)
	if !slices.Equal(eff, []string{"delegate:", "read:payments.charge.read"}) {
		t.Fatalf("effective: %v", eff)
	}
}

func TestMatrixRankingAndDependents(t *testing.T) {
	w := newWorld()
	second := ids.NewV7()
	w.in.Grants = append(w.in.Grants, domain.Grant{ID: ids.NewV7(), Agent: w.other, Bounds: gdomain.Bounds{
		Operations: &gdomain.Ops{"payments.charge.read"},
	}, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)})
	w.in.Dispatches = []domain.Dispatch{{Agent: w.other, Connection: w.conn, Operation: "payments.charge.read", Count: 1, Last: now}}
	rs := domain.Compute(w.in).Rights
	m := domain.BuildMatrix(rs)
	if len(m.Agents) != 3 { // two agents and the credential holder
		t.Fatalf("agents: %d", len(m.Agents))
	}
	cell := slices.IndexFunc(m.Cells, func(c domain.Cell) bool {
		return c.Agent != nil && *c.Agent == w.agent && c.Verb == domain.VerbTransfer && c.View == domain.Effective
	})
	if cell < 0 || m.Cells[cell].ResourceGroup != "payments/charge" {
		t.Fatalf("transfer cell: %d", cell)
	}
	ranked := domain.Rank(rs, []domain.AgentInfo{{ID: w.agent}, {ID: w.other, Owned: true}, {ID: second}},
		map[string]bool{"payments.refund.create": true})
	if len(ranked) < 2 || ranked[0].Agent == nil || *ranked[0].Agent != w.agent ||
		ranked[0].Keys.Consequence != domain.VerbTransfer || !ranked[0].Keys.Irreversible {
		t.Fatalf("ranking: %+v", ranked)
	}
	deps := domain.Dependents(rs, w.conn)
	var who []string
	for _, d := range deps {
		if d.Agent == nil {
			who = append(who, "*")
		} else {
			who = append(who, d.Agent.String())
		}
	}
	if len(deps) != 3 || !slices.Contains(who, w.other.String()) || !slices.Contains(who, "*") {
		t.Fatalf("dependents: %v", who)
	}
}

// TestPreviewKeepsRemainingReach: revoking the grant removes its effective
// reach and names the observed work it disrupts, while the credential's
// reach stays as remaining for a credential revocation (D31: removing an
// edge alone never proves closure).
func TestPreviewKeepsRemainingReach(t *testing.T) {
	w := newWorld()
	w.in.Dispatches = []domain.Dispatch{{Agent: w.agent, Connection: w.conn, Operation: "payments.charge.read", Count: 1, Last: now}}
	d := domain.Preview(w.in, domain.Change{RevokeGrants: []ids.UUID{w.grant}})
	if d.After[domain.Effective] != 0 || d.Before[domain.Effective] == 0 || len(d.Removed) == 0 || len(d.Disruption) != 1 {
		t.Fatalf("revoke: %+v", d)
	}
	d = domain.Preview(w.in, domain.Change{QuarantineConnections: []ids.UUID{w.conn}})
	if len(d.Weakened) == 0 || len(d.Remaining) == 0 {
		t.Fatalf("quarantine: weakened %d remaining %d", len(d.Weakened), len(d.Remaining))
	}
	d = domain.Preview(w.in, domain.Change{RevokeCredentials: []ids.UUID{w.conn}})
	if !slices.ContainsFunc(d.Removed, func(r domain.Right) bool { return r.ResourceGroup == "credential:payments" }) {
		t.Fatalf("credential revoke: %+v", d.Removed)
	}
	// A second grant keeps the path: it is remaining, not removed.
	w.in.Grants = append(w.in.Grants, domain.Grant{
		ID: ids.NewV7(), Agent: w.agent, Bounds: gdomain.Bounds{},
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	})
	d = domain.Preview(w.in, domain.Change{RevokeGrants: []ids.UUID{w.grant}})
	if len(d.Disruption) != 0 || !slices.ContainsFunc(d.Remaining, func(r domain.Right) bool { return r.Verb == domain.VerbTransfer }) {
		t.Fatalf("second grant: disruption %d remaining %d", len(d.Disruption), len(d.Remaining))
	}
}

// TestHR254_GraphFiltersBeforeCounting: an edge touching an agent the
// viewer may not see is gone before collapsing, capping and counting;
// expired and historical edges never count as current authority.
func TestHR254_GraphFiltersBeforeCounting(t *testing.T) {
	w := newWorld()
	w.in.Grants = append(w.in.Grants, domain.Grant{
		ID: ids.NewV7(), Agent: w.other, Bounds: gdomain.Bounds{},
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	})
	w.in.Grants[0].ExpiresAt = now.Add(-time.Second)
	rs := domain.Compute(w.in).Rights
	hidden := w.other.String()
	visible := func(n domain.Node) bool { return !(n.Type == "agent" && n.ID == hidden) }
	g := domain.Build(domain.ModeAuthority, domain.AuthorityEdges(rs), visible, domain.GraphFilter{}, true, domain.DefaultLimits)
	for _, n := range g.Nodes {
		if n.ID == hidden {
			t.Fatal("hidden agent in the graph")
		}
	}
	if len(g.Edges) == 0 || g.Current[domain.EdgeHolds] != 0 || g.Current[domain.EdgeAllows] != 0 {
		t.Fatalf("expired grant counted as current: %v (%d edges)", g.Current, len(g.Edges))
	}
	all := domain.Build(domain.ModeAuthority, domain.AuthorityEdges(rs), func(domain.Node) bool { return true },
		domain.GraphFilter{}, true, domain.DefaultLimits)
	if all.Current[domain.EdgeHolds] == 0 {
		t.Fatalf("visible current grant not counted: %v", all.Current)
	}
	// Caps truncate and say so; gap edges survive collapsing.
	small := domain.Build(domain.ModeExposure, domain.ExposureEdges(rs), visible, domain.GraphFilter{}, false,
		domain.Limits{Nodes: 3, Edges: 2})
	if !small.Truncated || len(small.Edges) > 2 || len(small.Nodes) > 3 {
		t.Fatalf("caps: %d edges %d nodes truncated=%v", len(small.Edges), len(small.Nodes), small.Truncated)
	}
	acts := []domain.Activity{
		{Run: "r1", Agent: "a", Transaction: "t1", Operation: "x.y", Decision: "ALLOW", At: now, Missing: "NO_RECEIPT"},
		{Run: "r1", Agent: "a", Transaction: "t1", Operation: "x.y", Decision: "ALLOW", At: now, Missing: "NO_RECEIPT"},
	}
	ag := domain.Build(domain.ModeActivity, domain.ActivityEdges(acts), func(domain.Node) bool { return true },
		domain.GraphFilter{Decisions: []string{"ALLOW"}}, true, domain.DefaultLimits)
	gaps := 0
	for _, e := range ag.Edges {
		if e.Kind == domain.EdgeGap {
			gaps++
		}
	}
	if gaps != 2 {
		t.Fatalf("gaps after collapsing: %d", gaps)
	}
	none := domain.Build(domain.ModeActivity, domain.ActivityEdges(acts), func(domain.Node) bool { return true },
		domain.GraphFilter{Operations: []string{"other.op"}}, true, domain.DefaultLimits)
	for _, e := range none.Edges {
		if e.Operation != "" {
			t.Fatalf("operation filter let %s through", e.Operation)
		}
	}
}

func TestCausalAndChangeEdges(t *testing.T) {
	acts := []domain.Activity{
		{Run: "child", ParentRun: "root", Agent: "a", Transaction: "t2", At: now.Add(time.Second)},
		{Run: "child", ParentRun: "root", Agent: "a", Transaction: "t1", At: now},
	}
	es := domain.CausalEdges(acts)
	if len(es) != 2 || es[0].Kind != domain.EdgeDelegated || es[1].From.ID != "t1" || es[1].Basis != "INFERRED" {
		t.Fatalf("causal: %+v", es)
	}
	cs := domain.ChangeEdges([]domain.ChangeRecord{{
		Actor: domain.Node{Type: "user", ID: "u"}, Subject: domain.Node{Type: "grant", ID: "g"},
		Revision: 2, At: now, Current: true,
	}})
	if len(cs) != 1 || cs[0].State != domain.EdgeActive || cs[0].Revision != 2 {
		t.Fatalf("change: %+v", cs)
	}
}

// TestRestrictionsShapeOnlyEffectiveReach: DENY_ALL on an agent removes
// its effective rights and leaves the credential view; HOLD_WRITES keeps
// reads usable and makes writes conditional; DENY_OPERATION removes one
// operation (D21, D31).
func TestRestrictionsShapeOnlyEffectiveReach(t *testing.T) {
	w := newWorld()
	agent := w.agent
	before := domain.Compute(w.in).Rights
	d := domain.Compare(before, domain.Compute(domain.Change{Restrictions: []domain.Restriction{{Agent: &agent}}}.Apply(w.in)).Rights,
		domain.Change{Restrictions: []domain.Restriction{{Agent: &agent}}})
	if d.After[domain.Effective] != 0 || d.After[domain.Credential] != d.Before[domain.Credential] || len(d.Remaining) == 0 {
		t.Fatalf("deny all: %v -> %v, remaining %d", d.Before, d.After, len(d.Remaining))
	}
	held := domain.Compute(domain.Change{Restrictions: []domain.Restriction{{Agent: &agent, Hold: true}}}.Apply(w.in)).Rights
	if r, _ := find(held, domain.Effective, &agent, "payments.charge.read", domain.VerbRead); r.Label != domain.Usable {
		t.Fatalf("held read: %v", r.Label)
	}
	if r, _ := find(held, domain.Effective, &agent, "payments.refund.create", domain.VerbTransfer); r.Label != domain.Conditional ||
		!slices.Contains(r.Reasons, domain.ReasonContainedHold) {
		t.Fatalf("held write: %+v", r)
	}
	one := domain.Compute(domain.Change{Restrictions: []domain.Restriction{{Agent: &agent, Operation: "payments.refund.create"}}}.Apply(w.in)).Rights
	if _, ok := find(one, domain.Effective, &agent, "payments.refund.create", domain.VerbTransfer); ok {
		t.Fatal("denied operation still reachable")
	}
	if _, ok := find(one, domain.Effective, &agent, "payments.charge.read", domain.VerbRead); !ok {
		t.Fatal("other operation lost")
	}
}
