// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"slices"

	"time"
)

// Node is a graph node: a subject type and id (the D1 subject vocabulary;
// resource groups use type "resource").
type Node struct {
	Type string
	ID   string
}

// Mode is a graph's mode (F272, F274).
type Mode string

// Modes.
const (
	ModeActivity  Mode = "activity"
	ModeCausal    Mode = "causal"
	ModeAuthority Mode = "authority"
	ModeExposure  Mode = "exposure"
	ModeChange    Mode = "change"
)

// EdgeState says whether an edge is current (F289).
type EdgeState string

// Edge states. HISTORICAL and EXPIRED edges are kept but never count as
// current authority (HR-254, D31).
const (
	EdgeActive     EdgeState = "ACTIVE"
	EdgeHistorical EdgeState = "HISTORICAL"
	EdgeExpired    EdgeState = "EXPIRED"
	EdgePossible   EdgeState = "POSSIBLE"
)

// Current reports whether the state counts as current authority.
func (s EdgeState) Current() bool { return s == EdgeActive || s == EdgePossible }

// Edge kinds every mode shares (F289).
const (
	EdgeHolds     = "holds"     // agent -> grant
	EdgeAllows    = "allows"    // grant -> resource
	EdgeReaches   = "reaches"   // agent or connection -> resource
	EdgeThrough   = "through"   // agent -> connection
	EdgeActed     = "acted"     // run -> transaction
	EdgeTouched   = "touched"   // transaction -> resource
	EdgeDelegated = "delegated" // parent -> child (grant or run)
	EdgeThen      = "then"      // transaction -> next transaction in a run
	EdgeChanged   = "changed"   // actor -> subject
	EdgeGap       = "gap"       // missing evidence between two nodes
)

// Edge is one edge in the shared vocabulary (D29).
type Edge struct {
	From, To Node
	// Owner is the agent the edge belongs to, when an end alone does not
	// say (a grant allows a resource): the viewer must see it too (D8).
	Owner      *Node
	Kind       string
	Verb       Verb
	Operation  string
	State      EdgeState
	Decision   string
	Coverage   Coverage
	Execution  string
	Effect     string
	Basis      string // OBSERVED, RULE_MATCH, INFERRED, HYPOTHESIS
	Revision   int
	At         *time.Time
	ExpiresAt  *time.Time
	Freshness  string
	Provenance string
	// Count is how many edges collapsing merged into this one.
	Count int
}

// GraphFilter narrows a graph (F293); empty fields do not filter.
type GraphFilter struct {
	Start, End *time.Time
	Runs       []string
	Agents     []string
	Operations []string
	Decisions  []string
	Outcomes   []string
	Principals []string
}

func in(list []string, v string) bool { return len(list) == 0 || slices.Contains(list, v) }

func (f GraphFilter) match(e Edge) bool {
	if e.At != nil && ((f.Start != nil && e.At.Before(*f.Start)) || (f.End != nil && e.At.After(*f.End))) {
		return false
	}
	ends := []Node{e.From, e.To}
	for _, c := range []struct {
		typ  string
		list []string
	}{{"run", f.Runs}, {"agent", f.Agents}, {"user", f.Principals}} {
		if len(c.list) == 0 {
			continue
		}
		hit := false
		for _, n := range ends {
			if n.Type == c.typ && slices.Contains(c.list, n.ID) {
				hit = true
			}
		}
		if !hit && slices.ContainsFunc(ends, func(n Node) bool { return n.Type == c.typ }) {
			return false
		}
	}
	if e.Operation != "" && !in(f.Operations, e.Operation) {
		return false
	}
	return (e.Decision == "" || in(f.Decisions, e.Decision)) && (e.Effect == "" || in(f.Outcomes, e.Effect))
}

// Limits cap a graph (D29).
type Limits struct {
	Nodes, Edges int
}

// DefaultLimits are the D29 caps.
var DefaultLimits = Limits{Nodes: 2000, Edges: 5000}

// Graph is a built graph.
type Graph struct {
	Mode  Mode
	Nodes []Node
	Edges []Edge
	// Truncated is set when the caps cut the graph.
	Truncated bool
	// Current counts the current edges by kind; historical and expired
	// edges are never in it.
	Current map[string]int
}

// Visible decides whether the viewer may see a node (D8): the caller's
// permission scope, never whether hidden rows exist.
type Visible func(Node) bool

// Build assembles a graph from candidate edges: it drops every edge with an
// end the viewer may not see first, then filters, then collapses repeats
// (gap edges are never merged away), then caps, and only then counts
// (HR-254). Nothing hidden reaches a count, a node list or a summary.
func Build(mode Mode, edges []Edge, visible Visible, f GraphFilter, collapse bool, lim Limits) Graph {
	g := Graph{Mode: mode, Current: map[string]int{}}
	var kept []Edge
	for _, e := range edges {
		if !visible(e.From) || !visible(e.To) || (e.Owner != nil && !visible(*e.Owner)) || !f.match(e) {
			continue
		}
		if e.Count == 0 {
			e.Count = 1
		}
		kept = append(kept, e)
	}
	if collapse {
		kept = collapseEdges(kept)
	}
	slices.SortStableFunc(kept, compareEdges)
	nodes := map[Node]bool{}
	for _, e := range kept {
		add := 0
		for _, n := range []Node{e.From, e.To} {
			if !nodes[n] {
				add++
			}
		}
		if len(g.Edges) >= lim.Edges || len(nodes)+add > lim.Nodes {
			g.Truncated = true
			break
		}
		nodes[e.From], nodes[e.To] = true, true
		g.Edges = append(g.Edges, e)
		if e.State.Current() {
			g.Current[e.Kind] += e.Count
		}
	}
	for n := range nodes {
		g.Nodes = append(g.Nodes, n)
	}
	slices.SortFunc(g.Nodes, func(a, b Node) int { return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.ID, b.ID)) })
	return g
}

func edgeKey(e Edge) string {
	return e.From.Type + ":" + e.From.ID + ">" + e.To.Type + ":" + e.To.ID + "|" + e.Kind + "|" + string(e.Verb) + "|" +
		string(e.State) + "|" + e.Decision + "|" + e.Effect + "|" + e.Provenance
}

func collapseEdges(edges []Edge) []Edge {
	idx := map[string]int{}
	var out []Edge
	for _, e := range edges {
		if e.Kind == EdgeGap {
			out = append(out, e)
			continue
		}
		k := edgeKey(e)
		if i, ok := idx[k]; ok {
			out[i].Count += e.Count
			if e.At != nil && (out[i].At == nil || e.At.After(*out[i].At)) {
				out[i].At = e.At
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, e)
	}
	return out
}

// compareEdges orders current edges first (so a cap cuts history before
// authority), gaps with them, then by time and key.
func compareEdges(a, b Edge) int {
	rank := func(e Edge) int {
		switch {
		case e.Kind == EdgeGap:
			return 0
		case e.State.Current():
			return 1
		default:
			return 2
		}
	}
	at := func(e Edge) int64 {
		if e.At == nil {
			return 0
		}
		return e.At.UnixNano()
	}
	return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(at(a), at(b)), cmp.Compare(edgeKey(a), edgeKey(b)))
}

func agentNode(r Right) Node {
	if r.Agent == nil {
		return Node{Type: "connection", ID: r.Connection.String()}
	}
	return Node{Type: "agent", ID: r.Agent.String()}
}

func stateOf(l Label) EdgeState {
	switch l {
	case Expired:
		return EdgeExpired
	case Uncertain:
		return EdgePossible
	default:
		return EdgeActive
	}
}

// AuthorityEdges are the authority graph's edges from effective rights:
// agent holds grant, grant allows a verb on a resource group (F274).
func AuthorityEdges(rights []Right) []Edge {
	var out []Edge
	for _, r := range rights {
		if r.View != Effective || r.Grant == nil {
			continue
		}
		grant := Node{Type: "grant", ID: r.Grant.String()}
		st := stateOf(r.Label)
		out = append(out,
			Edge{From: agentNode(r), To: grant, Kind: EdgeHolds, State: st, Basis: "RULE_MATCH", ExpiresAt: r.ExpiresAt,
				Provenance: string(Effective)},
			Edge{From: grant, To: Node{Type: "resource", ID: r.ResourceGroup}, Owner: ptr(agentNode(r)), Kind: EdgeAllows, Verb: r.Verb, State: st,
				Coverage: r.Coverage, Basis: "RULE_MATCH", ExpiresAt: r.ExpiresAt, Provenance: string(Effective)})
	}
	return out
}

// ExposureEdges are the exposure graph's edges from all three views: who
// reaches which resource group with which verb, through which connection
// (F274). Observed edges are HISTORICAL unless still authorized.
func ExposureEdges(rights []Right) []Edge {
	var out []Edge
	for _, r := range rights {
		st := stateOf(r.Label)
		basis := "RULE_MATCH"
		switch r.View {
		case Observed:
			basis = "OBSERVED"
			if st == EdgeActive {
				st = EdgeHistorical // what happened, shown beside what can happen
			}
		case Credential:
			if r.Label == Uncertain {
				basis = "INFERRED"
			}
		}
		from := agentNode(r)
		if r.Connection != nil && r.Agent != nil {
			out = append(out, Edge{From: from, To: Node{Type: "connection", ID: r.Connection.String()}, Kind: EdgeThrough,
				State: st, Coverage: r.Coverage, Basis: basis, Provenance: string(r.View)})
		}
		out = append(out, Edge{From: from, To: Node{Type: "resource", ID: r.ResourceGroup}, Owner: ptr(from), Kind: EdgeReaches, Verb: r.Verb,
			State: st, Coverage: r.Coverage, Basis: basis, Operation: r.Operation, At: r.ObservedAt, ExpiresAt: r.ExpiresAt, Provenance: string(r.View)})
	}
	return out
}

// Activity is one recorded transaction for the activity and causal graphs.
type Activity struct {
	Run, Agent, Transaction string
	Principal               string
	ParentRun               string
	Operation               string
	Resource                string
	Decision                string
	Execution               string
	Effect                  string
	At                      time.Time
	// Missing marks a transaction whose evidence has a gap (no decision
	// receipt, an unknown effect).
	Missing string
}

// ActivityEdges: run acted (transaction), transaction touched resource; a
// gap edge marks missing evidence (F272).
func ActivityEdges(acts []Activity) []Edge {
	var out []Edge
	for _, a := range acts {
		at := a.At
		run, txn := Node{Type: "run", ID: a.Run}, Node{Type: "transaction", ID: a.Transaction}
		agent := Node{Type: "agent", ID: a.Agent}
		out = append(out, Edge{From: agent, To: run, Kind: EdgeActed, State: EdgeHistorical,
			Basis: "OBSERVED", At: &at})
		out = append(out, Edge{From: run, To: txn, Owner: &agent, Kind: EdgeActed, State: EdgeHistorical, Decision: a.Decision,
			Execution: a.Execution, Effect: a.Effect, Basis: "OBSERVED", At: &at, Operation: a.Operation, Provenance: "transaction"})
		if a.Resource != "" {
			out = append(out, Edge{From: txn, To: Node{Type: "resource", ID: a.Resource}, Owner: &agent, Kind: EdgeTouched,
				State: EdgeHistorical, Decision: a.Decision, Execution: a.Execution, Effect: a.Effect, Basis: "OBSERVED",
				At: &at, Operation: a.Operation, Provenance: "transaction"})
		}
		if a.Missing != "" {
			out = append(out, Edge{From: run, To: txn, Owner: &agent, Kind: EdgeGap, State: EdgeHistorical, Basis: "OBSERVED", At: &at,
				Provenance: a.Missing})
		}
	}
	return out
}

// CausalEdges: parent run delegated child run, and each run's transactions
// in order (then). Order is evidence; causation is never asserted, so the
// basis is INFERRED.
func CausalEdges(acts []Activity) []Edge {
	var out []Edge
	byRun := map[string][]Activity{}
	parents := map[string]string{}
	for _, a := range acts {
		byRun[a.Run] = append(byRun[a.Run], a)
		if a.ParentRun != "" {
			parents[a.Run] = a.ParentRun
		}
	}
	runs := make([]string, 0, len(byRun))
	for r := range byRun {
		runs = append(runs, r)
	}
	slices.Sort(runs)
	for _, r := range runs {
		if p, ok := parents[r]; ok {
			owner := Node{Type: "agent", ID: byRun[r][0].Agent}
			out = append(out, Edge{From: Node{Type: "run", ID: p}, To: Node{Type: "run", ID: r}, Owner: &owner, Kind: EdgeDelegated,
				State: EdgeHistorical, Basis: "OBSERVED"})
		}
		list := byRun[r]
		slices.SortFunc(list, func(a, b Activity) int {
			return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.Transaction, b.Transaction))
		})
		for i := 1; i < len(list); i++ {
			at := list[i].At
			out = append(out, Edge{From: Node{Type: "transaction", ID: list[i-1].Transaction},
				To: Node{Type: "transaction", ID: list[i].Transaction}, Owner: ptr(Node{Type: "agent", ID: list[i].Agent}), Kind: EdgeThen, State: EdgeHistorical,
				Basis: "INFERRED", At: &at})
		}
	}
	return out
}

// ChangeRecord is one authority change for the change graph.
type ChangeRecord struct {
	Actor    Node
	Subject  Node
	Revision int
	What     string
	At       time.Time
	// Current is false for a change since superseded.
	Current bool
}

// ChangeEdges: actor changed subject at a revision (F274).
func ChangeEdges(cs []ChangeRecord) []Edge {
	out := make([]Edge, 0, len(cs))
	for _, c := range cs {
		at, st := c.At, EdgeHistorical
		if c.Current {
			st = EdgeActive
		}
		out = append(out, Edge{From: c.Actor, To: c.Subject, Kind: EdgeChanged, State: st, Revision: c.Revision,
			Basis: "OBSERVED", At: &at, Provenance: c.What})
	}
	return out
}
