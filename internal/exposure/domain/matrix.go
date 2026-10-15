// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Cell is one matrix cell: an agent's reach to a resource group with one
// verb in one view, at its most usable label (F256).
type Cell struct {
	Agent         *ids.UUID
	ResourceGroup string
	Verb          Verb
	View          View
	Label         Label
	Coverage      Coverage
	// Bases explain the verb: every distinct basis behind the cell (D45,
	// F257). Irreversible is set when any operation behind it is.
	Bases        []string
	Irreversible bool
	// Rights counts the rights behind the cell.
	Rights int
}

// Matrix is agents x resource groups x verbs, per view.
type Matrix struct {
	Agents []*ids.UUID
	Groups []string
	Cells  []Cell
}

// BuildMatrix folds visible rights into a matrix. Rights must already be
// filtered by the viewer's permissions (D8): the matrix counts only what
// it is given. EXPIRED rights stay in the observed view's history but never
// make a current cell in the effective or credential view (HR-254).
func BuildMatrix(rights []Right) Matrix {
	type key struct {
		agent string
		group string
		verb  Verb
		view  View
	}
	cells := map[key]*Cell{}
	agents := map[string]*ids.UUID{}
	groups := map[string]bool{}
	for _, r := range rights {
		if r.View != Observed && !r.Label.Current() {
			continue
		}
		a := "*"
		if r.Agent != nil {
			a = r.Agent.String()
		}
		agents[a] = r.Agent
		groups[r.ResourceGroup] = true
		k := key{a, r.ResourceGroup, r.Verb, r.View}
		c, ok := cells[k]
		if !ok {
			cells[k] = &Cell{
				Agent: r.Agent, ResourceGroup: r.ResourceGroup, Verb: r.Verb, View: r.View, Label: r.Label,
				Coverage: r.Coverage, Rights: 1, Bases: []string{r.Basis}, Irreversible: r.Irreversible,
			}
			continue
		}
		c.Rights++
		c.Irreversible = c.Irreversible || r.Irreversible
		if !slices.Contains(c.Bases, r.Basis) {
			c.Bases = append(c.Bases, r.Basis)
			slices.Sort(c.Bases)
		}
		if r.Label.Rank() < c.Label.Rank() {
			c.Label = r.Label
		}
		if r.Coverage.Rank() < c.Coverage.Rank() {
			c.Coverage = r.Coverage
		}
	}
	var m Matrix
	keys := make([]string, 0, len(agents))
	for k := range agents {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		m.Agents = append(m.Agents, agents[k])
	}
	for g := range groups {
		m.Groups = append(m.Groups, g)
	}
	slices.Sort(m.Groups)
	for _, c := range cells {
		m.Cells = append(m.Cells, *c)
	}
	slices.SortFunc(m.Cells, func(a, b Cell) int {
		return cmp.Or(cmp.Compare(agentKey(a.Agent), agentKey(b.Agent)), cmp.Compare(a.ResourceGroup, b.ResourceGroup),
			cmp.Compare(slices.Index(AllVerbs, a.Verb), slices.Index(AllVerbs, b.Verb)),
			cmp.Compare(slices.Index(Views, a.View), slices.Index(Views, b.View)))
	})
	return m
}

func agentKey(a *ids.UUID) string {
	if a == nil {
		return "*"
	}
	return a.String()
}

// AgentInfo is what ranking reads of an agent.
type AgentInfo struct {
	ID    ids.UUID
	Owned bool
}

// RankKeys are the ranking's ordered keys (F257, D28), each shown as is:
// there is no single score.
type RankKeys struct {
	// Consequence: the costliest verb the agent currently reaches, and
	// whether any reached operation is irreversible.
	Consequence  Verb
	Irreversible bool
	// Scope: how many resource groups and connections it reaches.
	ResourceGroups int
	Connections    int
	// Usability: the most usable label among its current rights.
	Usability Label
	// Enforceability: the weakest coverage on its current rights.
	Enforceability Coverage
	// Owned: whether the agent has an owner.
	Owned bool
	// Remediation readiness: how many current rights a grant revocation
	// removes (a right with a grant), versus those only a credential or
	// route change removes.
	Revocable   int
	Unrevocable int
}

// Ranked is one ranked agent.
type Ranked struct {
	Agent *ids.UUID
	Keys  RankKeys
}

// Rank orders agents by consequence, then scope, present usability,
// enforceability, ownership and remediation readiness: the riskiest first.
// irreversible names the operations whose definitions are irreversible.
func Rank(rights []Right, agents []AgentInfo, irreversible map[string]bool) []Ranked {
	owned := map[string]bool{}
	for _, a := range agents {
		owned[a.ID.String()] = a.Owned
	}
	type acc struct {
		keys   RankKeys
		agent  *ids.UUID
		groups map[string]bool
		conns  map[string]bool
		seen   bool
	}
	by := map[string]*acc{}
	for _, r := range rights {
		if r.View == Observed || !r.Label.Current() {
			continue
		}
		k := agentKey(r.Agent)
		a, ok := by[k]
		if !ok {
			a = &acc{
				agent: r.Agent, groups: map[string]bool{}, conns: map[string]bool{},
				keys: RankKeys{Consequence: VerbRead, Usability: Expired, Enforceability: CoverageEnforced, Owned: owned[k]},
			}
			by[k] = a
		}
		if !a.seen || r.Verb.Consequence() > a.keys.Consequence.Consequence() {
			a.keys.Consequence = r.Verb
		}
		a.seen = true
		a.keys.Irreversible = a.keys.Irreversible || irreversible[r.Operation]
		a.groups[r.ResourceGroup] = true
		if r.Connection != nil {
			a.conns[r.Connection.String()] = true
		}
		if r.Label.Rank() < a.keys.Usability.Rank() {
			a.keys.Usability = r.Label
		}
		if r.Coverage.Rank() < a.keys.Enforceability.Rank() {
			a.keys.Enforceability = r.Coverage
		}
		if r.Grant != nil {
			a.keys.Revocable++
		} else {
			a.keys.Unrevocable++
		}
	}
	out := make([]Ranked, 0, len(by))
	for _, a := range by {
		a.keys.ResourceGroups, a.keys.Connections = len(a.groups), len(a.conns)
		out = append(out, Ranked{Agent: a.agent, Keys: a.keys})
	}
	slices.SortFunc(out, compareRanked)
	return out
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// compareRanked puts the riskier agent first, key by key.
func compareRanked(a, b Ranked) int {
	x, y := a.Keys, b.Keys
	return cmp.Or(
		-cmp.Compare(x.Consequence.Consequence(), y.Consequence.Consequence()),
		-cmp.Compare(boolRank(x.Irreversible), boolRank(y.Irreversible)),
		-cmp.Compare(x.ResourceGroups+x.Connections, y.ResourceGroups+y.Connections),
		cmp.Compare(x.Usability.Rank(), y.Usability.Rank()),
		cmp.Compare(x.Enforceability.Rank(), y.Enforceability.Rank()),
		cmp.Compare(boolRank(x.Owned), boolRank(y.Owned)),
		-cmp.Compare(x.Unrevocable, y.Unrevocable),
		cmp.Compare(agentKey(a.Agent), agentKey(b.Agent)),
	)
}

// Filter selects rights for a drill-down (F260).
type Filter struct {
	Agent         *ids.UUID
	Connection    *ids.UUID
	ResourceGroup string
	Verb          Verb
	View          View
	// Current leaves out EXPIRED rights.
	Current bool
}

// Match reports whether r passes the filter.
func (f Filter) Match(r Right) bool {
	switch {
	case f.Agent != nil && (r.Agent == nil || *r.Agent != *f.Agent):
		return false
	case f.Connection != nil && (r.Connection == nil || *r.Connection != *f.Connection):
		return false
	case f.ResourceGroup != "" && r.ResourceGroup != f.ResourceGroup:
		return false
	case f.Verb != "" && r.Verb != f.Verb:
		return false
	case f.View != "" && r.View != f.View:
		return false
	case f.Current && !r.Label.Current():
		return false
	}
	return true
}

// Select returns the rights that pass f.
func Select(rights []Right, f Filter) []Right {
	var out []Right
	for _, r := range rights {
		if f.Match(r) {
			out = append(out, r)
		}
	}
	return out
}

// Workload is a dependent of a shared credential (F430).
type Workload struct {
	Agent  *ids.UUID
	Views  []View
	Rights int
	// LastUsed is the latest observed dispatch through the connection.
	LastUsed *time.Time
}

// Dependents lists every workload whose reach goes through connection's
// credential (F260, F430): each agent with a right through the connection
// in any view, current or historical, with when it last used it. The
// credential's own holder ("*", a nil agent) is listed too.
func Dependents(rights []Right, connection ids.UUID) []Workload {
	by := map[string]*Workload{}
	for _, r := range rights {
		if r.Connection == nil || *r.Connection != connection {
			continue
		}
		k := agentKey(r.Agent)
		w, ok := by[k]
		if !ok {
			w = &Workload{Agent: r.Agent}
			by[k] = w
		}
		if !slices.Contains(w.Views, r.View) {
			w.Views = append(w.Views, r.View)
		}
		w.Rights++
		if r.ObservedAt != nil && (w.LastUsed == nil || r.ObservedAt.After(*w.LastUsed)) {
			w.LastUsed = r.ObservedAt
		}
	}
	out := make([]Workload, 0, len(by))
	for _, w := range by {
		slices.SortFunc(w.Views, func(a, b View) int { return slices.Index(Views, a) - slices.Index(Views, b) })
		out = append(out, *w)
	}
	slices.SortFunc(out, func(a, b Workload) int { return cmp.Compare(agentKey(a.Agent), agentKey(b.Agent)) })
	return out
}
