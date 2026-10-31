// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"strconv"
)

// Definition document v2 (D301, D307): `nodes` instead of `do`, with
// branches that are mutually exclusive. There is no parallel execution; a
// join only merges paths.
const (
	APIVersionV2 = "automations.pantherclaw.dev/v2"
	// EndNode is the terminal a lifted v1 definition ends at. It cannot be
	// a node id, so it never collides with a step.
	EndNode = "$end"
)

// NodeKind is what a node of a v2 definition does.
type NodeKind string

// Node kinds.
const (
	NodeKindStep     NodeKind = "step"
	NodeKindBranch   NodeKind = "branch"
	NodeKindSwitch   NodeKind = "switch"
	NodeKindJoin     NodeKind = "join"
	NodeKindTerminal NodeKind = "terminal"
)

// Outcome is what a terminal node declares for its path (D301). The final
// state never exceeds it, and never exceeds the evidence (D307).
type Outcome string

// Outcomes.
const (
	OutcomeSucceeded          Outcome = "SUCCEEDED"
	OutcomePartiallyCompleted Outcome = "PARTIALLY_COMPLETED"
	OutcomeFailed             Outcome = "FAILED"
)

// Valid reports whether o is an outcome.
func (o Outcome) Valid() bool {
	return o == OutcomeSucceeded || o == OutcomePartiallyCompleted || o == OutcomeFailed
}

// Join modes.
const (
	JoinAny = "ANY"
	JoinAll = "ALL"
)

// NodeSpec is one entry of `nodes`: exactly one of a step (Step), a branch,
// a switch, a join or a terminal (Outcome). The first node is the entry.
type NodeSpec struct {
	ID string `json:"id"`
	// A step node, as a v1 step plus where it goes next.
	Step      string         `json:"step,omitzero"`
	With      jsontext.Value `json:"with,omitzero"`
	When      string         `json:"when,omitzero"`
	Timeout   Duration       `json:"timeout,omitzero"`
	Retry     *Retry         `json:"retry,omitzero"`
	OnFailure OnFailure      `json:"on_failure,omitzero"`
	// Next follows a step or a join.
	Next   string      `json:"next,omitzero"`
	Branch *BranchSpec `json:"branch,omitzero"`
	Switch *SwitchSpec `json:"switch,omitzero"`
	Join   *JoinSpec   `json:"join,omitzero"`
	// A terminal node.
	Outcome    Outcome  `json:"outcome,omitzero"`
	FinishWhen []Finish `json:"finish_when,omitzero"`
}

// BranchSpec is if/else on one guard, in the `when` grammar.
type BranchSpec struct {
	When string `json:"when"`
	Then string `json:"then"`
	Else string `json:"else"`
}

// SwitchSpec is ordered cases, the first that holds wins, and a default.
type SwitchSpec struct {
	Cases   []CaseSpec `json:"cases"`
	Default string     `json:"default,omitzero"`
}

// CaseSpec is one case of a switch.
type CaseSpec struct {
	When string `json:"when"`
	Next string `json:"next"`
}

// JoinSpec merges exclusive paths: From is exactly the node's direct
// predecessors (D307).
type JoinSpec struct {
	Mode string   `json:"mode"`
	From []string `json:"from"`
}

// Kind returns the node's kind, or "" unless it is exactly one kind.
func (n *NodeSpec) Kind() NodeKind {
	var k NodeKind
	c := 0
	for _, x := range []struct {
		set  bool
		kind NodeKind
	}{
		{n.Step != "", NodeKindStep},
		{n.Branch != nil, NodeKindBranch},
		{n.Switch != nil, NodeKindSwitch},
		{n.Join != nil, NodeKindJoin},
		{n.Outcome != "" || len(n.FinishWhen) > 0, NodeKindTerminal},
	} {
		if x.set {
			k, c = x.kind, c+1
		}
	}
	if c != 1 {
		return ""
	}
	return k
}

// wellFormed reports whether the node holds only its kind's fields.
func (n *NodeSpec) wellFormed() bool {
	stepFields := len(n.With) > 0 || n.When != "" || n.Timeout != 0 || n.Retry != nil || n.OnFailure != ""
	switch n.Kind() {
	case NodeKindStep:
		return true
	case NodeKindJoin:
		return !stepFields
	case NodeKindBranch, NodeKindSwitch, NodeKindTerminal:
		return !stepFields && n.Next == ""
	}
	return false
}

// Spec is a step node as a step.
func (n *NodeSpec) Spec() StepSpec {
	return StepSpec{
		ID: n.ID, Step: n.Step, With: n.With, When: n.When, Timeout: n.Timeout, Retry: n.Retry, OnFailure: n.OnFailure,
	}
}

// Edge is one way out of a node.
type Edge struct {
	To string
	// Label says which way this is: "then", "else", "case <i>", "default".
	Label string
	// Guard is the expression that selects it.
	Guard string
}

// Edges lists the node's ways out, in evaluation order; an unset target is
// left out, and Validate reports it.
func (n *NodeSpec) Edges() []Edge {
	var out []Edge
	add := func(e Edge) {
		if e.To != "" {
			out = append(out, e)
		}
	}
	switch n.Kind() {
	case NodeKindStep, NodeKindJoin:
		add(Edge{To: n.Next})
	case NodeKindBranch:
		add(Edge{To: n.Branch.Then, Label: "then", Guard: n.Branch.When})
		add(Edge{To: n.Branch.Else, Label: "else"})
	case NodeKindSwitch:
		for i, c := range n.Switch.Cases {
			add(Edge{To: c.Next, Label: "case " + strconv.Itoa(i), Guard: c.When})
		}
		add(Edge{To: n.Switch.Default, Label: "default"})
	case NodeKindTerminal:
	}
	return out
}

// Flow is a definition as a graph: a v2 definition's nodes, or a v1
// definition lifted in memory to a line ending at EndNode (D301). The
// engine runs lifted v1 definitions by step index, never through a Flow;
// it is what path-wise readers share.
type Flow struct {
	Entry string
	// Nodes are in declaration order.
	Nodes []NodeSpec
	index map[string]int
}

// Node returns the node with id, or nil. With a repeated id it returns the
// first; Validate refuses repeats.
func (f *Flow) Node(id string) *NodeSpec {
	if i, ok := f.index[id]; ok {
		return &f.Nodes[i]
	}
	return nil
}

func newFlow(nodes []NodeSpec) *Flow {
	f := &Flow{Nodes: nodes, index: make(map[string]int, len(nodes))}
	if len(nodes) > 0 {
		f.Entry = nodes[0].ID
	}
	for i := range nodes {
		if _, dup := f.index[nodes[i].ID]; !dup {
			f.index[nodes[i].ID] = i
		}
	}
	return f
}

// lift is v1's `do` as a line to one terminal holding finish_when. It reads
// the stored definition only; nothing of it is ever stored.
func (d *Definition) lift() *Flow {
	nodes := make([]NodeSpec, 0, len(d.Do)+1)
	for i := range d.Do {
		s := d.Do[i]
		next := EndNode
		if i+1 < len(d.Do) {
			next = d.Do[i+1].ID
		}
		nodes = append(nodes, NodeSpec{
			ID: s.ID, Step: s.Step, With: s.With, When: s.When, Timeout: s.Timeout, Retry: s.Retry, OnFailure: s.OnFailure, Next: next,
		})
	}
	nodes = append(nodes, NodeSpec{ID: EndNode, Outcome: OutcomeSucceeded, FinishWhen: d.Finish})
	return newFlow(nodes)
}

// IsV2 reports whether the definition is the node format.
func (d *Definition) IsV2() bool { return d.APIVersion == APIVersionV2 }

// Flow returns the definition as a graph.
func (d *Definition) Flow() *Flow {
	if d.flow != nil {
		return d.flow
	}
	if d.IsV2() {
		return newFlow(d.Nodes)
	}
	return d.lift()
}

// stepsInOrder lists a v2 definition's step nodes, each after every node
// that leads to it, declaration order breaking ties. Nodes on a cycle come
// last in declaration order; Validate refuses them.
func stepsInOrder(f *Flow) []StepSpec {
	incoming := make(map[string]int, len(f.Nodes))
	for i := range f.Nodes {
		for _, e := range f.Nodes[i].Edges() {
			incoming[e.To]++
		}
	}
	done := make(map[string]bool, len(f.Nodes))
	out := make([]StepSpec, 0, len(f.Nodes))
	place := func(n *NodeSpec) {
		done[n.ID] = true
		if n.Kind() == NodeKindStep {
			out = append(out, n.Spec())
		}
		for _, e := range n.Edges() {
			incoming[e.To]--
		}
	}
	for progress := true; progress; {
		progress = false
		for i := range f.Nodes {
			if n := &f.Nodes[i]; !done[n.ID] && incoming[n.ID] <= 0 {
				place(n)
				progress = true
				break
			}
		}
	}
	for i := range f.Nodes {
		if n := &f.Nodes[i]; !done[n.ID] {
			place(n)
		}
	}
	return out
}
