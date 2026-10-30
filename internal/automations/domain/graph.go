// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "strconv"

// Graph node and edge types (F663).
const (
	NodeTrigger   = "TRIGGER"
	NodeCondition = "CONDITION"
	NodeStep      = "STEP"
	NodeGate      = "GATE"
	NodeFinish    = "FINISH"
	NodeBranch    = "BRANCH"
	NodeSwitch    = "SWITCH"
	NodeJoin      = "JOIN"

	EdgeNext       = "NEXT"
	EdgeBranch     = "BRANCH"
	EdgeOnFailure  = "ON_FAILURE"
	EdgeCompensate = "COMPENSATE"
	EdgeFinishes   = "FINISHES"
)

// GraphNode is one node of a version graph.
type GraphNode struct {
	ID        string
	Type      string
	Kind      string
	Label     string
	Authority []string
	Effectful bool
}

// GraphEdge connects two nodes. A BRANCH edge carries which way it is and
// the guard that selects it.
type GraphEdge struct{ From, To, Type, Label, Guard string }

// graphID is a v2 node's id in the graph, matching its v1 form for steps.
func graphID(f *Flow, id string) string {
	if n := f.Node(id); n != nil && n.Kind() == NodeKindTerminal {
		return "finish-" + id
	}
	if n := f.Node(id); n != nil && n.Kind() != NodeKindStep {
		return "node-" + id
	}
	return "step-" + id
}

// Graph returns the version as nodes and edges: the trigger, its
// conditions, the steps in order (gates as GATE nodes), compensation and
// finish conditions, each step linked to the authority it uses: "ceiling"
// for launch_run and the waits on its runs, else its platform scopes. A v2
// version also has its branch, switch and join nodes, with an edge per way
// out, and one finish node per terminal.
func Graph(d *Definition) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge
	prev := "trigger"
	nodes = append(nodes, GraphNode{ID: prev, Type: NodeTrigger, Kind: string(d.When.Kind()), Label: whenText(d, nil)})
	for i, c := range d.If {
		id := "if-" + strconv.Itoa(i)
		nodes = append(nodes, GraphNode{ID: id, Type: NodeCondition, Label: c})
		edges = append(edges, GraphEdge{From: prev, To: id, Type: EdgeNext})
		prev = id
	}
	add := func(s StepSpec) GraphNode {
		k := Catalog[s.Step]
		n := GraphNode{ID: "step-" + s.ID, Type: NodeStep, Kind: s.Step, Label: stepText(d, s, nil), Effectful: k.Effectful}
		if s.Step == KindGate {
			n.Type = NodeGate
		}
		switch s.Step {
		case KindLaunchRun, KindWaitRun, KindWaitEffect:
			n.Authority = []string{"ceiling"}
		default:
			for _, p := range d.Authority.Platform {
				if p.Step == s.Step {
					n.Authority = append(n.Authority, p.Scopes...)
				}
			}
		}
		nodes = append(nodes, n)
		return n
	}
	if d.IsV2() {
		f := d.Flow()
		edges = append(edges, GraphEdge{From: prev, To: graphID(f, f.Entry), Type: EdgeNext})
		for i := range f.Nodes {
			n := &f.Nodes[i]
			switch n.Kind() {
			case NodeKindStep:
				add(n.Spec())
			case NodeKindBranch:
				nodes = append(nodes, GraphNode{ID: graphID(f, n.ID), Type: NodeBranch, Label: n.Branch.When})
			case NodeKindSwitch:
				nodes = append(nodes, GraphNode{ID: graphID(f, n.ID), Type: NodeSwitch, Label: n.ID})
			case NodeKindJoin:
				nodes = append(nodes, GraphNode{ID: graphID(f, n.ID), Type: NodeJoin, Kind: n.Join.Mode, Label: n.ID})
			case NodeKindTerminal:
				nodes = append(nodes, GraphNode{ID: graphID(f, n.ID), Type: NodeFinish, Kind: string(n.Outcome), Label: n.ID})
				for _, w := range n.FinishWhen {
					edges = append(edges, GraphEdge{From: "step-" + w.Step, To: graphID(f, n.ID), Type: EdgeFinishes, Label: string(w.Condition)})
				}
			}
			for _, e := range n.Edges() {
				t := EdgeNext
				if e.Label != "" {
					t = EdgeBranch
				}
				edges = append(edges, GraphEdge{From: graphID(f, n.ID), To: graphID(f, e.To), Type: t, Label: e.Label, Guard: e.Guard})
			}
		}
	} else {
		for _, s := range d.Do {
			n := add(s)
			edges = append(edges, GraphEdge{From: prev, To: n.ID, Type: EdgeNext})
			prev = n.ID
		}
	}
	if d.IfFails != nil {
		cprev := ""
		for _, s := range d.IfFails.Compensate {
			n := add(s)
			switch {
			case s.Compensates != "":
				edges = append(edges, GraphEdge{From: "step-" + s.Compensates, To: n.ID, Type: EdgeCompensate})
			case cprev == "":
				for _, x := range d.Do {
					edges = append(edges, GraphEdge{From: "step-" + x.ID, To: n.ID, Type: EdgeOnFailure})
				}
			default:
				edges = append(edges, GraphEdge{From: cprev, To: n.ID, Type: EdgeCompensate})
			}
			cprev = n.ID
		}
	}
	for i, f := range d.Finish {
		id := "finish-" + strconv.Itoa(i)
		nodes = append(nodes, GraphNode{ID: id, Type: NodeFinish, Kind: string(f.Condition), Label: f.Step + " " + string(f.Condition)})
		edges = append(edges, GraphEdge{From: "step-" + f.Step, To: id, Type: EdgeFinishes})
	}
	return nodes, edges
}
