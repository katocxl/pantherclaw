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

	EdgeNext       = "NEXT"
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

// GraphEdge connects two nodes.
type GraphEdge struct{ From, To, Type string }

// Graph returns the version as nodes and edges: the trigger, its
// conditions, the steps in order (gates as GATE nodes), compensation and
// finish conditions, each step linked to the authority it uses: "ceiling"
// for launch_run and the waits on its runs, else its platform scopes.
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
	for _, s := range d.Do {
		n := add(s)
		edges = append(edges, GraphEdge{From: prev, To: n.ID, Type: EdgeNext})
		prev = n.ID
	}
	if d.IfFails != nil {
		cprev := ""
		for _, s := range d.IfFails.Compensate {
			n := add(s)
			if cprev == "" {
				for _, x := range d.Do {
					edges = append(edges, GraphEdge{From: "step-" + x.ID, To: n.ID, Type: EdgeOnFailure})
				}
			} else {
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
