// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/v2"
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// FlowAllowance lets data of Classes, read anywhere in the run tree, go to
// Destinations (G0 M16 D75): an external disclosure after a sensitive read
// that one allowance covers is not held. Flows are not bounds and are never
// on guardrails.
type FlowAllowance struct {
	// Classes is a subset of pii and secret.
	Classes []string `json:"classes"`
	// Destinations are exact ActionIR destinations (kind and id), at least
	// one.
	Destinations []actionir.Destination `json:"destinations"`
}

// Caps on a grant's flows.
const (
	maxFlows            = 16
	maxFlowDestinations = 64
	maxFlowField        = 512
)

// FlowClasses are the classes a flow allowance can name (D71).
var FlowClasses = []string{"pii", "secret"}

func validateFlows(flows []FlowAllowance) error {
	if len(flows) > maxFlows {
		return invalid("grant: at most %d flows", maxFlows)
	}
	for i, f := range flows {
		at := fmt.Sprintf("flows[%d]", i)
		if len(f.Classes) == 0 || len(f.Destinations) == 0 || len(f.Destinations) > maxFlowDestinations {
			return invalid("grant: %s names at least one class and 1 to %d destinations", at, maxFlowDestinations)
		}
		for j, c := range f.Classes {
			if !slices.Contains(FlowClasses, c) || slices.Contains(f.Classes[:j], c) {
				return invalid("grant: %s classes are distinct values of %v", at, FlowClasses)
			}
		}
		for j, d := range f.Destinations {
			if (d.Kind != "internal" && d.Kind != "external") || d.ID == "" || len(d.ID) > maxFlowField ||
				slices.Contains(f.Destinations[:j], d) {
				return invalid("grant: %s destinations are distinct, each with a kind (internal or external) and an id", at)
			}
		}
	}
	return nil
}

// Covers reports whether the allowance covers every class and every
// destination given (D75); no destinations never match.
func (f FlowAllowance) Covers(classes []string, dests []actionir.Destination) bool {
	if len(dests) == 0 {
		return false
	}
	for _, c := range classes {
		if !slices.Contains(f.Classes, c) {
			return false
		}
	}
	for _, d := range dests {
		if !slices.Contains(f.Destinations, d) {
			return false
		}
	}
	return true
}

// within reports whether f is covered by one of parent (classes and
// destinations both subsets).
func (f FlowAllowance) within(parent []FlowAllowance) bool {
	return slices.ContainsFunc(parent, func(p FlowAllowance) bool { return p.Covers(f.Classes, f.Destinations) })
}

// FlowsWithin returns the first flow of child that no allowance of parent
// covers, or -1 (HR-432): flows only narrow, and none means none.
func FlowsWithin(child, parent []FlowAllowance) int {
	return slices.IndexFunc(child, func(f FlowAllowance) bool { return !f.within(parent) })
}

// FlowCovers reports whether one of flows covers every class and every
// destination (D75).
func FlowCovers(flows []FlowAllowance, classes []string, dests []actionir.Destination) bool {
	return slices.ContainsFunc(flows, func(f FlowAllowance) bool { return f.Covers(classes, dests) })
}

// EncodeFlows is the stored form of flows: nil for none.
func EncodeFlows(flows []FlowAllowance) ([]byte, error) {
	if len(flows) == 0 {
		return nil, nil
	}
	return json.Marshal(flows, json.Deterministic(true))
}

// DecodeFlows strictly decodes stored or requested flows; empty means none.
func DecodeFlows(raw []byte) ([]FlowAllowance, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []FlowAllowance
	if err := json.Unmarshal(raw, &out, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("grant: flows: %v", err)
	}
	if err := validateFlows(out); err != nil {
		return nil, err
	}
	return out, nil
}

// FlowCovers reports whether every grant of the chain, from the root down
// to the run's own, has a flow that covers every class and every
// destination (D75, HR-432): a parent's narrowing revision stops a flow its
// child still names, as bounds are checked at every level. A chain without
// grants covers nothing.
func (c Chain) FlowCovers(classes []string, dests []actionir.Destination) bool {
	return len(c.Grants) > 0 && !slices.ContainsFunc(c.Grants, func(g Grant) bool { return !FlowCovers(g.Flows, classes, dests) })
}
