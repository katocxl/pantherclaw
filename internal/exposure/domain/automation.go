// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"slices"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Automation exposure (G0 M11 D37, F025, F262, F747–F750, F754, HR-289).
// An automation holds reach two ways, kept apart:
//
//   - current execution reach: the EFFECTIVE rights of the active grants it
//     issued under its ceiling, tagged with the automation (Team, F025);
//   - its issuance ceiling: what it could issue any time, the ceiling's
//     bounds through every ceiling agent, in the ISSUANCE_CEILING view
//     (Business, F262). It is potential reach and never stands in for, or
//     adds to, an agent's current reach.
//
// Automations rank by their ceiling, never by how much they ran: an idle
// automation with a wide ceiling is no less exposed (F754).

// IssuanceCeiling is the view of what an automation's ceiling lets it
// issue (D37).
const IssuanceCeiling View = "ISSUANCE_CEILING"

// Potential reports a view of reach nobody holds yet: the issuance ceiling.
// Readers of current authority (views, graphs, ranking, posture, search,
// previews) leave it out unless it is asked for by name (D37a).
func (v View) Potential() bool { return v == IssuanceCeiling }

// HeldReach drops the potential (ceiling) rights.
func HeldReach(rights []Right) []Right {
	return slices.DeleteFunc(slices.Clone(rights), func(r Right) bool { return r.View.Potential() })
}

// ReasonCeiling marks a ceiling right.
const ReasonCeiling = "ISSUANCE_CEILING"

// Ceiling is an automation's issuance ceiling as exposure reads it.
type Ceiling struct {
	ID         ids.UUID
	Automation ids.UUID
	// Agents are the ceiling's agents (a cohort resolved to its members).
	Agents          []ids.UUID
	Bounds          gdomain.Bounds
	DelegationDepth int
	ReviewBy        time.Time
	// Active is false for a SUPERSEDED, EXPIRED, VOID or REVOKED ceiling,
	// which can issue nothing and so has no reach (D37a).
	Active bool
}

// ceilings adds the ISSUANCE_CEILING view: every right a grant inside an
// ACTIVE ceiling could carry, for every ceiling agent. Its rights are
// CONDITIONAL (an execution must issue them first), never USABLE; reach
// through a connection whose package is unknown is UNCERTAIN, never absent.
// A ceiling that is not active, or past its review date, can issue nothing
// and has no rights (D37a).
func ceilings(b *builder, in Inputs, conns map[ids.UUID]*Connection) {
	for _, ce := range in.Ceilings {
		if !ce.Active || !in.Now.Before(ce.ReviewBy) {
			continue
		}
		label, reasons := Conditional, []string{ReasonCeiling}
		expires := ptr(ce.ReviewBy)
		auto := ptr(ce.Automation)
		agents := slices.Clone(ce.Agents)
		slices.SortFunc(agents, func(a, b ids.UUID) int { return cmp.Compare(a.String(), b.String()) })
		for _, agent := range slices.Compact(agents) {
			for _, c := range sortedConns(conns) {
				base, baseReasons := label, slices.Clone(reasons)
				if c.State == "QUARANTINED" {
					baseReasons = append(baseReasons, ReasonConnectionQuarantined)
				}
				if !c.Known {
					l := base
					if l.Rank() < Uncertain.Rank() {
						l = Uncertain
					}
					for _, v := range []Verb{VerbRead, VerbUpdate} {
						b.add(Right{
							View: IssuanceCeiling, Label: l, Agent: ptr(agent), Connection: ptr(c.ID), Automation: auto,
							ResourceGroup: "connection:" + c.Name, Verb: v, Coverage: CoverageUnknown,
							Reasons: append(slices.Clone(baseReasons), ReasonPackageUnknown), ExpiresAt: expires,
						})
					}
					continue
				}
				for _, op := range c.Operations {
					if !grantAllows(ce.Bounds, op) {
						continue
					}
					rs := slices.Clone(baseReasons)
					if why := in.Policy.restriction(op.Name); why != "" {
						rs = append(rs, why)
					}
					cov, ok := in.Coverage[CoverageKey{Agent: agent, Connection: c.ID, Operation: op.Name}]
					if !ok {
						cov = CoverageUnknown
					}
					for _, cl := range Classify(op, *c) {
						b.add(Right{
							View: IssuanceCeiling, Label: base, Agent: ptr(agent), Connection: ptr(c.ID), Automation: auto,
							Operation: op.Name, ResourceGroup: Group(op, *c), Verb: cl.Verb, Basis: cl.Explain(),
							Irreversible: op.Reversibility == defs.Irreversible, Coverage: cov, Reasons: rs, ExpiresAt: expires,
						})
					}
					if ce.DelegationDepth > 0 {
						b.add(Right{
							View: IssuanceCeiling, Label: base, Agent: ptr(agent), Connection: ptr(c.ID), Automation: auto,
							ResourceGroup: Group(op, *c), Verb: VerbDelegate, Basis: BasisDelegation, Coverage: cov,
							Reasons: append(rs, ReasonDelegable), Depth: ce.DelegationDepth, ExpiresAt: expires,
						})
					}
				}
			}
		}
	}
}

// AutomationKeys are an automation's ranking keys (D37): the ceiling's
// keys, ranked as an agent's are, plus its current execution reach shown
// beside them and never used to rank (F754).
type AutomationKeys struct {
	Ceiling RankKeys
	// Agents is how many ceiling agents the ceiling reaches through.
	Agents int
	// CurrentRights counts the current effective rights of grants it
	// issued; ActiveGrants how many grants they come from.
	CurrentRights int
	ActiveGrants  int
}

// RankedAutomation is one ranked automation.
type RankedAutomation struct {
	Automation ids.UUID
	Keys       AutomationKeys
}

// RankAutomations orders automations by their issuance ceiling's
// consequence, then scope, usability and enforceability (HR-289): never by
// activity. Rights must already be filtered by the viewer's permissions.
func RankAutomations(rights []Right, irreversible map[string]bool) []RankedAutomation {
	type acc struct {
		keys   AutomationKeys
		groups map[string]bool
		conns  map[string]bool
		agents map[string]bool
		grants map[string]bool
		seen   bool
	}
	by := map[ids.UUID]*acc{}
	get := func(a ids.UUID) *acc {
		x, ok := by[a]
		if !ok {
			x = &acc{
				groups: map[string]bool{}, conns: map[string]bool{}, agents: map[string]bool{}, grants: map[string]bool{},
				keys: AutomationKeys{Ceiling: RankKeys{Consequence: VerbRead, Usability: Expired, Enforceability: CoverageEnforced, Owned: true}},
			}
			by[a] = x
		}
		return x
	}
	for _, r := range rights {
		if r.Automation == nil || !r.Label.Current() {
			continue
		}
		a := get(*r.Automation)
		//exhaustive:ignore // only the effective and ceiling views carry an automation's reach
		switch r.View {
		case Effective:
			a.keys.CurrentRights++
			if r.Grant != nil {
				a.grants[r.Grant.String()] = true
			}
			continue
		case IssuanceCeiling:
		default:
			continue
		}
		k := &a.keys.Ceiling
		if !a.seen || r.Verb.Consequence() > k.Consequence.Consequence() {
			k.Consequence = r.Verb
		}
		a.seen = true
		k.Irreversible = k.Irreversible || r.Irreversible || irreversible[r.Operation]
		a.groups[r.ResourceGroup] = true
		if r.Connection != nil {
			a.conns[r.Connection.String()] = true
		}
		if r.Agent != nil {
			a.agents[r.Agent.String()] = true
		}
		if r.Label.Rank() < k.Usability.Rank() {
			k.Usability = r.Label
		}
		if r.Coverage.Rank() < k.Enforceability.Rank() {
			k.Enforceability = r.Coverage
		}
		k.Revocable++ // revoking the automation's authority removes every ceiling right
	}
	out := make([]RankedAutomation, 0, len(by))
	for id, a := range by {
		a.keys.Ceiling.ResourceGroups, a.keys.Ceiling.Connections = len(a.groups), len(a.conns)
		a.keys.Agents, a.keys.ActiveGrants = len(a.agents), len(a.grants)
		out = append(out, RankedAutomation{Automation: id, Keys: a.keys})
	}
	slices.SortFunc(out, func(a, b RankedAutomation) int {
		x, y := a.Keys.Ceiling, b.Keys.Ceiling
		return cmp.Or(
			-cmp.Compare(x.Consequence.Consequence(), y.Consequence.Consequence()),
			-cmp.Compare(boolRank(x.Irreversible), boolRank(y.Irreversible)),
			-cmp.Compare(x.ResourceGroups+x.Connections, y.ResourceGroups+y.Connections),
			-cmp.Compare(a.Keys.Agents, b.Keys.Agents),
			cmp.Compare(x.Usability.Rank(), y.Usability.Rank()),
			cmp.Compare(x.Enforceability.Rank(), y.Enforceability.Rank()),
			cmp.Compare(a.Automation.String(), b.Automation.String()),
		)
	})
	return out
}

// Graph vocabulary for automations (D37a).
const (
	// EdgeIssued: automation -> a grant it issued under its ceiling.
	EdgeIssued = "issued"
	// EdgeCeiling: automation -> a resource group its ceiling lets it
	// issue reach to, through a ceiling agent (in Context).
	EdgeCeiling = "ceiling"
	// NodeAutomation is the automation node type.
	NodeAutomation = "automation"
)

// AutomationEdges are the authority graph's automation edges: an
// automation issued each grant behind its execution reach, and, only when
// the ceiling is asked for, the reach its ceiling allows. Ceiling edges are
// POSSIBLE: potential reach, never counted as held (D37a).
func AutomationEdges(rights []Right, ceiling bool) []Edge {
	var out []Edge
	for _, r := range rights {
		if r.Automation == nil {
			continue
		}
		auto := Node{Type: NodeAutomation, ID: r.Automation.String()}
		switch {
		case r.View == Effective && r.Grant != nil:
			out = append(out, Edge{
				From: auto, To: Node{Type: "grant", ID: r.Grant.String()}, Context: []Node{ownerNode(r)}, Kind: EdgeIssued,
				State: stateOf(r), Basis: "RULE_MATCH", ExpiresAt: r.ExpiresAt, Provenance: string(Effective),
			})
		case ceiling && r.View == IssuanceCeiling:
			out = append(out, Edge{
				From: auto, To: Node{Type: "resource", ID: r.ResourceGroup}, Context: []Node{ownerNode(r)}, Kind: EdgeCeiling,
				Verb: r.Verb, Operation: r.Operation, State: EdgePossible, Coverage: r.Coverage, Basis: "RULE_MATCH",
				ExpiresAt: r.ExpiresAt, Provenance: string(IssuanceCeiling),
			})
		}
	}
	return out
}
