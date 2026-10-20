// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"fmt"
	"slices"
	"strings"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Reason codes of data scope and required sets (G0 M14 D11, D78).
const (
	// ReasonDataScope: the answer is limited to a record scope or to data
	// classes, which the gateway applies (an obligation).
	ReasonDataScope = "DATA_SCOPE"
	// ReasonScopeUnsupported: a data scope applies, but the definition or
	// the route cannot enforce it (HR-302).
	ReasonScopeUnsupported = "SCOPE_UNSUPPORTED"
	// ReasonTargetSetRequired, ReasonDestinationSetRequired: the definition
	// requires a target or destination set that no grant or guardrail binds.
	ReasonTargetSetRequired      = "TARGET_SET_REQUIRED"
	ReasonDestinationSetRequired = "DESTINATION_SET_REQUIRED"
	// ReasonDelegationNotAllowed: the requester's grant does not let this
	// call go to the peer agent (D89, D33).
	ReasonDelegationNotAllowed = "DELEGATION_NOT_ALLOWED"
	// ReasonPeerCheckUnavailable: a call through an a2a connection with no
	// peer check wired (fail closed).
	ReasonPeerCheckUnavailable = "PEER_CHECK_UNAVAILABLE"
)

// ScopeRule names the source of data scope obligations on receipts: the
// intersection of the grant chain (envelopes included) and the policy.
const ScopeRule = "pantherclaw.data-scope"

// boundariesM14 runs the M14 checks of step 7: peer calls (D89), required
// sets (D78) and data scope (D11).
func (p *Pipeline) boundariesM14(ctx context.Context, s *state) {
	p.peerCheck(ctx, s)
	s.requiredSets()
	s.dataScope()
}

// peerCheck asks the peer port about a call through an a2a connection.
func (p *Pipeline) peerCheck(ctx context.Context, s *state) {
	if s.conn == nil || s.conn.Kind != "a2a" || (s.def != nil && s.def.Access == defs.AccessRead) {
		return // a read of a peer's task delegates nothing (D111)
	}
	leaf, ok := s.chain.Leaf()
	switch {
	case !ok:
		return // no grant: step 3 already refused
	case p.Peer == nil:
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonPeerCheckUnavailable, "calls to peer agents cannot be checked", "")
		return
	}
	if reason := p.Peer(ctx, s.req.Org, *s.conn, leaf); reason != "" {
		s.cl.add(StepBoundaries, adomain.Deny, ReasonDelegationNotAllowed, reason, "grant "+leaf.ID.String())
	}
}

// requiredSets denies an action whose definition requires a target or
// destination set that neither a grant nor a guardrail of its chain binds
// (D78): an unbounded post to any channel, for example.
func (s *state) requiredSets() {
	if s.def == nil || s.gAction == nil || len(s.chain.Grants) == 0 {
		return
	}
	eff := s.chain.Effective()
	for _, c := range s.def.Constraints {
		if !c.Required {
			continue
		}
		switch c.Kind { //nolint:exhaustive // only sets can be required (validated)
		case defs.ConstraintTargetSet:
			if eff.Targets == nil {
				s.cl.add(StepBoundaries, adomain.Deny, ReasonTargetSetRequired,
					s.def.Operation+" needs a grant or guardrail that lists its targets", "")
				continue
			}
			if _, ok := (*eff.Targets)[s.def.Target.Type]; !ok {
				s.cl.add(StepBoundaries, adomain.Deny, ReasonTargetSetRequired,
					s.def.Operation+" needs a grant or guardrail that lists its "+s.def.Target.Type+" targets", "")
			}
		case defs.ConstraintDestinationSet:
			if eff.Destinations == nil {
				s.cl.add(StepBoundaries, adomain.Deny, ReasonDestinationSetRequired,
					s.def.Operation+" needs a grant or guardrail that lists its destinations", "")
			}
		}
	}
}

// dataScope attaches the action's data scope obligations (D11, F101–F103):
// the record scope and data classes of the grant chain (envelopes and
// ancestors included) intersected with every data scope rule of the
// policy, as one record_scope and one data_classes obligation. The rule
// obligations are replaced by them. When a scope applies but the
// definition does not declare it can enforce that kind (Scoping), or the
// route is not one whose answer the gateway itself reads (a pantherclaw_held
// http or postgres connection, on the http or mcp channel), the action is
// CANNOT_AUTHORIZE SCOPE_UNSUPPORTED (HR-302): never silently unscoped.
// Without any scope there is no obligation (the gateway still withholds
// secret values).
func (s *state) dataScope() {
	if s.def == nil {
		return
	}
	var bound gdomain.ScopeBound
	if s.gAction != nil && len(s.chain.Grants) > 0 {
		bound = s.chain.Effective().Scope[s.def.Operation]
	}
	records, classes := bound.Records, []string(nil)
	if bound.Classes != nil {
		classes = slices.Clone(bound.Classes.IDs)
	}
	var rules []string
	kept := s.ev.Obligations[:0:0]
	for _, o := range s.ev.Obligations {
		switch o.Kind { //nolint:exhaustive // only the scope kinds are merged
		case pdomain.RecordScope:
			rules = append(rules, o.Rule)
			records = meetRecords(records, &gdomain.RecordScope{Key: o.Param, Values: o.Values})
		case pdomain.DataClasses:
			rules = append(rules, o.Rule)
			classes = meetClasses(classes, o.Values)
		default:
			kept = append(kept, o)
		}
	}
	s.ev.Obligations = kept
	if records == nil && classes == nil {
		return
	}
	if why := s.scopeUnsupported(records != nil, classes != nil); why != "" {
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonScopeUnsupported, why, "")
		return
	}
	source := ScopeRule
	if len(rules) > 0 {
		source += " (policy " + strings.Join(rules, ", ") + ")"
	}
	var parts []string
	if records != nil {
		s.ev.Obligations = append(s.ev.Obligations, pdomain.Obligation{
			Rule: ScopeRule, Kind: pdomain.RecordScope, Param: records.Key, Values: slices.Clone(records.Values), Timing: pdomain.TimingBeforeExecution,
		})
		parts = append(parts, fmt.Sprintf("records with %s in [%s]", records.Key, strings.Join(records.Values, ", ")))
	}
	if classes != nil {
		slices.Sort(classes)
		s.ev.Obligations = append(s.ev.Obligations, pdomain.Obligation{
			Rule: ScopeRule, Kind: pdomain.DataClasses, Values: classes, Timing: pdomain.TimingBeforeExecution,
		})
		parts = append(parts, "data classes ["+strings.Join(classes, ", ")+"]")
	}
	s.cl.add(StepRequirements, adomain.AllowWithObligations, ReasonDataScope, "the answer is limited to "+strings.Join(parts, " and "), source)
}

// scopeUnsupported says why a scope cannot be enforced on this action, or "".
func (s *state) scopeUnsupported(records, classes bool) string {
	switch {
	case records && !slices.Contains(s.def.Scoping, "records"):
		return s.def.Operation + " cannot limit the records of its answer"
	case classes && !slices.Contains(s.def.Scoping, "classes"):
		return s.def.Operation + " cannot limit the data classes of its answer"
	case s.a.Channel != string(defs.ChannelHTTP) && s.a.Channel != string(defs.ChannelMCP):
		return "a data scope is enforced only on answers the gateway reads, not through the " + s.a.Channel + " channel"
	case s.conn == nil || s.conn.AccessMode != "pantherclaw_held" || (s.conn.Kind != "http" && s.conn.Kind != "postgres"):
		return "a data scope is enforced only through a pantherclaw_held http or postgres connection"
	}
	return ""
}

// meetRecords is the records both scopes allow: one key's common values;
// two different keys allow none, since one answer cannot be held to both.
func meetRecords(a, b *gdomain.RecordScope) *gdomain.RecordScope {
	switch {
	case a == nil:
		return &gdomain.RecordScope{Key: b.Key, Values: slices.Clone(b.Values)}
	case a.Key != b.Key:
		return &gdomain.RecordScope{Key: a.Key, Values: []string{}}
	}
	out := &gdomain.RecordScope{Key: a.Key, Values: []string{}}
	for _, v := range a.Values {
		if slices.Contains(b.Values, v) {
			out.Values = append(out.Values, v)
		}
	}
	return out
}

// meetClasses is the classes both allow; nil allows every class.
func meetClasses(a, b []string) []string {
	if a == nil {
		return slices.Clone(b)
	}
	out := []string{}
	for _, c := range a {
		if slices.Contains(b, c) {
			out = append(out, c)
		}
	}
	return out
}
