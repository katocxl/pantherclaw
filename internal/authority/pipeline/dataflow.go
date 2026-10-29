// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"slices"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// classRank orders the data classes from the most open to the strictest;
// "" (no class known) is below public.
var classRank = map[string]int{"": -1, "public": 0, "internal": 1, "pii": 2, "secret": 3}

// RaiseClass is the stricter of class and by (G0 M16 D72, HR-430): a
// classification fact about the action's target (D80) raises a read's
// class this way and never lowers it. A value that is not a data class
// raises nothing.
func RaiseClass(class, by string) string {
	if r, ok := classRank[by]; ok && r > classRank[class] {
		return by
	}
	return class
}

// ReadClass is the class of the data an access: read operation returns
// (G0 M16 D72, HR-430), "" when none is known or the operation is not a
// read:
//   - the strictest class among the definition's declared response
//     fields, capped by the decision's data_classes obligation when there
//     is one;
//   - for an operation that declares a data scope (Scoping) and has a
//     data_classes obligation, the strictest class the obligation allows;
//   - then raised, never lowered, by classified: the class a
//     pc.classification fact gives the action's target (D80), or "".
//
// It is a class and nothing else: the content of the answer is never
// recorded (HR-434).
func ReadClass(d *defs.Definition, obligations []pdomain.Obligation, classified string) string {
	if d == nil || d.Access != defs.AccessRead {
		return ""
	}
	declared := ""
	if d.Response != nil {
		for _, f := range d.Response.Fields {
			declared = RaiseClass(declared, f.Class)
		}
	}
	allowed, scoped := "", false
	for _, o := range obligations {
		if o.Kind != pdomain.DataClasses {
			continue
		}
		strictest := ""
		for _, c := range o.Values {
			strictest = RaiseClass(strictest, c)
		}
		if !scoped || classRank[strictest] < classRank[allowed] {
			allowed = strictest
		}
		scoped = true
	}
	class := declared
	switch {
	case declared != "" && scoped && classRank[allowed] < classRank[declared]:
		class = allowed
	case declared == "" && scoped && len(d.Scoping) > 0:
		class = allowed
	}
	return RaiseClass(class, classified)
}

// RecordedReadClass is the read class the transaction records (D72): the
// evaluation's ReadClass when its decision is ALLOW or
// ALLOW_WITH_OBLIGATIONS, "" otherwise.
func (e *Evaluation) RecordedReadClass() string {
	if e.Decision != adomain.Allow && e.Decision != adomain.AllowWithObligations {
		return ""
	}
	return e.ReadClass
}

// readClass sets the evaluation's read class from the definition, the
// final obligations and the target's classification (D72).
func (s *state) readClass() {
	if s.def == nil {
		return
	}
	s.ev.ReadClass = ReadClass(s.def, s.ev.Obligations, s.classification)
}

// Reason codes and level of the data-flow hold (G0 M16 D76).
const (
	// ReasonDataFlowHold: an external disclosure follows a pii or secret
	// read in the run tree, and no flow of the grant covers it (HR-431).
	ReasonDataFlowHold = "DATA_FLOW_HOLD"
	// ReasonDataFlowAllowed: a flow of the grant covers the disclosure.
	ReasonDataFlowAllowed = "DATA_FLOW_ALLOWED"
	// DataFlowLevel is the source of the hold's requirement.
	DataFlowLevel = "data_flow"
	// EffectExternalDisclosure is the consequence effect that makes a
	// write an external disclosure (D74).
	EffectExternalDisclosure = "external_disclosure"
)

// externalDisclosure reports whether the action is an external disclosure
// (D74): a write whose connection's destination class is public, or whose
// predicted consequences include an external_disclosure effect. Reads
// never count.
func (s *state) externalDisclosure() bool {
	if s.def == nil || s.def.Access != defs.AccessWrite {
		return false
	}
	if s.conn != nil && s.conn.DestinationClass == "public" {
		return true
	}
	return slices.ContainsFunc(s.ev.Consequences, func(c consequences.Consequence) bool {
		return c.State == consequences.Predicted && c.Err == nil && c.Effect == EffectExternalDisclosure
	})
}

// dataFlow holds an external disclosure after a pii or secret read anywhere
// in the run tree unless one of the grant's flows covers every class read
// and every destination of the action (G0 M16 D73–D76, HR-431). The detail
// names the classes and the read transactions, never content (HR-434).
// Approval binds the action as any requirement does; in monitor mode the
// evaluation records the would-hold (Would, HR-433).
func (p *Pipeline) dataFlow(ctx context.Context, s *state) {
	if !s.externalDisclosure() {
		return
	}
	reads, err := p.Reader.SensitiveReads(ctx, s.req.Org, s.ev.RunID)
	if err != nil {
		s.missing(StepBoundaries, err, "the run's read history")
		return
	}
	var classes, txns []string
	for _, r := range reads {
		if r.Class != "pii" && r.Class != "secret" {
			continue
		}
		if !slices.Contains(classes, r.Class) {
			classes = append(classes, r.Class)
		}
		txns = append(txns, r.TransactionID.String())
	}
	if len(classes) == 0 {
		return
	}
	slices.Sort(classes)
	leaf, _ := s.chain.Leaf()
	what := "the run tree read " + strings.Join(classes, " and ") + " data (transactions " + strings.Join(txns, ", ") + ")"
	if gdomain.FlowCovers(leaf.Flows, classes, s.a.Destinations) {
		s.cl.add(StepBoundaries, adomain.Allow, ReasonDataFlowAllowed, what+"; a flow of grant "+leaf.ID.String()+" allows it here", "")
		return
	}
	a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
	s.ev.Approvals = append(s.ev.Approvals, a)
	s.cl.add(StepRequirements, adomain.RequireApproval, ReasonDataFlowHold,
		what+" and this action discloses data outside: approval by "+a.Role+" is required", DataFlowLevel)
	s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: DataFlowLevel, Reason: ReasonDataFlowHold}))
}

// Would is what an enforce-mode route would have decided about a
// monitor-mode permit (HR-184), generalising WouldUnknown (G0 M16 D76,
// HR-433): the unknown consequence's answer when there is one, otherwise
// "HOLD: DATA_FLOW_HOLD" (or the stricter decision the same reasons give)
// when the data-flow hold applies. ok is false when neither applies.
func (e *Evaluation) Would() (string, bool) {
	if would, _, ok := e.WouldUnknown(); ok {
		return would, true
	}
	if !e.MonitorPermit() || !slices.ContainsFunc(e.Checklist, func(it Item) bool { return it.Code == ReasonDataFlowHold }) {
		return "", false
	}
	would := "HOLD"
	if e.Decision == adomain.Deny || e.Decision == adomain.CannotAuthorize {
		would = string(e.Decision)
	}
	return would + ": " + ReasonDataFlowHold, true
}
