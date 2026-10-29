// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
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
