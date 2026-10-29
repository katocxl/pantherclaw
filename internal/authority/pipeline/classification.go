// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
)

// ReasonClassificationStale notes a pc.classification fact older than
// ClassificationMaxAge, which is ignored.
const ReasonClassificationStale = "CLASSIFICATION_STALE"

// ClassificationMaxAge is how old a classification may be and still raise
// a read's class: the longest lag any fact may declare.
const ClassificationMaxAge = fdomain.MaxLagCeiling

// classify reads the pc.classification fact about a read's target (step 6,
// G0 M16 D80, HR-435). It is optional: a missing fact has no effect and a
// stale one is ignored with a note. Its class only raises the read class
// (ReadClass, S16a's D72), never lowers it, and never allows anything; a
// policy that names the fact sees it as facts.pc_classification through
// the ordinary fact requirements.
func (p *Pipeline) classify(ctx context.Context, s *state) bool {
	if !p.at(5) || s.def == nil || s.def.Access != defs.AccessRead {
		return true
	}
	got, err := p.Reader.Facts(ctx, s.req.Org, s.connID(), s.a.Target.Type, s.a.Target.ID, []string{fdomain.NameClassification})
	if err != nil {
		s.missing(StepFacts, err, "the classification")
		return false
	}
	f, ok := got[fdomain.NameClassification]
	switch {
	case !ok || f.Class() == "":
		return true
	case s.cont.Now.Sub(f.ObservedAt) > ClassificationMaxAge:
		s.cl.note(StepFacts, StatusNotApplicable, ReasonClassificationStale,
			fdomain.NameClassification+" is older than "+ClassificationMaxAge.String()+" and is ignored")
		return true
	}
	s.classification = f.Class()
	s.used = append(s.used, f)
	return true
}
