// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"slices"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	csdomain "github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Content signals (G0 M27 D507, D512; HR-648, HR-650). Decisions run before
// results exist, so a result's flag lands on the run as the pc.content.flag
// fact and later decisions read it here. A flag only restricts:
//
//   - in ACTIVE, a flag on the run tree holds a later write, and reads pass;
//   - in ACTIVE, a flag on this action's outbound payload holds it now;
//   - a scan that could not finish is a flag like any other (HR-650);
//   - in ACTIVE, an org's own rule may deny on `run.content_flags`;
//   - in WATCHING a would-hold is a note and no decision changes.
//
// Nothing here allows anything, lowers a decision or removes a requirement,
// and no reader of this state can: it only ever calls cl.add with a hold.
// Detail names kinds and locations, never a value, and is for people only
// (HR-400, HR-649).

// Reason codes and level of a content hold.
const (
	// ReasonContentFlagHold: a content flag holds the action for a person.
	ReasonContentFlagHold = "CONTENT_FLAG_HOLD"
	// ReasonContentFlagWatching notes what ACTIVE would have held.
	ReasonContentFlagWatching = "CONTENT_FLAG_WATCHING"
	// ContentLevel is the source of the hold's requirement.
	ContentLevel = "content_signal"
)

// contentSignals reads the org's mode and the run tree's flags (step 6).
func (p *Pipeline) contentSignals(ctx context.Context, s *state) bool {
	if !p.at(7) { // earlier recordings neither read nor held
		return true
	}
	st, err := p.Reader.ContentSignals(ctx, s.req.Org, s.ev.RunID)
	if err != nil {
		s.missing(StepFacts, err, "the content signals")
		return false
	}
	if !s.ownRun() {
		st.Kinds = nil // a flag is the agent's own run's
	}
	s.content = st
	found := make([]PayloadFinding, 0, len(s.req.ContentFindings)+1)
	for _, f := range s.req.ContentFindings {
		c := csdomain.Closed(csdomain.Finding{Kind: f.Kind, Location: f.Location}) // D533
		found = append(found, PayloadFinding{Kind: c.Kind, Location: c.Location})
	}
	// A gateway-carried call without the gateway's word that it scanned is
	// not known to have no flags: a gateway from before M27, or one whose
	// configuration is stale, fails closed (D533). The declared unscanned
	// faces need no word; the Authority decides which they are.
	if csdomain.Mode(st.Mode).Scans() && s.req.ContentScan != csdomain.ScanScanned && !s.declaredUnscanned() {
		found = append(found, PayloadFinding{Kind: csdomain.Unscanned.Kind, Location: csdomain.Unscanned.Location})
	}
	s.ev.ContentFindings = payloadFindings(found)
	return true
}

// declaredUnscanned reports whether the call comes through a face content
// signals declare unscanned (D504, D532).
func (s *state) declaredUnscanned() bool {
	kind := ""
	if s.conn != nil {
		kind = s.conn.Kind
	}
	return csdomain.DeclaredUnscanned(s.a.Channel, kind)
}

// runContentFlags are the flags policy sees as `run.content_flags`: the run
// tree's and this action's, in ACTIVE only, so WATCHING changes no decision.
func (s *state) runContentFlags() []string {
	if s.content.Mode != string(csdomain.ModeActive) {
		return nil
	}
	out := slices.Clone(s.content.Kinds)
	for _, f := range s.ev.ContentFindings {
		out = append(out, f.Kind)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// contentHold files the hold content flags call for (step 7, after the
// data-flow hold). It only adds a requirement.
func (s *state) contentHold() {
	var why []string
	if len(s.ev.ContentFindings) > 0 {
		var what []string
		for _, f := range s.ev.ContentFindings {
			what = append(what, f.Kind+" at "+f.Location)
		}
		why = append(why, "the outbound payload carries content flags ("+strings.Join(what, ", ")+")")
	}
	// Reads pass (D512): a later read is held only by its own payload.
	if len(s.content.Kinds) > 0 && (s.def == nil || s.def.Access != defs.AccessRead) {
		why = append(why, "the run tree carries content flags ("+strings.Join(s.content.Kinds, ", ")+")")
	}
	if len(why) == 0 {
		return
	}
	detail := strings.Join(why, " and ") + "; flags are inference, not proof"
	switch s.content.Mode {
	case string(csdomain.ModeActive):
		a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
		s.ev.Approvals = append(s.ev.Approvals, a)
		s.cl.add(StepRequirements, adomain.RequireApproval, ReasonContentFlagHold, "approval by "+a.Role+" is required: "+detail, ContentLevel)
		s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: ContentLevel, Reason: ReasonContentFlagHold}))
	case string(csdomain.ModeWatching):
		s.cl.note(StepRequirements, StatusNotApplicable, ReasonContentFlagWatching, "ACTIVE would hold this action: "+detail)
	}
}
