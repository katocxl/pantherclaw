// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Resumer resumes an automation a pause_launches step paused (core,
// revalidated like ResumeAutomation). It resumes only an automation
// still PAUSED for reason and reports false, with nothing changed, when
// it is paused for another reason or not paused.
type Resumer interface {
	ResumePaused(ctx context.Context, tx pgx.Tx, org ids.OrgID, automation ids.UUID, reason autodomain.PauseReason) (bool, error)
}

// Output keys of the launch kinds.
const (
	OutPaused  = "paused"
	OutResumed = "resumed"
	OutSkipped = "skipped"
)

// MaxPauseList bounds a LIST selector.
const MaxPauseList = 50

// pauseLaunches pauses the automations whose launches are affected by the
// trigger (its agent) or a declared list, for COVERAGE_RECOVERY (D31). It
// never pauses its own automation. The paused automations are its refs,
// which resume_launches reads.
type pauseLaunches struct{ d Deps }

func (*pauseLaunches) Kind() string { return autodomain.KindPauseLaunches }

func (s *pauseLaunches) selector(sc autodomain.StepContext) (autodomain.PauseSelector, string) {
	w, ok := sc.With.(*autodomain.PauseLaunchesWith)
	if !ok {
		return autodomain.PauseSelector{}, ReasonBadWith
	}
	var sel autodomain.PauseSelector
	switch w.Selector {
	case autodomain.SelectAffected:
		if len(w.Automations) > 0 {
			return sel, ReasonBadWith
		}
		agent, ok := triggerSubject(sc, reflexdomain.SubjectAgent)
		if !ok {
			return sel, ReasonNoSubject
		}
		sel.AffectingAgent = &agent
	case autodomain.SelectList:
		if len(w.Automations) == 0 || len(w.Automations) > MaxPauseList {
			return sel, ReasonBadWith
		}
		for _, a := range w.Automations {
			if a.UUID() != sc.Execution.Automation && !slices.Contains(sel.Automations, a.UUID()) {
				sel.Automations = append(sel.Automations, a.UUID())
			}
		}
		if len(sel.Automations) == 0 {
			return sel, ReasonBadWith
		}
	default:
		return sel, ReasonBadWith
	}
	if !inScope(sc.Def, autodomain.KindPauseLaunches, w.Selector) {
		return sel, ReasonOutsideScope
	}
	return sel, ""
}

func (s *pauseLaunches) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	sel, reason := s.selector(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Pauser == nil {
		return unwired()
	}
	paused, err := s.d.Pauser.Pause(ctx, tx, sc.Org, sel, autodomain.PauseCoverageRecovery)
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	refs := make([]reflexdomain.EvidenceRef, 0, len(paused))
	for _, a := range paused {
		if a != sc.Execution.Automation {
			refs = append(refs, ref(RefAutomation, a))
		}
	}
	effect := autodomain.EffectUnchanged
	if len(refs) > 0 {
		effect = autodomain.EffectChanged
	}
	// The automation itself as evidence, so the step has a ref even when
	// nothing needed pausing.
	refs = append(refs, ref(RefAutomationSelf, sc.Execution.Automation))
	return autodomain.StepResult{
		State: autodomain.StepDone, Effect: effect, Refs: refs,
		Output: map[string]string{OutPaused: strconv.Itoa(len(refs) - 1)},
	}, nil
}

func (s *pauseLaunches) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *pauseLaunches) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	sel, reason := s.selector(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	out := map[string]string{"selector": "LIST", "listed": strconv.Itoa(len(sel.Automations))}
	if sel.AffectingAgent != nil {
		out = map[string]string{"selector": "AFFECTED", "agent": sel.AffectingAgent.String()}
	}
	return shadowed(out)
}

// RefAutomationSelf marks the pausing automation in pause_launches' refs;
// resume_launches never resumes it.
const RefAutomationSelf = "automation_self"

// resumeLaunches resumes exactly what a pause_launches step of this
// execution paused (D31): each automation still paused for
// COVERAGE_RECOVERY, revalidated by core; one paused for another reason
// meanwhile stays paused and is counted as skipped.
type resumeLaunches struct{ d Deps }

func (*resumeLaunches) Kind() string { return autodomain.KindResumeLaunches }

func (s *resumeLaunches) check(sc autodomain.StepContext) (string, string) {
	w, ok := sc.With.(*autodomain.ResumeLaunchesWith)
	if !ok || w.Step == "" {
		return "", ReasonBadWith
	}
	if !slices.ContainsFunc(sc.Def.Do, func(st autodomain.StepSpec) bool {
		return st.ID == w.Step && st.Step == autodomain.KindPauseLaunches
	}) {
		return "", ReasonBadWith
	}
	// resume_launches has no scope of its own: it follows its
	// pause_launches step's (D3 AFFECTED, LIST).
	if !inScope(sc.Def, autodomain.KindResumeLaunches, autodomain.ScopeAffected) &&
		!inScope(sc.Def, autodomain.KindResumeLaunches, autodomain.ScopeList) {
		return "", ReasonOutsideScope
	}
	return w.Step, ""
}

func (s *resumeLaunches) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	step, reason := s.check(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Resumer == nil {
		return unwired()
	}
	paused, err := pausedBy(ctx, tx, sc, step)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	var resumed, skipped int
	refs := make([]reflexdomain.EvidenceRef, 0, len(paused)+1)
	for _, a := range paused {
		ok, err := s.d.Resumer.ResumePaused(ctx, tx, sc.Org, a, autodomain.PauseCoverageRecovery)
		if err != nil {
			if _, refused := refusal(err); !refused {
				return autodomain.StepResult{}, err
			}
			ok = false
		}
		if ok {
			resumed++
			refs = append(refs, ref(RefAutomation, a))
		} else {
			skipped++
		}
	}
	effect := autodomain.EffectUnchanged
	if resumed > 0 {
		effect = autodomain.EffectChanged
	}
	refs = append(refs, ref(RefAutomationSelf, sc.Execution.Automation))
	return autodomain.StepResult{
		State: autodomain.StepDone, Effect: effect, Refs: refs,
		Output: map[string]string{OutResumed: strconv.Itoa(resumed), OutSkipped: strconv.Itoa(skipped)},
	}, nil
}

// pausedBy returns the automations a pause_launches step of the execution
// paused, from its DONE attempt's refs.
func pausedBy(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, step string) ([]ids.UUID, error) {
	raw, err := dbq.New(tx).AutomationStepDoneRefs(ctx, sc.Org, sc.Execution.ID, step)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var refs []reflexdomain.EvidenceRef
	if err := json.Unmarshal(raw, &refs); err != nil {
		return nil, err
	}
	var out []ids.UUID
	for _, r := range refs {
		if r.Kind == RefAutomation && r.ID != sc.Execution.Automation && !slices.Contains(out, r.ID) {
			out = append(out, r.ID)
		}
	}
	return out, nil
}

func (s *resumeLaunches) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *resumeLaunches) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	step, reason := s.check(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"from": step})
}
