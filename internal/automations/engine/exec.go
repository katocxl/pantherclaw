// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package engine runs governed-automation executions (G0 M11 part 2 D24,
// D27): one accepted trigger worked through a version's steps by the
// closed step catalog, with retries only for retry-safe kinds, the
// declared failure behaviour and compensation, and a final state that
// claims success only on evidence (HR-280, HR-282).
//
// The Machine is the single implementation of the execution rules. The
// database driver (adapters/pgengine) loads an execution, lets the Machine
// advance it and stores the result in one transaction; Simulate runs the
// same Machine in memory over stubbed step results (assurance's scenario
// tests, D34).
package engine

import (
	"slices"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Execution reasons beyond D24's that the engine records, stable codes.
const (
	// ReasonFinishNotMet: every step ran (or was skipped) but a finish
	// condition holds no evidence.
	ReasonFinishNotMet = "FINISH_NOT_MET"
	// ReasonEffectUnknown: an irreversible operation's outcome is unknown
	// (HR-280); the execution waits for reconciliation.
	ReasonEffectUnknown = "EFFECT_UNKNOWN"
	// ReasonTimeout: a waiting step reached its timeout.
	ReasonTimeout = "TIMEOUT"
	// ReasonTemplate: a `with` could not be rendered from the trigger's
	// parameters and earlier outputs (HR-276).
	ReasonTemplate = "TEMPLATE_INVALID"
	// ReasonGuard: a step's `when` guard could not be evaluated (fail
	// closed).
	ReasonGuard = "GUARD_INVALID"
	// ReasonUnsupported: the step kind has no runtime here (HR-279).
	ReasonUnsupported = "UNSUPPORTED_CAPABILITY"
	// ReasonOutputInvalid: a step returned an output beyond its bounds.
	ReasonOutputInvalid = "OUTPUT_INVALID"
)

// OutputIrreversible is the output key a step sets to "true" when its
// UNKNOWN outcome concerns an irreversible operation (wait_effect):
// the execution stops in NEEDS_RECONCILIATION and never retries (HR-280).
const OutputIrreversible = "irreversible"

// OutputRunBound is the output key launch_run sets to "true" once its run
// bound an instance: from then on it never retries (HR-280).
const OutputRunBound = "run_bound"

// OutputAttempt is the key under which a starting step finds its own
// attempt id (StepContext.Outputs[its id]), for rows that name the attempt
// (a launch).
const OutputAttempt = "attempt_id"

// Exec is one execution as the Machine works it.
type Exec struct {
	ID         ids.UUID
	Org        ids.OrgID
	Automation ids.UUID
	Version    ids.UUID
	Mode       autodomain.Mode
	Def        *autodomain.Definition
	// View is what steps see of the execution.
	View autodomain.ExecutionView

	State        autodomain.ExecutionState
	Reason       string
	Current      int
	Compensating bool
	StartedAt    time.Time
	DeadlineAt   time.Time
	WakeAt       time.Time
	// CancelReason is set by CancelExecution or the kill switch; the
	// Machine honours it at the next boundary (HR-283).
	CancelReason string
	Transitions  int

	Attempts []*Attempt
	Result   *Result
}

// Attempt is one step attempt (D24).
type Attempt struct {
	ID           ids.UUID
	Index        int
	StepID       string
	Number       int
	Kind         string
	Compensation bool
	State        autodomain.StepState
	Refused      bool
	Reason       string
	Output       map[string]string
	Refs         []reflexdomain.EvidenceRef
	Effect       autodomain.Effect
	StartedAt    time.Time
	EndedAt      time.Time
	WakeAt       time.Time
	// New and Dirty tell the store what to write.
	New, Dirty bool
}

// Terminal reports whether the attempt has ended.
func (a *Attempt) Terminal() bool {
	return a.State != autodomain.StepRunning && a.State != autodomain.StepWaiting
}

// Result is an execution's final account (D27, HR-282): what each step
// changed, the finish conditions and their evidence, and the work left.
type Result struct {
	State     autodomain.ExecutionState `json:"state"`
	Reason    string                    `json:"reason,omitzero"`
	Changed   []string                  `json:"changed"`
	Unchanged []string                  `json:"unchanged"`
	Unknown   []string                  `json:"unknown"`
	Finish    []FinishStatus            `json:"finish"`
	// Compensated lists compensation steps that ran; they are never an
	// undo (F727).
	Compensated []string                   `json:"compensated,omitzero"`
	Unresolved  []Unresolved               `json:"unresolved"`
	Cleanup     []reflexdomain.EvidenceRef `json:"cleanup,omitzero"`
}

// FinishStatus is one finish_when entry and whether evidence meets it.
type FinishStatus struct {
	Step      string                     `json:"step"`
	Condition autodomain.FinishCondition `json:"condition"`
	Met       bool                       `json:"met"`
	Refs      []reflexdomain.EvidenceRef `json:"refs,omitzero"`
}

// Unresolved is work an execution leaves open: an unknown outcome, a
// pending gate, a reconciliation.
type Unresolved struct {
	Step   string `json:"step"`
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitzero"`
}

// latest returns the last attempt of the step at index (compensation or
// not), or nil.
func (x *Exec) latest(index int, compensation bool) *Attempt {
	var out *Attempt
	for _, a := range x.Attempts {
		if a.Index == index && a.Compensation == compensation && (out == nil || a.Number > out.Number) {
			out = a
		}
	}
	return out
}

// Latest returns the last attempt of every step that ran, in order (main
// steps first, then compensation).
func (x *Exec) Latest() []*Attempt {
	var out []*Attempt
	for _, comp := range []bool{false, true} {
		n := len(x.steps(comp))
		for i := range n {
			if a := x.latest(i, comp); a != nil {
				out = append(out, a)
			}
		}
	}
	return out
}

// steps returns the main steps or the compensation steps.
func (x *Exec) steps(compensation bool) []autodomain.StepSpec {
	if !compensation {
		return x.Def.Do
	}
	if x.Def.IfFails == nil {
		return nil
	}
	return x.Def.IfFails.Compensate
}

// outputs are the latest terminal outputs of the main steps by id.
func (x *Exec) outputs() map[string]map[string]string {
	out := map[string]map[string]string{}
	for i := range x.Def.Do {
		if a := x.latest(i, false); a != nil && a.Terminal() {
			out[a.StepID] = a.Output
		}
	}
	return out
}

// Active reports whether the execution has not ended.
func (x *Exec) Active() bool { return x.State.Active() }

func cloneRefs(r []reflexdomain.EvidenceRef) []reflexdomain.EvidenceRef { return slices.Clone(r) }
