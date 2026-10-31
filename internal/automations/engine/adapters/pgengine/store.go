// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgengine is the PostgreSQL side of the automation engine (G0 M11
// part 2 D24–D28): starting executions for accepted triggers, the River
// driver that advances them in tenant transactions, the wake sweep, and the
// hooks that revalidate authority and clean up (HR-273, HR-283).
package pgengine

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"sync"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// definitions caches parsed version definitions; a version's definition
// never changes once it can run (D5).
type definitions struct {
	mu sync.Mutex
	m  map[ids.UUID]*autodomain.Definition
}

const maxCachedDefinitions = 512

func (d *definitions) get(ctx context.Context, q *dbq.Queries, org ids.OrgID, version ids.UUID) (*autodomain.Definition, error) {
	v, err := q.GetAutomationVersion(ctx, org, version)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	def, ok := d.m[version]
	d.mu.Unlock()
	if ok {
		return def, nil
	}
	def, err = autodomain.Parse(v.Definition)
	if err != nil {
		return nil, fmt.Errorf("pgengine: version %s: %w", version, err)
	}
	d.mu.Lock()
	if d.m == nil || len(d.m) >= maxCachedDefinitions {
		d.m = map[ids.UUID]*autodomain.Definition{}
	}
	d.m[version] = def
	d.mu.Unlock()
	return def, nil
}

// load reads an execution FOR UPDATE with its definition and attempts.
func (e *Engine) load(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (*engine.Exec, error) {
	row, err := q.LockAutomationExecution(ctx, org, id)
	if err != nil {
		return nil, err
	}
	return e.build(ctx, q, row)
}

// build maps a stored execution to the Machine's model.
func (e *Engine) build(ctx context.Context, q *dbq.Queries, row dbq.PcAutomationExecution) (*engine.Exec, error) {
	org := row.OrgID
	def, err := e.defs.get(ctx, q, org, row.VersionID)
	if err != nil {
		return nil, err
	}
	a, err := q.GetAutomation(ctx, org, row.AutomationID)
	if err != nil {
		return nil, err
	}
	params, err := decodeParams(row.Params)
	if err != nil {
		return nil, err
	}
	subjects, err := decodeSubjects(row.Subjects)
	if err != nil {
		return nil, err
	}
	evidence, err := DecodeRefs(row.Evidence)
	if err != nil {
		return nil, err
	}
	x := &engine.Exec{
		ID: row.ID, Org: org, Automation: row.AutomationID, Version: row.VersionID, Mode: autodomain.Mode(row.Mode),
		Def: def, State: autodomain.ExecutionState(row.State), Current: int(row.CurrentStep),
		Compensating: row.Compensating, DeadlineAt: row.DeadlineAt, Transitions: int(row.Transitions), Path: row.Path,
	}
	if row.CurrentNode != nil {
		x.CurrentNode = *row.CurrentNode
	}
	if row.Reason != nil {
		x.Reason = *row.Reason
	}
	if row.StartedAt != nil {
		x.StartedAt = *row.StartedAt
	}
	if row.WakeAt != nil {
		x.WakeAt = *row.WakeAt
	}
	if row.CancelReason != nil {
		x.CancelReason = *row.CancelReason
	}
	x.View = autodomain.ExecutionView{
		ID: row.ID, Automation: row.AutomationID, AutomationName: a.Name, Version: row.VersionID, Mode: x.Mode,
		ServiceAccount: row.ServiceAccountID, Owner: a.OwnerUserID, StartedAt: x.StartedAt, DeadlineAt: row.DeadlineAt,
		Trigger: autodomain.TriggerRef{
			ID: row.TriggerID, Org: org, Automation: row.AutomationID, Version: row.VersionID,
			Kind: autodomain.TriggerKind(row.TriggerKind), Mode: x.Mode, Params: params, Subjects: subjects,
			Evidence: evidence, Root: row.RootTriggerID, Ancestry: row.Ancestry, Depth: int(row.Depth),
			OccurredAt: row.OccurredAt,
		},
	}
	switch {
	case row.PrincipalUserID != nil:
		x.View.Principal = gdomain.Principal{Kind: gdomain.PrincipalUser, ID: *row.PrincipalUserID}
	case row.PrincipalSaID != nil:
		x.View.Principal = gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: *row.PrincipalSaID}
	}
	if row.CeilingID != nil {
		x.View.Ceiling = *row.CeilingID
		c, err := q.GetAutomationCeiling(ctx, org, *row.CeilingID)
		if err != nil {
			return nil, err
		}
		x.View.Confirmers = c.ApprovedBy
	}
	if row.Result != nil {
		r, err := decodeResult(row.Result)
		if err != nil {
			return nil, err
		}
		x.Result = &r
	}
	attempts, err := q.ListAutomationStepAttempts(ctx, org, row.ID)
	if err != nil {
		return nil, err
	}
	for _, s := range attempts {
		at, err := attemptOf(s)
		if err != nil {
			return nil, err
		}
		x.Attempts = append(x.Attempts, at)
	}
	return x, nil
}

func attemptOf(s dbq.PcAutomationStepAttempt) (*engine.Attempt, error) {
	out, err := decodeOutput(s.Output)
	if err != nil {
		return nil, err
	}
	refs, err := DecodeRefs(s.Refs)
	if err != nil {
		return nil, err
	}
	a := &engine.Attempt{
		ID: s.ID, Index: int(s.StepIndex), StepID: s.StepID, NodeID: s.StepID, Visit: int(s.Visit), Number: int(s.Attempt), Kind: s.Kind,
		Compensation: s.Compensation, State: autodomain.StepState(s.State), Refused: s.Decision == "REFUSED",
		Output: out, Refs: refs, Effect: autodomain.Effect(s.Effect), StartedAt: s.StartedAt,
	}
	if s.NodeID != nil {
		a.NodeID = *s.NodeID
	}
	if s.Reason != nil {
		a.Reason = *s.Reason
	}
	if s.EndedAt != nil {
		a.EndedAt = *s.EndedAt
	}
	if s.WakeAt != nil {
		a.WakeAt = *s.WakeAt
	}
	return a, nil
}

// save writes what the Machine changed.
func (e *Engine) save(ctx context.Context, q *dbq.Queries, x *engine.Exec) error {
	for _, a := range x.Attempts {
		if !a.New && !a.Dirty {
			continue
		}
		out, err := encodeOutput(a.Output)
		if err != nil {
			return err
		}
		refs, err := EncodeRefs(a.Refs)
		if err != nil {
			return err
		}
		decision := "ALLOWED"
		if a.Refused {
			decision = "REFUSED"
		}
		if a.New {
			err = q.InsertAutomationStepAttempt(ctx, dbq.InsertAutomationStepAttemptParams{
				OrgID: x.Org, ID: a.ID, ExecutionID: x.ID, StepIndex: int16(a.Index), StepID: a.StepID, NodeID: &a.NodeID, //nolint:gosec // ≤ 40
				Attempt: int16(a.Number), Kind: a.Kind, Compensation: a.Compensation, State: string(a.State), //nolint:gosec // ≤ 5
				Decision: decision, Reason: nonEmpty(a.Reason), Output: out, Refs: refs, Effect: string(effectOr(a.Effect)),
				WakeAt: timeOrNil(a.WakeAt),
			})
		} else {
			var n int64
			n, err = q.SaveAutomationStepAttempt(ctx, dbq.SaveAutomationStepAttemptParams{
				OrgID: x.Org, ID: a.ID, State: string(a.State), Decision: decision, Reason: nonEmpty(a.Reason), Output: out,
				Refs: refs, Effect: string(effectOr(a.Effect)), WakeAt: timeOrNil(a.WakeAt),
			})
			if err == nil && n != 1 {
				err = fmt.Errorf("pgengine: attempt %s changed concurrently", a.ID)
			}
		}
		if err != nil {
			return err
		}
		a.New, a.Dirty = false, false
	}
	var result []byte
	if x.Result != nil {
		b, err := encodeResult(*x.Result)
		if err != nil {
			return err
		}
		result = b
	}
	n, err := q.SaveAutomationExecution(ctx, dbq.SaveAutomationExecutionParams{
		OrgID: x.Org, ID: x.ID, State: string(x.State), Reason: nonEmpty(x.Reason), CurrentStep: int16(x.Current), //nolint:gosec // ≤ 40
		Compensating: x.Compensating, Result: result, Transitions: int32(min(x.Transitions, 1<<30)), //nolint:gosec // bounded
		StartedAt: timeOrNil(x.StartedAt), WakeAt: timeOrNil(x.WakeAt), CurrentNode: nonEmpty(x.CurrentNode), Path: pathOf(x.Path),
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("pgengine: execution %s not saved", x.ID)
	}
	return nil
}

// pathOf is never NULL: a v1 execution stores an empty path.
func pathOf(p []string) []string {
	if p == nil {
		return []string{}
	}
	return p
}

func effectOr(e autodomain.Effect) autodomain.Effect {
	if e == "" {
		return autodomain.EffectNone
	}
	return e
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// storedResult is engine.Result with text ids.
type storedResult struct {
	State       autodomain.ExecutionState `json:"state"`
	Reason      string                    `json:"reason,omitzero"`
	Changed     []string                  `json:"changed"`
	Unchanged   []string                  `json:"unchanged"`
	Unknown     []string                  `json:"unknown"`
	Finish      []storedFinish            `json:"finish"`
	Compensated []string                  `json:"compensated,omitzero"`
	Unresolved  []engine.Unresolved       `json:"unresolved"`
	Cleanup     []ref                     `json:"cleanup,omitzero"`
}

type storedFinish struct {
	Step      string                     `json:"step"`
	Condition autodomain.FinishCondition `json:"condition"`
	Met       bool                       `json:"met"`
	Refs      []ref                      `json:"refs,omitzero"`
}

func toRefs(rs []reflexdomain.EvidenceRef) []ref {
	var out []ref
	for _, r := range rs {
		out = append(out, ref{Kind: r.Kind, ID: r.ID.String()})
	}
	return out
}

func fromRefs(rs []ref) ([]reflexdomain.EvidenceRef, error) {
	var out []reflexdomain.EvidenceRef
	for _, r := range rs {
		id, err := ids.ParseUUID(r.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, reflexdomain.EvidenceRef{Kind: r.Kind, ID: id})
	}
	return out, nil
}

func encodeResult(r engine.Result) ([]byte, error) {
	s := storedResult{
		State: r.State, Reason: r.Reason, Changed: r.Changed, Unchanged: r.Unchanged, Unknown: r.Unknown,
		Compensated: r.Compensated, Unresolved: r.Unresolved, Cleanup: toRefs(r.Cleanup), Finish: []storedFinish{},
	}
	for _, f := range r.Finish {
		s.Finish = append(s.Finish, storedFinish{Step: f.Step, Condition: f.Condition, Met: f.Met, Refs: toRefs(f.Refs)})
	}
	return json.Marshal(s, json.Deterministic(true))
}

func decodeResult(b []byte) (engine.Result, error) {
	var s storedResult
	if err := json.Unmarshal(b, &s); err != nil {
		return engine.Result{}, fmt.Errorf("pgengine: result: %w", err)
	}
	r := engine.Result{
		State: s.State, Reason: s.Reason, Changed: s.Changed, Unchanged: s.Unchanged, Unknown: s.Unknown,
		Compensated: s.Compensated, Unresolved: s.Unresolved,
	}
	var err error
	if r.Cleanup, err = fromRefs(s.Cleanup); err != nil {
		return r, err
	}
	for _, f := range s.Finish {
		refs, err := fromRefs(f.Refs)
		if err != nil {
			return r, err
		}
		r.Finish = append(r.Finish, engine.FinishStatus{Step: f.Step, Condition: f.Condition, Met: f.Met, Refs: refs})
	}
	return r, nil
}

// DecodeResult reads a stored execution result (the inspector, D29).
func DecodeResult(b []byte) (engine.Result, error) { return decodeResult(b) }
