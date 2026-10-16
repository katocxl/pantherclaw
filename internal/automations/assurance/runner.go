// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"
	"fmt"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Running scenario tests (D34, HR-287, HR-288): every case runs the
// version's steps through engine.Simulate, the Machine live executions use,
// in memory with the case's stubs: nothing is issued, started, delivered or
// written, and the clock is simulated.

// defaultWait is how long a WAITING stub waits when it names no wait.
const defaultWait = 15 * time.Second

// stepResult turns a stub into the engine's result: evidence becomes a ref
// (a finish condition can be met only with evidence, HR-282).
func stepResult(s StubResult, now time.Time) autodomain.StepResult {
	r := autodomain.StepResult{
		State: autodomain.StepState(s.State), Effect: autodomain.Effect(s.Effect), Reason: s.Reason, Output: s.Output,
	}
	if r.Effect == "" {
		r.Effect = autodomain.EffectNone
	}
	if s.Evidence {
		r.Refs = []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceLedger, ID: ids.NewV7()}}
	}
	if r.State == autodomain.StepWaiting {
		w := s.Wait.D()
		if w <= 0 {
			w = defaultWait
		}
		r.WakeAt = now.Add(w)
	}
	return r
}

// triggerOf builds the case's TEST trigger: its parameters converted by the
// version's declarations (a value that does not fit refuses the trigger,
// HR-276, so the case fails with the reason).
func triggerOf(def *autodomain.Definition, org ids.OrgID, automation, version ids.UUID, c Case, now time.Time) (autodomain.TriggerRef, error) {
	t := autodomain.TriggerRef{
		ID: ids.NewV7(), Org: org, Automation: automation, Version: version, Kind: def.When.Kind(), Mode: autodomain.ModeTest,
		Params: map[string]autodomain.Value{}, OccurredAt: now,
	}
	t.Root = t.ID
	specs := def.When.Params()
	for name, raw := range c.Trigger.Params {
		spec, ok := specs[name]
		if !ok {
			return t, fmt.Errorf("parameter %s is not declared", name)
		}
		v, err := spec.Convert(name, raw)
		if err != nil {
			return t, err
		}
		t.Params[name] = v
	}
	for name, spec := range specs {
		if _, ok := t.Params[name]; !ok && spec.IsRequired() {
			return t, fmt.Errorf("parameter %s is required", name)
		}
	}
	return t, nil
}

// baseKey is the key the trigger path gives one delivery of a trigger
// (D23): a schedule occurrence's time; otherwise the delivery's own id (a
// ledger entry, a webhook-id, an idempotency key).
func baseKey(t autodomain.TriggerRef, delivery ids.UUID) string {
	switch t.Kind {
	case autodomain.TriggerSchedule:
		return triggers.ScheduleKey(t.Automation, t.OccurredAt)
	case autodomain.TriggerInbound:
		return triggers.InboundKey(t.Automation, delivery.String()) // one source stands for the version's
	case autodomain.TriggerManual:
		return triggers.ManualKey(delivery.String())
	case autodomain.TriggerEvent, autodomain.TriggerCondition, autodomain.TriggerThreshold:
	}
	return triggers.EventKey(delivery)
}

// duplicateRefused reports whether a second delivery of the same trigger
// (same parameters and occurrence, a new delivery id) would be refused as a
// duplicate: same base key, or the same declared key (HR-277).
func duplicateRefused(def *autodomain.Definition, t autodomain.TriggerRef) bool {
	second := t
	second.ID = ids.NewV7()
	if baseKey(t, t.ID) == baseKey(second, second.ID) {
		return true
	}
	k := triggers.DedupeKey(def, t)
	return k != "" && k == triggers.DedupeKey(def, second)
}

// RunCase runs one case (pure: no transaction).
func RunCase(ctx context.Context, def *autodomain.Definition, org ids.OrgID, automation, version ids.UUID, c Case,
	start time.Time,
) (CaseResult, error) {
	t, err := triggerOf(def, org, automation, version, c, start)
	if err != nil {
		// A trigger refused for its parameters is the case's outcome (HR-276).
		return Judge(c, Outcome{State: "REFUSED_INVALID", Reason: err.Error()}), nil //nolint:nilerr // the refusal is the result
	}
	stubs := engine.Stubs{}
	for id, rs := range c.Stubs {
		for _, s := range rs {
			stubs[id] = append(stubs[id], stepResult(s, start))
		}
	}
	sim, err := engine.Simulate(ctx, def, t, stubs, clock.NewFake(start))
	if err != nil {
		return CaseResult{}, err
	}
	o := Outcome{State: string(sim.State), Reason: sim.Reason, Steps: map[string]string{}, Elapsed: sim.Elapsed}
	for _, a := range sim.Attempts {
		if !a.Compensation {
			o.Steps[a.StepID] = string(a.State)
		}
	}
	if c.Kind == CaseDuplicate {
		o.DuplicateRefused = duplicateRefused(def, t)
	}
	return Judge(c, o), nil
}

// Run runs every case and lists the required kinds missing.
func Run(ctx context.Context, def *autodomain.Definition, org ids.OrgID, automation, version ids.UUID, cases []Case,
	irreversible bool, start time.Time,
) (RunResult, error) {
	out := RunResult{Missing: Missing(cases, irreversible)}
	for _, c := range cases {
		r, err := RunCase(ctx, def, org, automation, version, c, start)
		if err != nil {
			return RunResult{}, fmt.Errorf("assurance: case %s: %w", c.Name, err)
		}
		out.Cases = append(out.Cases, r)
	}
	return out, nil
}
