// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package templates

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"time"

	"go.yaml.in/yaml/v3"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Baseline test kinds (D34). HR-287 requires NORMAL, DENIED, TIMEOUT and
// DUPLICATE, plus PARTIAL or UNKNOWN when the ceiling has an irreversible
// operation.
const (
	TestNormal    = "NORMAL"
	TestDenied    = "DENIED"
	TestTimeout   = "TIMEOUT"
	TestDuplicate = "DUPLICATE"
	TestPartial   = "PARTIAL"
	TestUnknown   = "UNKNOWN"
	TestCustom    = "CUSTOM"
)

var testKinds = []string{TestNormal, TestDenied, TestTimeout, TestDuplicate, TestPartial, TestUnknown, TestCustom}

// TestCase is one baseline scenario of a rendered definition (D34): a
// trigger, the would-be results of its steps, and the expected outcome.
// A DUPLICATE case submits its trigger twice and expects one execution:
// both submissions share the trigger's dedupe key, and the one execution
// ends as Expect says.
type TestCase struct {
	Name    string                             `json:"name"`
	Kind    string                             `json:"kind"`
	Trigger TestTrigger                        `json:"trigger"`
	Stubs   map[string][]autodomain.StepResult `json:"stubs,omitzero"`
	Expect  Expect                             `json:"expect"`
}

// TestTrigger is the scenario's trigger, as accepted (D11).
type TestTrigger struct {
	Kind     autodomain.TriggerKind      `json:"kind"`
	Params   map[string]autodomain.Value `json:"params,omitzero"`
	Subjects []reflexdomain.Subject      `json:"subjects,omitzero"`
	Evidence []reflexdomain.EvidenceRef  `json:"evidence,omitzero"`
}

// Ref returns the trigger as the engine receives it for automation and
// version.
func (t TestTrigger) Ref(org ids.OrgID, automation, version ids.UUID, at time.Time) autodomain.TriggerRef {
	id := ids.NewV7()
	return autodomain.TriggerRef{
		ID: id, Org: org, Automation: automation, Version: version, Kind: t.Kind, Mode: autodomain.ModeTest,
		Params: t.Params, Subjects: slices.Clone(t.Subjects), Evidence: slices.Clone(t.Evidence), Root: id, OccurredAt: at,
	}
}

// Expect is a scenario's expected outcome: the execution's final state and
// reason, and the final state of the named steps.
type Expect struct {
	State  autodomain.ExecutionState       `json:"state"`
	Reason string                          `json:"reason,omitzero"`
	Steps  map[string]autodomain.StepState `json:"steps,omitzero"`
}

// testSpec is a baseline test as authored in a template.
type testSpec struct {
	Name    string `yaml:"name"`
	Kind    string `yaml:"kind"`
	Trigger struct {
		Params   map[string]string `yaml:"params"`
		Subjects []struct {
			Type string `yaml:"type"`
			ID   string `yaml:"id"`
		} `yaml:"subjects"`
	} `yaml:"trigger"`
	Stubs  map[string][]stubSpec `yaml:"stubs"`
	Expect struct {
		State  string            `yaml:"state"`
		Reason string            `yaml:"reason"`
		Steps  map[string]string `yaml:"steps"`
	} `yaml:"expect"`
}

// stubSpec is one would-be step result; refs are evidence kinds, given
// stable ids.
type stubSpec struct {
	State  string            `yaml:"state"`
	Effect string            `yaml:"effect"`
	Reason string            `yaml:"reason"`
	Output map[string]string `yaml:"output"`
	Refs   []string          `yaml:"refs"`
}

var (
	stepStates = []autodomain.StepState{
		autodomain.StepRunning, autodomain.StepWaiting, autodomain.StepDone, autodomain.StepFailed, autodomain.StepSkipped,
		autodomain.StepUnknown, autodomain.StepShadowed, autodomain.StepCompensation,
	}
	effects    = []autodomain.Effect{autodomain.EffectChanged, autodomain.EffectUnchanged, autodomain.EffectUnknown, autodomain.EffectNone}
	execStates = []autodomain.ExecutionState{
		autodomain.ExecSucceeded, autodomain.ExecPartiallyCompleted, autodomain.ExecFailed, autodomain.ExecCancelled,
		autodomain.ExecNeedsReconciliation,
	}
	refKind = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)
)

// buildTests decodes the rendered tests and binds them to def: trigger
// parameters are converted by the trigger's declarations, and every step
// named exists.
func buildTests(template string, def *autodomain.Definition, raw []byte) ([]TestCase, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var specs []testSpec
	if err := dec.Decode(&specs); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("tests: %w", err)
	}
	steps := map[string]bool{}
	for _, s := range def.Do {
		steps[s.ID] = true
	}
	if def.IfFails != nil {
		for _, s := range def.IfFails.Compensate {
			steps[s.ID] = true
		}
	}
	declared := def.When.Params()
	out := make([]TestCase, 0, len(specs))
	names := map[string]bool{}
	for _, s := range specs {
		at := func(format string, args ...any) error {
			return fmt.Errorf("test %q: "+format, append([]any{s.Name}, args...)...)
		}
		if s.Name == "" || names[s.Name] {
			return nil, at("a test has a unique name")
		}
		names[s.Name] = true
		if !slices.Contains(testKinds, s.Kind) {
			return nil, at("unknown kind %q", s.Kind)
		}
		tc := TestCase{Name: s.Name, Kind: s.Kind, Trigger: TestTrigger{Kind: def.When.Kind()}}
		for name, rawv := range s.Trigger.Params {
			p, ok := declared[name]
			if !ok {
				return nil, at("trigger parameter %q is not declared", name)
			}
			v, err := p.Convert(name, rawv)
			if err != nil {
				return nil, at("%v", err)
			}
			if tc.Trigger.Params == nil {
				tc.Trigger.Params = map[string]autodomain.Value{}
			}
			tc.Trigger.Params[name] = v
		}
		for _, sub := range s.Trigger.Subjects {
			x := reflexdomain.Subject{Type: reflexdomain.SubjectType(sub.Type), ID: sub.ID}
			if !x.Valid() {
				return nil, at("subject %s:%s is not valid", sub.Type, sub.ID)
			}
			tc.Trigger.Subjects = append(tc.Trigger.Subjects, x)
		}
		if tc.Trigger.Kind != autodomain.TriggerSchedule {
			tc.Trigger.Evidence = []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceLedger, ID: stableID(template, s.Name, "trigger")}}
		}
		for step, rs := range s.Stubs {
			if !steps[step] {
				return nil, at("stub for unknown step %q", step)
			}
			for i, r := range rs {
				res, err := r.result(template, s.Name, step, i)
				if err != nil {
					return nil, at("%s[%d]: %v", step, i, err)
				}
				if tc.Stubs == nil {
					tc.Stubs = map[string][]autodomain.StepResult{}
				}
				tc.Stubs[step] = append(tc.Stubs[step], res)
			}
		}
		tc.Expect.State = autodomain.ExecutionState(s.Expect.State)
		tc.Expect.Reason = s.Expect.Reason
		if !slices.Contains(execStates, tc.Expect.State) {
			return nil, at("expected state %q is not a final state", s.Expect.State)
		}
		for step, st := range s.Expect.Steps {
			if !steps[step] || !slices.Contains(stepStates, autodomain.StepState(st)) {
				return nil, at("expected step %s=%s is not a step and step state", step, st)
			}
			if tc.Expect.Steps == nil {
				tc.Expect.Steps = map[string]autodomain.StepState{}
			}
			tc.Expect.Steps[step] = autodomain.StepState(st)
		}
		out = append(out, tc)
	}
	return out, nil
}

func (r stubSpec) result(template, test, step string, i int) (autodomain.StepResult, error) {
	res := autodomain.StepResult{
		State: autodomain.StepState(r.State), Effect: autodomain.Effect(r.Effect), Reason: r.Reason, Output: r.Output,
	}
	if !slices.Contains(stepStates, res.State) {
		return res, fmt.Errorf("unknown state %q", r.State)
	}
	if r.Effect != "" && !slices.Contains(effects, res.Effect) {
		return res, fmt.Errorf("unknown effect %q", r.Effect)
	}
	if !res.Valid() {
		return res, errors.New("output beyond its bounds")
	}
	for j, k := range r.Refs {
		if !refKind.MatchString(k) {
			return res, fmt.Errorf("ref kind %q", k)
		}
		res.Refs = append(res.Refs, reflexdomain.EvidenceRef{Kind: k, ID: stableID(template, test, step, strconv.Itoa(i), strconv.Itoa(j))})
	}
	return res, nil
}

// stableID derives a version-8 UUID from parts, so a template's baseline
// tests are the same on every render.
func stableID(parts ...string) ids.UUID {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	var u ids.UUID
	copy(u[:], h.Sum(nil))
	u[6] = u[6]&0x0f | 0x80
	u[8] = u[8]&0x3f | 0x80
	return u
}
