// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
)

// Scenario tests (D34, F738–F740, HR-287). A case submits one trigger to
// the version's steps in memory, each step answering from its stubs, and
// states the outcome it expects. A version is TESTED only when its cases
// cover the required kinds and every case passes for its current digest.

// CaseKind is what a case exercises.
type CaseKind string

// Case kinds.
const (
	CaseNormal    CaseKind = "NORMAL"
	CaseDenied    CaseKind = "DENIED"
	CaseTimeout   CaseKind = "TIMEOUT"
	CaseDuplicate CaseKind = "DUPLICATE"
	CasePartial   CaseKind = "PARTIAL"
	CaseUnknown   CaseKind = "UNKNOWN"
	CaseCustom    CaseKind = "CUSTOM"
)

// MaxCases bounds a version's cases.
const MaxCases = 50

// StubResult is one stubbed attempt result.
type StubResult struct {
	State    string            `json:"state"`
	Effect   string            `json:"effect,omitzero"`
	Reason   string            `json:"reason,omitzero"`
	Output   map[string]string `json:"output,omitzero"`
	Evidence bool              `json:"evidence,omitzero"`
	// Wait is how long a WAITING result waits (default 15 s).
	Wait autodomain.Duration `json:"wait,omitzero"`
}

// Expect is a case's expected outcome.
type Expect struct {
	State  string            `json:"state"`
	Reason string            `json:"reason,omitzero"`
	Steps  map[string]string `json:"steps,omitzero"`
}

// CaseTrigger is the trigger a case submits: its parameters as text.
type CaseTrigger struct {
	Params map[string]string `json:"params,omitzero"`
}

// Case is one scenario test.
type Case struct {
	Name    string                  `json:"name"`
	Kind    CaseKind                `json:"kind"`
	Trigger CaseTrigger             `json:"trigger"`
	Stubs   map[string][]StubResult `json:"stubs,omitzero"`
	Expect  Expect                  `json:"expect"`
}

// ErrCase reports a case that does not fit the version.
var ErrCase = fmt.Errorf("%w: test case", autodomain.ErrInvalid)

var (
	caseKinds  = []CaseKind{CaseNormal, CaseDenied, CaseTimeout, CaseDuplicate, CasePartial, CaseUnknown, CaseCustom}
	stubStates = []string{
		string(autodomain.StepRunning), string(autodomain.StepWaiting), string(autodomain.StepDone),
		string(autodomain.StepFailed), string(autodomain.StepSkipped), string(autodomain.StepUnknown),
	}
	stubEffects = []string{"", string(autodomain.EffectChanged), string(autodomain.EffectUnchanged), string(autodomain.EffectUnknown), string(autodomain.EffectNone)}
	finalStates = []string{
		string(autodomain.ExecSucceeded), string(autodomain.ExecPartiallyCompleted), string(autodomain.ExecFailed),
		string(autodomain.ExecCancelled), string(autodomain.ExecNeedsReconciliation),
	}
)

// Check validates cases against the definition: unique names, known kinds,
// stubs and expectations only on its steps, at most MaxCases.
func Check(def *autodomain.Definition, cases []Case) error {
	if len(cases) > MaxCases {
		return fmt.Errorf("%w: at most %d cases", ErrCase, MaxCases)
	}
	seen := map[string]bool{}
	for _, c := range cases {
		switch {
		case seen[c.Name]:
			return fmt.Errorf("%w: %q twice", ErrCase, c.Name)
		case !slices.Contains(caseKinds, c.Kind):
			return fmt.Errorf("%w %s: kind %q", ErrCase, c.Name, c.Kind)
		case !slices.Contains(finalStates, c.Expect.State):
			return fmt.Errorf("%w %s: expected state %q is not a final state", ErrCase, c.Name, c.Expect.State)
		}
		seen[c.Name] = true
		for id, rs := range c.Stubs {
			if def.Step(id) == nil {
				return fmt.Errorf("%w %s: no step %q", ErrCase, c.Name, id)
			}
			if len(rs) == 0 || len(rs) > 10 {
				return fmt.Errorf("%w %s: step %q has %d stubs; 1..10", ErrCase, c.Name, id, len(rs))
			}
			for _, r := range rs {
				if !slices.Contains(stubStates, r.State) || !slices.Contains(stubEffects, r.Effect) {
					return fmt.Errorf("%w %s: step %q stub %s/%s", ErrCase, c.Name, id, r.State, r.Effect)
				}
				if r.Wait.D() < 0 || r.Wait.D() > 7*24*time.Hour {
					return fmt.Errorf("%w %s: step %q waits %s", ErrCase, c.Name, id, r.Wait.D())
				}
			}
		}
		for id := range c.Expect.Steps {
			if def.Step(id) == nil {
				return fmt.Errorf("%w %s: expects step %q, which does not exist", ErrCase, c.Name, id)
			}
		}
	}
	return nil
}

// Irreversible reports whether the version's ceiling bounds any of the
// irreversible operations: its operations match one, or it names none
// (every operation).
func Irreversible(def *autodomain.Definition, irreversible map[string]bool) bool {
	c := def.Authority.Ceiling
	if c == nil {
		return false
	}
	for op := range irreversible {
		if allows(c.Bounds, op) {
			return true
		}
	}
	return false
}

func allows(b gdomain.Bounds, op string) bool { return b.Operations == nil || b.Operations.Matches(op) }

// RequiredKinds are the kinds a version's cases must cover (HR-287):
// NORMAL, DENIED, TIMEOUT and DUPLICATE, and PARTIAL or UNKNOWN when its
// ceiling has an irreversible operation (listed as "PARTIAL|UNKNOWN").
func RequiredKinds(irreversible bool) []string {
	out := []string{string(CaseNormal), string(CaseDenied), string(CaseTimeout), string(CaseDuplicate)}
	if irreversible {
		out = append(out, string(CasePartial)+"|"+string(CaseUnknown))
	}
	return out
}

// Missing lists the required kinds no case covers.
func Missing(cases []Case, irreversible bool) []string {
	have := map[string]bool{}
	for _, c := range cases {
		have[string(c.Kind)] = true
	}
	var out []string
	for _, k := range RequiredKinds(irreversible) {
		if !slices.ContainsFunc(strings.Split(k, "|"), func(x string) bool { return have[x] }) {
			out = append(out, k)
		}
	}
	return out
}

// Digest is the SHA-256 of the cases' canonical JSON, in order: a run
// counts only for the cases it ran (HR-287).
func Digest(cases []Case) ([]byte, error) {
	b, err := json.Marshal(cases, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// Outcome is what a case's simulated execution did.
type Outcome struct {
	State  string
	Reason string
	Steps  map[string]string
	// DuplicateRefused: the second submission of a DUPLICATE case had the
	// same dedupe key and would start no execution.
	DuplicateRefused bool
	Elapsed          time.Duration
}

// CaseResult is a case's result.
type CaseResult struct {
	Name             string              `json:"name"`
	Kind             CaseKind            `json:"kind"`
	Passed           bool                `json:"passed"`
	State            string              `json:"state"`
	Reason           string              `json:"reason,omitzero"`
	Steps            map[string]string   `json:"steps,omitzero"`
	Differences      []string            `json:"differences,omitzero"`
	DuplicateRefused bool                `json:"duplicate_refused,omitzero"`
	Elapsed          autodomain.Duration `json:"elapsed,omitzero"`
}

// Judge compares an outcome with the case's expectation.
func Judge(c Case, o Outcome) CaseResult {
	r := CaseResult{
		Name: c.Name, Kind: c.Kind, State: o.State, Reason: o.Reason, Steps: o.Steps, DuplicateRefused: o.DuplicateRefused,
		Elapsed: autodomain.Duration(o.Elapsed),
	}
	if o.State != c.Expect.State {
		r.Differences = append(r.Differences, fmt.Sprintf("state %s, expected %s", o.State, c.Expect.State))
	}
	if c.Expect.Reason != "" && o.Reason != c.Expect.Reason {
		r.Differences = append(r.Differences, fmt.Sprintf("reason %q, expected %q", o.Reason, c.Expect.Reason))
	}
	ids := make([]string, 0, len(c.Expect.Steps))
	for id := range c.Expect.Steps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if got := o.Steps[id]; got != c.Expect.Steps[id] {
			r.Differences = append(r.Differences, fmt.Sprintf("step %s %s, expected %s", id, orNone(got), c.Expect.Steps[id]))
		}
	}
	if c.Kind == CaseDuplicate && !o.DuplicateRefused {
		r.Differences = append(r.Differences, "a second identical trigger would start another execution")
	}
	r.Passed = len(r.Differences) == 0
	return r
}

func orNone(s string) string {
	if s == "" {
		return "not reached"
	}
	return s
}

// RunResult is a whole run: every case, and the kinds still missing.
type RunResult struct {
	Cases   []CaseResult `json:"cases"`
	Missing []string     `json:"missing_kinds,omitzero"`
}

// Passed reports whether the run makes the version TESTED: no required
// kind missing and every case passed (HR-287).
func (r RunResult) Passed() bool {
	if len(r.Missing) > 0 || len(r.Cases) == 0 {
		return false
	}
	for _, c := range r.Cases {
		if !c.Passed {
			return false
		}
	}
	return true
}
