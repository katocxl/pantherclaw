// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

const sample = `
apiVersion: automations.pantherclaw.dev/v1
kind: Automation
purpose: Refund small tickets from Support.
work_kind: AGENT_WORK
review_by: "2026-12-01"
when:
  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:
      ticket:
        from: /ticket/id
        type: string
        pattern: "T-[0-9]{1,10}"
authority:
  principal: self
  ceiling:
    agents: [0192f000-0000-7000-8000-000000000003]
    bounds:
      operations: [payments.refund]
    per_grant:
      ttl: 1h
    per_day:
      grants: 5
      runs: 5
      budget:
        - currency: USD
          amount: "250.00"
do:
  - id: launch
    step: launch_run
    with:
      agent: 0192f000-0000-7000-8000-000000000003
      task_ref: "ticket {{params.ticket}}"
  - id: wait
    step: wait_run
    with:
      step: launch
    timeout: 2h
finish_when:
  - step: wait
    condition: RUN_ENDED
limits:
  deadline: 1d
`

func parse(t *testing.T) *autodomain.Definition {
	t.Helper()
	d, err := autodomain.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func cases(kinds ...assurance.CaseKind) []assurance.Case {
	var out []assurance.Case
	for i, k := range kinds {
		out = append(out, assurance.Case{
			Name: string(rune('a'+i)) + "-case", Kind: k, Expect: assurance.Expect{State: "SUCCEEDED"},
		})
	}
	return out
}

// A version is TESTED only when its cases cover NORMAL, DENIED, TIMEOUT
// and DUPLICATE, plus PARTIAL or UNKNOWN when its ceiling has an
// irreversible operation, and every case passes.
func TestHR287_RequiredKindsAndPassing(t *testing.T) {
	d := parse(t)
	rev := map[string]defs.Reversibility{"payments.refund": defs.Reversible, "payments.charge": defs.Irreversible}
	if assurance.Irreversible(d, rev, false) {
		t.Error("a ceiling bounded to payments.refund reaches payments.charge")
	}
	if assurance.Irreversible(d, rev, true) {
		t.Error("an unreadable package made an exact, declared reversible operation irreversible")
	}
	// D94 S2: unknown or undeclared reversibility counts as irreversible.
	for name, ops := range map[string]map[string]defs.Reversibility{
		"unknown":    {"payments.refund": ""},
		"undeclared": {"payments.charge": defs.Reversible},
	} {
		if !assurance.Irreversible(d, ops, false) {
			t.Errorf("%s reversibility counted as reversible", name)
		}
	}
	irr := assurance.Irreversible(d, map[string]defs.Reversibility{"payments.refund": defs.Irreversible}, false)
	if !irr {
		t.Fatal("payments.refund is irreversible and in the ceiling")
	}
	base := cases(assurance.CaseNormal, assurance.CaseDenied, assurance.CaseTimeout, assurance.CaseDuplicate)
	if got := assurance.Missing(base, false); len(got) != 0 {
		t.Errorf("reversible ceiling: missing %v", got)
	}
	if got := assurance.Missing(base, irr); !slices.Equal(got, []string{"PARTIAL|UNKNOWN"}) {
		t.Errorf("irreversible ceiling: missing %v", got)
	}
	if got := assurance.Missing(append(base, cases(assurance.CaseUnknown)...), irr); len(got) != 0 {
		t.Errorf("UNKNOWN covers the irreversible kind: missing %v", got)
	}
	if got := assurance.Missing(base[:3], false); !slices.Equal(got, []string{"DUPLICATE"}) {
		t.Errorf("missing %v, want DUPLICATE", got)
	}

	pass := assurance.CaseResult{Passed: true}
	if (assurance.RunResult{Cases: []assurance.CaseResult{pass}, Missing: []string{"TIMEOUT"}}).Passed() {
		t.Error("a run missing a required kind passed")
	}
	if (assurance.RunResult{Cases: []assurance.CaseResult{pass, {Passed: false}}}).Passed() {
		t.Error("a run with a failing case passed")
	}
	if (assurance.RunResult{}).Passed() {
		t.Error("an empty run passed")
	}
	if !(assurance.RunResult{Cases: []assurance.CaseResult{pass}}).Passed() {
		t.Error("a complete passing run did not pass")
	}
}

func TestJudge(t *testing.T) {
	c := assurance.Case{
		Name: "dup", Kind: assurance.CaseDuplicate,
		Expect: assurance.Expect{State: "SUCCEEDED", Steps: map[string]string{"launch": "DONE", "wait": "DONE"}},
	}
	ok := assurance.Judge(c, assurance.Outcome{
		State: "SUCCEEDED", Steps: map[string]string{"launch": "DONE", "wait": "DONE"}, DuplicateRefused: true,
	})
	if !ok.Passed {
		t.Errorf("differences %v", ok.Differences)
	}
	bad := assurance.Judge(c, assurance.Outcome{State: "FAILED", Steps: map[string]string{"launch": "FAILED"}})
	if bad.Passed || len(bad.Differences) != 4 {
		t.Errorf("differences %v; want state, launch, wait and the duplicate", bad.Differences)
	}
}

func TestCheckAndDigest(t *testing.T) {
	d := parse(t)
	good := []assurance.Case{{
		Name: "normal", Kind: assurance.CaseNormal, Trigger: assurance.CaseTrigger{Params: map[string]string{"ticket": "T-1"}},
		Stubs:  map[string][]assurance.StubResult{"launch": {{State: "DONE", Effect: "CHANGED"}}},
		Expect: assurance.Expect{State: "SUCCEEDED", Steps: map[string]string{"wait": "DONE"}},
	}}
	if err := assurance.Check(d, good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*assurance.Case){
		"unknown step stub":   func(c *assurance.Case) { c.Stubs = map[string][]assurance.StubResult{"nope": {{State: "DONE"}}} },
		"unknown step expect": func(c *assurance.Case) { c.Expect.Steps = map[string]string{"nope": "DONE"} },
		"not final":           func(c *assurance.Case) { c.Expect.State = "RUNNING" },
		"bad kind":            func(c *assurance.Case) { c.Kind = "MAYBE" },
		"bad stub state":      func(c *assurance.Case) { c.Stubs = map[string][]assurance.StubResult{"launch": {{State: "SHADOWED"}}} },
	} {
		c := good[0]
		mut(&c)
		if assurance.Check(d, []assurance.Case{c}) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, err := assurance.Digest(good)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := assurance.Digest(good)
	good[0].Expect.State = "FAILED"
	c, _ := assurance.Digest(good)
	if !bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Error("the digest is not deterministic or misses a change")
	}
}
