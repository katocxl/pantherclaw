// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

type fake struct {
	caps       map[app.Capability]bool
	fixture    app.Fixture
	setupErr   error
	teardownEr error
	respond    func(st domain.Step, n int) (domain.Observation, error)
	calls      []domain.Step
	varsSeen   []map[string]string
	setups     int
	teardowns  int
}

func (f *fake) Capabilities() map[app.Capability]bool { return f.caps }
func (f *fake) Setup(context.Context, domain.Scenario) (app.Fixture, error) {
	f.setups++
	return f.fixture, f.setupErr
}

func (f *fake) Do(ctx context.Context, _ domain.Scenario, st domain.Step, vars map[string]string) (domain.Observation, error) {
	f.calls = append(f.calls, st)
	cp := map[string]string{}
	for k, v := range vars {
		cp[k] = v
	}
	f.varsSeen = append(f.varsSeen, cp)
	return f.respond(st, len(f.calls))
}

func (f *fake) Teardown(context.Context, domain.Scenario) error { f.teardowns++; return f.teardownEr }

func all() map[app.Capability]bool {
	return map[app.Capability]bool{app.CapGitHub: true, app.CapMCP: true, app.CapPerson: true, app.CapHarness: true, app.CapSandbox: true}
}

func scenario(t *testing.T, steps string) domain.Scenario {
	t.Helper()
	s, err := domain.Parse([]byte(`apiVersion: pantherclaw.range/v1
id: RT-009
title: t
category: boundary
suite: coding-agent
tier: community
attacker: A1
threats: [T-080]
rules: [HR-201]
steps:
` + steps))
	if err != nil {
		t.Fatal(err)
	}
	return *s
}

const twoCalls = `  - {id: first, do: agent.call, with: {face: mcp, connection: github, tool: t, args: {n: 1}}, save: {pr: /number}, expect: {outcome: HOLD, reason: R}}
  - {id: second, do: agent.call, with: {face: http, connection: github, method: GET, path: "/pulls/${pr}/${fixture.branch}"}, expect: {outcome: HOLD, same_decision_as: first}}
`

func hold(domain.Step, int) (domain.Observation, error) {
	return domain.Observation{Outcome: domain.OutcomeHold, Reason: "R", Response: []byte(`{"number": 12345678901234567}`)}, nil
}

func TestRunnerPassesAndSubstitutes(t *testing.T) {
	d := &fake{caps: all(), fixture: app.Fixture{"branch": "feat"}, respond: hold}
	res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, twoCalls))
	if res.Verdict != domain.VerdictPass || len(res.Steps) != 2 {
		t.Fatalf("%+v", res)
	}
	if got := string(d.calls[1].With); !strings.Contains(got, "/pulls/12345678901234567/feat") {
		t.Errorf("second step with = %s", got)
	}
	if d.setups != 1 || d.teardowns != 1 || res.Digest == "" {
		t.Errorf("setups %d teardowns %d digest %q", d.setups, d.teardowns, res.Digest)
	}
}

func TestRunnerStopsOnFailAndTearsDown(t *testing.T) {
	d := &fake{caps: all(), fixture: app.Fixture{"branch": "b"}, respond: func(st domain.Step, n int) (domain.Observation, error) {
		return domain.Observation{Outcome: domain.OutcomeAllow, Response: []byte(`{"number":1}`)}, nil
	}}
	res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, twoCalls))
	if res.Verdict != domain.VerdictFail || len(res.Steps) != 1 || len(d.calls) != 1 {
		t.Fatalf("%+v calls=%d", res, len(d.calls))
	}
	if d.teardowns != 1 {
		t.Error("teardown did not run")
	}
}

func TestRunnerNeverRetries(t *testing.T) {
	d := &fake{caps: all(), respond: func(domain.Step, int) (domain.Observation, error) { return domain.Observation{}, errors.New("boom") }}
	res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, "  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t}, expect: {outcome: ALLOW}}\n"))
	if res.Verdict != domain.VerdictError || len(d.calls) != 1 || d.teardowns != 1 {
		t.Fatalf("%+v calls=%d", res, len(d.calls))
	}
}

func TestRunnerSetupErrorStillTearsDown(t *testing.T) {
	d := &fake{caps: all(), setupErr: errors.New("no sim"), respond: hold}
	res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, twoCalls))
	if res.Verdict != domain.VerdictError || d.teardowns != 1 || len(d.calls) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestRunnerTimeoutIsAnError(t *testing.T) {
	d := &fake{caps: all(), respond: func(domain.Step, int) (domain.Observation, error) {
		time.Sleep(80 * time.Millisecond)
		return domain.Observation{Outcome: domain.OutcomeAllow}, nil
	}}
	res := (&app.Runner{Driver: d, Timeout: 20 * time.Millisecond}).Run(context.Background(), scenario(t, "  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t}, expect: {outcome: ALLOW}}\n"))
	if res.Verdict != domain.VerdictError || d.teardowns != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestRunnerTeardownFailureTurnsPassIntoError(t *testing.T) {
	d := &fake{caps: all(), teardownEr: errors.New("leak"), respond: hold, fixture: app.Fixture{"branch": "b"}}
	res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, twoCalls))
	if res.Verdict != domain.VerdictError {
		t.Fatalf("%+v", res)
	}
}

func TestRunnerSkips(t *testing.T) {
	step := "  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t}, expect: {outcome: ALLOW}}\n"
	for name, tc := range map[string]struct {
		caps    map[app.Capability]bool
		body    func(domain.Scenario) domain.Scenario
		steps   string
		wantRun bool
	}{
		"missing capability": {map[app.Capability]bool{}, func(s domain.Scenario) domain.Scenario { s.Requires = []string{"github"}; return s }, step, false},
		"harness only":       {map[app.Capability]bool{}, func(s domain.Scenario) domain.Scenario { s.HarnessOnly = true; return s }, step, false},
		"person step":        {map[app.Capability]bool{}, func(s domain.Scenario) domain.Scenario { return s }, "  - {id: h, do: operator.revoke_grant}\n  - {id: a, do: person.approve, with: {step: h, as: approver}, expect: {outcome: ALLOW}}\n", false},
		"capable": {all(), func(s domain.Scenario) domain.Scenario {
			s.Requires = []string{"github"}
			s.HarnessOnly = true
			return s
		}, step, true},
	} {
		d := &fake{caps: tc.caps, respond: func(domain.Step, int) (domain.Observation, error) {
			return domain.Observation{Outcome: domain.OutcomeAllow}, nil
		}}
		res := (&app.Runner{Driver: d}).Run(context.Background(), tc.body(scenario(t, tc.steps)))
		if tc.wantRun != (res.Verdict == domain.VerdictPass) || (!tc.wantRun && (res.Verdict != domain.VerdictSkipped || d.setups != 0)) {
			t.Errorf("%s: %+v setups=%d", name, res, d.setups)
		}
	}
}

func TestRunnerRejectsASubstitutedValueThatBreaksTheRules(t *testing.T) {
	// A saved response value cannot turn a path into a URL (T-092).
	d := &fake{caps: all(), respond: func(st domain.Step, n int) (domain.Observation, error) {
		return domain.Observation{Outcome: domain.OutcomeAllow, Response: []byte(`{"p":"//evil.example"}`)}, nil
	}}
	res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, `  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t}, save: {p: /p}, expect: {outcome: ALLOW}}
  - {id: b, do: agent.call, with: {face: http, connection: g, method: GET, path: "/${p}"}, expect: {outcome: ALLOW}}
`))
	if res.Verdict != domain.VerdictError || len(d.calls) != 1 {
		t.Fatalf("%+v calls=%d", res, len(d.calls))
	}
}

func TestRunnerSaveOfAMissingPointerFails(t *testing.T) {
	d := &fake{caps: all(), fixture: app.Fixture{"branch": "b"}, respond: func(domain.Step, int) (domain.Observation, error) {
		return domain.Observation{Outcome: domain.OutcomeHold, Reason: "R", Response: []byte(`{"other":1}`)}, nil
	}}
	res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, twoCalls))
	if res.Verdict != domain.VerdictFail {
		t.Fatalf("%+v", res)
	}
}

func TestLoadDirSortsAndChecks(t *testing.T) {
	set, err := app.LoadDir("../testdata/valid")
	if err != nil || len(set) < 3 {
		t.Fatalf("%v %d", err, len(set))
	}
	for i := 1; i < len(set); i++ {
		if set[i-1].Scenario.ID >= set[i].Scenario.ID {
			t.Error("not sorted by id")
		}
	}
	if _, err := app.LoadDir("../testdata/invalid"); err == nil {
		t.Error("a directory of invalid files loaded")
	}
}

func TestHR226_RunnerResultsFeedTheGate(t *testing.T) {
	d := &fake{caps: all(), fixture: app.Fixture{"branch": "b"}, respond: hold}
	r := &app.Runner{Driver: d}
	good := r.Run(context.Background(), scenario(t, twoCalls))
	d.respond = func(domain.Step, int) (domain.Observation, error) {
		return domain.Observation{Outcome: domain.OutcomeAllow, Response: []byte(`{"number":1}`)}, nil
	}
	bad := r.Run(context.Background(), scenario(t, twoCalls))
	c := domain.Compare(app.Entries([]domain.Result{good}), app.Entries([]domain.Result{bad}))
	if c.ExitCode() != 1 || len(c.Regressions) != 1 {
		t.Fatalf("%+v", c)
	}
}

func concurrentScenario(t *testing.T, expect string) domain.Scenario {
	return scenario(t, `  - id: race
    do: agent.call
    with: {face: sdk, connection: payments, tool: refund, concurrent: 5, args: {charge: "c-${n}"}}
    expect: `+expect+"\n")
}

func eachOf(outcomes ...domain.Outcome) func(domain.Step, int) (domain.Observation, error) {
	return func(st domain.Step, _ int) (domain.Observation, error) {
		o := domain.Observation{}
		for _, x := range outcomes {
			o.Each = append(o.Each, domain.Observation{Outcome: x, Reason: "LIMIT"})
		}
		return o, nil
	}
}

func TestRunnerJudgesConcurrentCalls(t *testing.T) {
	a, d := domain.OutcomeAllow, domain.OutcomeDeny
	for name, tc := range map[string]struct {
		got  []domain.Outcome
		want domain.Verdict
	}{
		"within limit":   {[]domain.Outcome{a, a, d, d, d}, domain.VerdictPass},
		"over the limit": {[]domain.Outcome{a, a, a, d, d}, domain.VerdictFail},
		"wrong outcome":  {[]domain.Outcome{a, d, d, d, domain.OutcomeHold}, domain.VerdictFail},
		"wrong count":    {[]domain.Outcome{a, d}, domain.VerdictError},
	} {
		dr := &fake{caps: all(), respond: eachOf(tc.got...)}
		res := (&app.Runner{Driver: dr}).Run(context.Background(), concurrentScenario(t, "{outcome: DENY, max_allow: 2}"))
		if res.Verdict != tc.want {
			t.Errorf("%s: %+v", name, res)
		}
		if tc.want != domain.VerdictError && !strings.Contains(string(dr.calls[0].With), "${n}") {
			t.Errorf("%s: ${n} was substituted by the runner: %s", name, dr.calls[0].With)
		}
	}
	// Without max_allow every call must match.
	dr := &fake{caps: all(), respond: eachOf(a, d, d, d, d)}
	if res := (&app.Runner{Driver: dr}).Run(context.Background(), concurrentScenario(t, "{outcome: DENY}")); res.Verdict != domain.VerdictFail {
		t.Errorf("%+v", res)
	}
}

func TestRunnerReasonMatchesAnyOfReasons(t *testing.T) {
	step := "  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t}, expect: {outcome: DENY, reason: B}}\n"
	for reasons, want := range map[string]domain.Verdict{"A,B": domain.VerdictPass, "A": domain.VerdictFail} {
		dr := &fake{caps: all(), respond: func(domain.Step, int) (domain.Observation, error) {
			return domain.Observation{Outcome: domain.OutcomeDeny, Reason: "A", Reasons: strings.Split(reasons, ",")}, nil
		}}
		if res := (&app.Runner{Driver: dr}).Run(context.Background(), scenario(t, step)); res.Verdict != want {
			t.Errorf("%s: %+v", reasons, res)
		}
	}
}

func TestRunnerBlockingOutcomesWhenOutcomeIsEmpty(t *testing.T) {
	a := domain.OutcomeAllow
	for name, tc := range map[string]struct {
		got  []domain.Outcome
		want domain.Verdict
	}{
		"mixed blocks":        {[]domain.Outcome{a, domain.OutcomeDeny, domain.OutcomeHold, domain.OutcomeRefused, domain.OutcomeCannotAuthorize}, domain.VerdictPass},
		"unknown is no block": {[]domain.Outcome{a, domain.OutcomeDeny, domain.OutcomeUnknown, domain.OutcomeDeny, domain.OutcomeDeny}, domain.VerdictFail},
		"too many allows":     {[]domain.Outcome{a, a, domain.OutcomeDeny, domain.OutcomeDeny, domain.OutcomeDeny}, domain.VerdictFail},
	} {
		dr := &fake{caps: all(), respond: eachOf(tc.got...)}
		res := (&app.Runner{Driver: dr}).Run(context.Background(), concurrentScenario(t, "{max_allow: 1}"))
		if res.Verdict != tc.want {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

func TestD30PersonRefusedFailsAndMissingReceiptPartsFail(t *testing.T) {
	steps := `  - {id: held, do: operator.revoke_grant}
  - {id: approve, do: person.approve, with: {step: held, as: approver}, expect: {outcome: ALLOW}}
`
	refused := &fake{caps: all(), respond: func(st domain.Step, n int) (domain.Observation, error) {
		if st.Do == "person.approve" {
			return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "SELF_APPROVAL"}, nil
		}
		return domain.Observation{}, nil
	}}
	if res := (&app.Runner{Driver: refused}).Run(context.Background(), scenario(t, steps)); res.Verdict != domain.VerdictFail {
		t.Errorf("a refused approval: %+v", res)
	}
	receipt := `  - {id: held, do: operator.revoke_grant}
  - {id: evidence, do: check.receipt, with: {of: held, has: [grant, simulated]}, expect: {outcome: HOLD}}
`
	for missing, want := range map[string]domain.Verdict{"": domain.VerdictPass, "simulated": domain.VerdictFail} {
		d := &fake{caps: all(), respond: func(st domain.Step, n int) (domain.Observation, error) {
			if st.Do == "check.receipt" {
				o := domain.Observation{Outcome: domain.OutcomeHold}
				if missing != "" {
					o.Missing = []string{missing}
				}
				return o, nil
			}
			return domain.Observation{}, nil
		}}
		if res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, receipt)); res.Verdict != want {
			t.Errorf("missing %q: %+v", missing, res)
		}
	}
}

func TestD30RunValidatesFirstAndNeverCallsTheDriver(t *testing.T) {
	s := scenario(t, "  - {id: a, do: operator.revoke_grant}\n")
	s.Steps[0].Do = "shell.run"
	d := &fake{caps: all(), respond: hold}
	res := (&app.Runner{Driver: d}).Run(context.Background(), s)
	if res.Verdict != domain.VerdictError || len(d.calls) != 0 || d.setups != 0 {
		t.Fatalf("%+v setups=%d calls=%d", res, d.setups, len(d.calls))
	}
}

func TestD30LoadDirReadsOnlyRegularFilesOfBoundedSize(t *testing.T) {
	dir := t.TempDir()
	good, err := os.ReadFile("../testdata/valid/RT-001-mcp-merge-held.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "RT-001-mcp-merge-held.yaml"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	huge := make([]byte, domain.MaxFileBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "RT-002-huge.yaml"), huge, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.LoadDir(dir); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized file: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "RT-002-huge.yaml"))
	if err := os.Mkdir(filepath.Join(dir, "RT-003-dir.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := app.LoadDir(dir); err == nil {
		t.Error("a directory named like a scenario file was accepted")
	}
	_ = os.Remove(filepath.Join(dir, "RT-003-dir.yaml"))
	if err := os.Symlink(filepath.Join(dir, "RT-001-mcp-merge-held.yaml"), filepath.Join(dir, "RT-004-link.yaml")); err == nil {
		if _, err := app.LoadDir(dir); err == nil {
			t.Error("a symbolic link was followed")
		}
	}
}
