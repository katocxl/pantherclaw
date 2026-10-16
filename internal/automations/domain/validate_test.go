// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type fakeEnv struct {
	irreversible map[string]bool
	budget       map[string]bool
	approvers    int
	edition      autodomain.Edition
	noOwner      bool
	under        map[string][]string
}

func (fakeEnv) Now() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }
func (e fakeEnv) Owner() ids.UUID {
	if e.noOwner {
		return ids.UUID{}
	}
	u, _ := ids.ParseUUID("0192f000-0000-7000-8000-000000000001")
	return u
}

func (fakeEnv) OwnerActivePerson(context.Context, ids.UUID) (bool, error) {
	return true, nil
}
func (fakeEnv) AgentGrantable(context.Context, ids.UUID) (bool, error) { return true, nil }
func (e fakeEnv) Operation(_ context.Context, op string) (autodomain.OperationInfo, error) {
	return autodomain.OperationInfo{
		Known: true, Irreversible: e.irreversible[op], ConsumesBudget: e.budget[op], IrreversibleUnder: e.under[op],
	}, nil
}

func (fakeEnv) DestinationActive(context.Context, ids.UUID, string) (bool, error) { return true, nil }

func (e fakeEnv) EligibleApprovers(context.Context, autodomain.GateWith, ids.UUID, ids.UUID) (int, error) {
	return e.approvers, nil
}

func (e fakeEnv) Edition(x autodomain.Edition) bool {
	return e.edition == autodomain.EditionBusiness || x == autodomain.EditionTeam
}

func codes(fs []autodomain.Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Severity == autodomain.SeverityError {
			out = append(out, f.Code)
		}
	}
	return out
}

func validate(t *testing.T, doc string, env fakeEnv) []autodomain.Finding {
	t.Helper()
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return autodomain.Validate(context.Background(), d, env)
}

func TestValidateSampleIsValid(t *testing.T) {
	fs := validate(t, sample, fakeEnv{edition: autodomain.EditionTeam, approvers: 1})
	if autodomain.HasErrors(fs) {
		t.Fatalf("findings: %+v", fs)
	}
	d, _ := autodomain.Parse([]byte(sample))
	s := autodomain.Summary(d, autodomain.Names{"0192f000-0000-7000-8000-000000000003": "Support Agent"})
	for _, want := range []string{"When: a signed ticket.created event arrives", "launch Support Agent for ticket {{params.ticket}}", "Finish when: step wait shows run ended"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
	if s2 := autodomain.Summary(d, autodomain.Names{"0192f000-0000-7000-8000-000000000003": "Support Agent"}); s2 != s {
		t.Error("the summary is not deterministic")
	}
	nodes, edges := autodomain.Graph(d)
	if len(nodes) != 4 || len(edges) != 3 {
		t.Errorf("graph %d nodes %d edges", len(nodes), len(edges))
	}
}

// TestValidateFindings: each D4 code fires on the definition that earns it.
func TestValidateFindings(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, code string
		env                  fakeEnv
	}{
		{
			"irreversible without wait_effect", "", "", autodomain.CodeIrreversibleUnreconciled,
			fakeEnv{irreversible: map[string]bool{"payments.refund": true}, approvers: 1},
		},
		{
			"budget without per-grant budget", "", "", autodomain.CodeCeilingUnbounded,
			fakeEnv{budget: map[string]bool{"payments.refund": true}, approvers: 1},
		},
		{"templated delivery", "      agent: 0192f000-0000-7000-8000-000000000003\n", "      agent: 0192f000-0000-7000-8000-000000000003\n      delivery: \"{{params.ticket}}\"\n", autodomain.CodeTemplateField, fakeEnv{approvers: 1}},
		{"undeclared parameter", "{{params.ticket}}", "{{params.amount}}", autodomain.CodeParamUndeclared, fakeEnv{approvers: 1}},
		{"unbounded string param", `pattern: "T-[0-9]{1,10}"`, "max_len: 20", autodomain.CodeParamUnbounded, fakeEnv{approvers: 1}},
		{"no finish", "finish_when:\n  - step: wait\n    condition: RUN_ENDED\n", "", autodomain.CodeTerminalMissing, fakeEnv{approvers: 1}},
		{"request-only completion", "condition: RUN_ENDED", "condition: EFFECT_CONFIRMED", autodomain.CodeCompletionRequestOnly, fakeEnv{approvers: 1}},
		{"no review date", "review_by: \"2026-12-01\"\n", "", autodomain.CodeReviewDate, fakeEnv{approvers: 1}},
		{"review date too far", "2026-12-01", "2027-06-01", autodomain.CodeReviewDate, fakeEnv{approvers: 1}},
		{"bad principal", "principal: self", "principal: alice", autodomain.CodePrincipalInvalid, fakeEnv{approvers: 1}},
		{"wait without timeout", "    timeout: 2h\n", "", autodomain.CodeDeadlineMissing, fakeEnv{approvers: 1}},
		{"agent outside ceiling", "      agent: 0192f000-0000-7000-8000-000000000003", "      agent: 0192f000-0000-7000-8000-000000000004", autodomain.CodeLimitRange, fakeEnv{approvers: 1}},
		{"unknown step", "step: wait_run", "step: run_shell", autodomain.CodeUnsupportedCapability, fakeEnv{approvers: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := sample
			if tc.from != "" {
				if !strings.Contains(doc, tc.from) {
					t.Fatalf("sample lacks %q", tc.from)
				}
				doc = strings.Replace(doc, tc.from, tc.to, 1)
			}
			d, err := autodomain.Parse([]byte(doc))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			fs := autodomain.Validate(context.Background(), d, tc.env)
			if got := codes(fs); !slices.Contains(got, tc.code) {
				t.Errorf("codes %v, want %s", got, tc.code)
			}
		})
	}
}

func TestValidateLoopWarning(t *testing.T) {
	doc := strings.Replace(sample, `  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:`, `  event:
    on: run.ended
    params:`, 1)
	fs := validate(t, doc, fakeEnv{approvers: 1})
	if !slices.ContainsFunc(fs, func(f autodomain.Finding) bool {
		return f.Code == autodomain.CodeLoopPossible && f.Severity == autodomain.SeverityWarning
	}) {
		t.Errorf("no LOOP_POSSIBLE warning: %+v", fs)
	}
}

func TestRequiredConfirmerPermissions(t *testing.T) {
	d, err := autodomain.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	got := d.RequiredConfirmerPermissions()
	agent, _ := ids.ParseUUID("0192f000-0000-7000-8000-000000000003")
	if len(got.Agents) != 1 || !slices.Equal(got.Agents[agent], []string{"grant.issue", "run.start"}) || len(got.Org) != 0 {
		t.Errorf("confirmer permissions %+v", got)
	}
}

// revoking is the sample plus a revoke_grant step of the trigger's grant.
func revoking(revocable string) string {
	doc := strings.Replace(sample, "    timeout: 2h\n", `    timeout: 2h
  - id: revoke
    step: revoke_grant
    with:
      scope: TRIGGER_GRANT
`, 1)
	doc = strings.Replace(doc, "do:\n", revocable+"  platform:\n    - step: revoke_grant\n      scopes: [TRIGGER_GRANT]\ndo:\n", 1)
	return doc
}

// TestRevocableScope (D65): revoking beyond the execution needs
// authority.revocable, and confirmers then need grant.revoke at the listed
// agents' paths, or at the org for all.
func TestRevocableScope(t *testing.T) {
	if got := codes(validate(t, revoking(""), fakeEnv{approvers: 1})); !slices.Contains(got, autodomain.CodeLimitRange) {
		t.Errorf("revoke_grant TRIGGER_GRANT without revocable: %v", got)
	}
	listed := revoking("  revocable:\n    agents: [0192f000-0000-7000-8000-000000000005]\n")
	if fs := validate(t, listed, fakeEnv{approvers: 1}); autodomain.HasErrors(fs) {
		t.Fatalf("findings: %+v", fs)
	}
	d, _ := autodomain.Parse([]byte(listed))
	other, _ := ids.ParseUUID("0192f000-0000-7000-8000-000000000005")
	if got := d.RequiredConfirmerPermissions(); !slices.Equal(got.Agents[other], []string{"grant.revoke"}) {
		t.Errorf("revocable agent permissions %+v", got)
	}
	d, _ = autodomain.Parse([]byte(revoking("  revocable:\n    all: true\n")))
	if got := d.RequiredConfirmerPermissions(); !slices.Equal(got.Org, []string{"grant.revoke"}) {
		t.Errorf("revocable all permissions %+v", got)
	}
	both := revoking("  revocable:\n    all: true\n    agents: [0192f000-0000-7000-8000-000000000005]\n")
	if got := codes(validate(t, both, fakeEnv{approvers: 1})); !slices.Contains(got, autodomain.CodeLimitRange) {
		t.Errorf("agents and all together: %v", got)
	}
}

// TestBuildDigestEvidenceScope (D85): confirmers hold evidence.read and
// evidence.export at the declared agents' paths, or at the org for all.
func TestBuildDigestEvidenceScope(t *testing.T) {
	d := &autodomain.Definition{Do: []autodomain.StepSpec{{
		ID: "digest", Step: autodomain.KindBuildDigest,
		With: []byte(`{"scope":"TIME_RANGE","days":7,"evidence":{"agents":["0192f000-0000-7000-8000-000000000005"]},"sections":["decisions"]}`),
	}}}
	a, _ := ids.ParseUUID("0192f000-0000-7000-8000-000000000005")
	if got := d.RequiredConfirmerPermissions(); !slices.Equal(got.Agents[a], []string{"evidence.export", "evidence.read"}) || len(got.Org) != 0 {
		t.Errorf("evidence agents %+v", got)
	}
	d.Do[0].With = []byte(`{"scope":"TIME_RANGE","days":7,"evidence":{"all":true},"sections":["decisions"]}`)
	if got := d.RequiredConfirmerPermissions(); !slices.Equal(got.Org, []string{"evidence.export", "evidence.read"}) {
		t.Errorf("evidence all %+v", got)
	}
	d.Do[0].Step = autodomain.KindPauseLaunches
	d.Do[0].With = []byte(`{"selector":"AFFECTED"}`)
	if got := d.RequiredConfirmerPermissions(); !slices.Equal(got.Org, []string{"automation.publish"}) {
		t.Errorf("pause_launches confirms with automation.publish (D67): %+v", got)
	}
}

// TestLaunchLimitsOnlyNarrow (D84 E6, E7): a launch may only lower the
// per-grant limits, every spending operation needs a per-grant budget, and
// wait_effect names an exact operation.
func TestLaunchLimitsOnlyNarrow(t *testing.T) {
	ceiling := "    per_grant:\n      ttl: 1h\n      limits:\n        budgets:\n          - id: spend\n            grouping: task\n            operations: [payments.refund]\n            currency: USD\n            limit: \"50.00\"\n            period: grant\n"
	doc := strings.Replace(sample, "    per_grant:\n      ttl: 1h\n", ceiling, 1)
	spend := fakeEnv{budget: map[string]bool{"payments.refund": true}, approvers: 1}
	if fs := validate(t, doc, spend); autodomain.HasErrors(fs) {
		t.Fatalf("findings: %+v", fs)
	}
	launch := func(limit string) string {
		return strings.Replace(doc, "      task_ref: \"ticket {{params.ticket}}\"\n", "      task_ref: \"ticket {{params.ticket}}\"\n      grant:\n        limits:\n          budgets:\n            - id: spend\n              grouping: task\n              operations: [payments.refund]\n              currency: USD\n              limit: \""+limit+"\"\n              period: grant\n", 1)
	}
	if fs := validate(t, launch("20.00"), spend); autodomain.HasErrors(fs) {
		t.Errorf("a lower limit is refused: %+v", fs)
	}
	if got := codes(validate(t, launch("80.00"), spend)); !slices.Contains(got, autodomain.CodeLimitRange) {
		t.Errorf("a higher limit is accepted: %v", got)
	}
	effect := strings.Replace(sample, "  - id: wait\n    step: wait_run\n    with:\n      step: launch\n", "  - id: wait\n    step: wait_effect\n    with:\n      step: launch\n      operation: payments.*\n", 1)
	if got := codes(validate(t, effect, fakeEnv{approvers: 1})); !slices.Contains(got, autodomain.CodeLimitRange) {
		t.Errorf("a wait_effect pattern is accepted: %v", got)
	}
}

func TestOwnerComesFromTheRow(t *testing.T) {
	if got := codes(validate(t, sample, fakeEnv{approvers: 1, noOwner: true})); !slices.Contains(got, autodomain.CodeOwnerMissing) {
		t.Errorf("no owner: %v", got)
	}
	for name, ok := range map[string]bool{"refund-tickets": true, "a": true, "x-": false, "-x": false, strings.Repeat("a", 52): true, strings.Repeat("a", 53): false} {
		if autodomain.NamePattern.MatchString(name) != ok {
			t.Errorf("name %q: want %v", name, ok)
		}
	}
}

// TestManualStepUpForIrreversibleCeiling (D87 P3): a manual start of an
// automation whose ceiling has an irreversible operation needs step_up.
func TestManualStepUpForIrreversibleCeiling(t *testing.T) {
	doc := strings.Replace(sample, `  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:
      ticket:
        from: /ticket/id
`, `  manual:
    params:
      ticket:
`, 1)
	irreversible := fakeEnv{irreversible: map[string]bool{"payments.refund": true}, approvers: 1}
	fs := validate(t, doc, irreversible)
	if !slices.ContainsFunc(fs, func(f autodomain.Finding) bool { return f.Path == "/when/manual/step_up" }) {
		t.Errorf("no step_up finding: %+v", fs)
	}
	fs = validate(t, strings.Replace(doc, "  manual:\n", "  manual:\n    step_up: true\n", 1), irreversible)
	if slices.ContainsFunc(fs, func(f autodomain.Finding) bool { return f.Path == "/when/manual/step_up" }) {
		t.Errorf("step_up: true still refused: %+v", fs)
	}
}

// TestD91_ValidationFixes: the params envelope fits its CHECK (K3), a
// prefix never hides an irreversible operation (K4), and the summary says
// whose grants the version may revoke.
func TestD91_ValidationFixes(t *testing.T) {
	var params strings.Builder
	for i := range 16 {
		fmt.Fprintf(&params, "      p%02d:\n        from: /p%d\n        type: string\n        pattern: \"[a-z]+\"\n        max_len: 256\n", i, i)
	}
	big := strings.Replace(sample, "      ticket:\n        from: /ticket/id\n        type: string\n        pattern: \"T-[0-9]{1,10}\"\n", params.String(), 1)
	big = strings.ReplaceAll(big, "{{params.ticket}}", "{{params.p00}}")
	if got := codes(validate(t, big, fakeEnv{approvers: 1})); !slices.Contains(got, autodomain.CodeParamUnbounded) {
		t.Errorf("16 params of 256 characters: %v", got)
	}
	prefix := strings.Replace(sample, "operations: [payments.refund]", "operations: [payments.*]", 1)
	env := fakeEnv{approvers: 1, under: map[string][]string{"payments.*": {"payments.transfer"}}}
	if got := codes(validate(t, prefix, env)); !slices.Contains(got, autodomain.CodePrefixIrreversible) {
		t.Errorf("a prefix covering an irreversible operation: %v", got)
	}
	d, err := autodomain.Parse([]byte(revoking("  revocable:\n    all: true\n")))
	if err != nil {
		t.Fatal(err)
	}
	if s := autodomain.Summary(d, nil); !strings.Contains(s, "may revoke grants of any agent") {
		t.Errorf("summary lacks the revocable scope:\n%s", s)
	}
}

func TestCeilingNotWiderThan(t *testing.T) {
	d, err := autodomain.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	prev := d.Authority.Ceiling
	same := *prev
	if !same.NotWiderThan(prev) {
		t.Error("the same ceiling is wider")
	}
	more := *prev
	more.PerDay.Grants++
	other := *prev
	other.Agents = append(slices.Clone(prev.Agents), autodomain.RefID{})
	longer := *prev
	longer.PerGrant.TTL = prev.PerGrant.TTL * 2
	for name, c := range map[string]autodomain.Ceiling{"more grants": more, "another agent": other, "longer grants": longer} {
		if c.NotWiderThan(prev) {
			t.Errorf("%s is not wider", name)
		}
	}
}

// TestD102_AbsentMinMeansOne: an absent or 0 wait_effect min and gate
// min_approvals mean 1; a negative one is refused (D102 C2).
func TestD102_AbsentMinMeansOne(t *testing.T) {
	doc := func(extra string) string {
		return strings.Replace(sample, "  - id: wait\n    step: wait_run\n    with:\n      step: launch\n    timeout: 2h\n",
			"  - id: wait\n    step: wait_effect\n    with:\n      step: launch\n      operation: payments.refund\n"+extra+"    timeout: 2h\n"+
				"  - id: ok\n    step: gate\n    with:\n      approvers:\n        roles: [automation_operator]\n      deadline: 1h\n"+
				strings.ReplaceAll(extra, "min:", "min_approvals:"), 1)
	}
	bad := func(fs []autodomain.Finding) []string {
		var out []string
		for _, f := range fs {
			if strings.HasSuffix(f.Path, "/min") || strings.HasSuffix(f.Path, "/min_approvals") {
				out = append(out, f.Path)
			}
		}
		return out
	}
	for _, extra := range []string{"", "      min: 0\n"} {
		if got := bad(validate(t, doc(extra), fakeEnv{approvers: 2})); len(got) != 0 {
			t.Errorf("%q refused: %v", extra, got)
		}
	}
	if got := bad(validate(t, doc("      min: -1\n"), fakeEnv{approvers: 2})); len(got) != 2 {
		t.Errorf("negative minimums: %v", got)
	}
	if (autodomain.WaitEffectWith{}).Effects() != 1 || (autodomain.GateWith{}).Approvals() != 1 || (autodomain.GateWith{MinApprovals: 2}).Approvals() != 2 {
		t.Error("absent minimums are not 1")
	}
}

// TestD102_RevocableWithin: a replacement that widens revocable is wider
// (D102 L4).
func TestD102_RevocableWithin(t *testing.T) {
	a, b := autodomain.RefID{}, autodomain.RefID(ids.NewV7())
	agents := &autodomain.AgentScope{Agents: []autodomain.RefID{a}}
	all := &autodomain.AgentScope{All: true}
	for name, tc := range map[string]struct {
		s, prev *autodomain.AgentScope
		want    bool
	}{
		"absent":         {nil, agents, true},
		"same":           {agents, agents, true},
		"agents in all":  {agents, all, true},
		"all over list":  {all, agents, false},
		"another agent":  {&autodomain.AgentScope{Agents: []autodomain.RefID{a, b}}, agents, false},
		"new revocation": {agents, nil, false},
	} {
		if got := tc.s.Within(tc.prev); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	d, err := autodomain.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	wider := d.Authority
	wider.Revocable = all
	if wider.NotWiderThan(d.Authority) || !d.Authority.NotWiderThan(d.Authority) {
		t.Error("Authority.NotWiderThan ignores revocable")
	}
}
