// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"context"
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
}

func (fakeEnv) Now() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }
func (fakeEnv) OwnerActivePerson(context.Context, ids.UUID) (bool, error) {
	return true, nil
}
func (fakeEnv) AgentGrantable(context.Context, ids.UUID) (bool, error) { return true, nil }
func (e fakeEnv) Operation(_ context.Context, op string) (autodomain.OperationInfo, error) {
	return autodomain.OperationInfo{Known: true, Irreversible: e.irreversible[op], ConsumesBudget: e.budget[op]}, nil
}
func (fakeEnv) DestinationActive(context.Context, ids.UUID, string) (bool, error) { return true, nil }
func (e fakeEnv) EligibleApprovers(context.Context, autodomain.GateWith, ids.UUID) (int, error) {
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
		{"irreversible without wait_effect", "", "", autodomain.CodeIrreversibleUnreconciled,
			fakeEnv{irreversible: map[string]bool{"payments.refund": true}, approvers: 1}},
		{"budget without per-grant budget", "", "", autodomain.CodeCeilingUnbounded,
			fakeEnv{budget: map[string]bool{"payments.refund": true}, approvers: 1}},
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
	if !slices.Equal(got.AgentPaths, []string{"grant.issue", "run.start"}) || len(got.Org) != 0 {
		t.Errorf("confirmer permissions %+v", got)
	}
}
