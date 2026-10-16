// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance_test

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var start = time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)

func run(t *testing.T, d *autodomain.Definition, c assurance.Case) assurance.CaseResult {
	t.Helper()
	r, err := assurance.RunCase(context.Background(), d, ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), c, start)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var ticket = assurance.CaseTrigger{Params: map[string]string{"ticket": "T-42"}}

func done(evidence bool) []assurance.StubResult {
	return []assurance.StubResult{{State: "DONE", Effect: "CHANGED", Evidence: evidence}}
}

// HR-287: the required kinds run through the engine's Machine: a normal
// run succeeds only with evidence, a refused launch fails, a wait past its
// timeout after a launch leaves it partially completed, and a duplicate
// passes only when a second delivery with the same parameters would start
// no execution (a declared dedupe key).
func TestHR287_CasesRunThroughTheEngine(t *testing.T) {
	d := parse(t)
	normal := assurance.Case{
		Name: "normal", Kind: assurance.CaseNormal, Trigger: ticket,
		Stubs:  map[string][]assurance.StubResult{"launch": done(false), "wait": done(true)},
		Expect: assurance.Expect{State: "SUCCEEDED", Steps: map[string]string{"launch": "DONE", "wait": "DONE"}},
	}
	if r := run(t, d, normal); !r.Passed {
		t.Errorf("normal: %v", r.Differences)
	}
	noEvidence := normal
	noEvidence.Stubs = map[string][]assurance.StubResult{"launch": done(false), "wait": done(false)}
	if r := run(t, d, noEvidence); r.Passed || r.State == "SUCCEEDED" {
		t.Errorf("success without evidence: %+v", r)
	}
	denied := assurance.Case{
		Name: "denied", Kind: assurance.CaseDenied, Trigger: ticket,
		Stubs:  map[string][]assurance.StubResult{"launch": {{State: "FAILED", Reason: "OUTSIDE_CEILING"}}},
		Expect: assurance.Expect{State: "FAILED", Steps: map[string]string{"launch": "FAILED"}},
	}
	if r := run(t, d, denied); !r.Passed {
		t.Errorf("denied: %v (%s %s)", r.Differences, r.State, r.Reason)
	}
	timeout := assurance.Case{
		Name: "timeout", Kind: assurance.CaseTimeout, Trigger: ticket,
		Stubs:  map[string][]assurance.StubResult{"launch": done(false), "wait": {{State: "WAITING"}}},
		Expect: assurance.Expect{State: "PARTIALLY_COMPLETED", Reason: "TIMEOUT", Steps: map[string]string{"wait": "FAILED"}},
	}
	if r := run(t, d, timeout); !r.Passed {
		t.Errorf("timeout: %v (%s %s)", r.Differences, r.State, r.Reason)
	} else if r.Elapsed.D() < 2*time.Hour {
		t.Errorf("timeout elapsed %s, want the 2h step timeout", r.Elapsed.D())
	}
	dup := normal
	dup.Name, dup.Kind = "dup", assurance.CaseDuplicate
	if r := run(t, d, dup); r.Passed || r.DuplicateRefused {
		t.Errorf("no dedupe key, yet a second delivery is refused: %+v", r)
	}
	keyed := parse(t)
	keyed.When.Dedupe = &autodomain.Dedupe{Key: "{{params.ticket}}", Window: autodomain.Duration(24 * time.Hour)}
	if r := run(t, keyed, dup); !r.Passed || !r.DuplicateRefused {
		t.Errorf("declared key: %+v", r)
	}
	bad := normal
	bad.Trigger = assurance.CaseTrigger{Params: map[string]string{"ticket": "DROP TABLE"}}
	if r := run(t, d, bad); r.Passed || r.State != "REFUSED_INVALID" {
		t.Errorf("a parameter outside its pattern ran: %+v", r)
	}
}
