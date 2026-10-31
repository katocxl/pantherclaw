// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

func refundDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/v2_refund.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var irreversibleRefund = fakeEnv{irreversible: map[string]bool{"payments.refund": true}, approvers: 1}

func replaced(t *testing.T, doc, from, to string) string {
	t.Helper()
	if !strings.Contains(doc, from) {
		t.Fatalf("the document has no %q", from)
	}
	return strings.Replace(doc, from, to, 1)
}

func wantCode(t *testing.T, doc string, env fakeEnv, code string) {
	t.Helper()
	if got := codes(validate(t, doc, env)); !slices.Contains(got, code) {
		t.Fatalf("codes %v lack %s", got, code)
	}
}

// TestV2ValidDefinitions: the fixtures pass, irreversible operations too.
//
// Covers: F678
func TestV2ValidDefinitions(t *testing.T) {
	if fs := validate(t, routeDoc(t), fakeEnv{approvers: 1}); autodomain.HasErrors(fs) {
		t.Errorf("route: %+v", fs)
	}
	if fs := validate(t, refundDoc(t), irreversibleRefund); autodomain.HasErrors(fs) {
		t.Errorf("refund: %+v", fs)
	}
}

// TestHR531_CyclesAndUnreachableNodesAreRefused: every loop, every node
// nothing leads to.
//
// Covers: F678
func TestHR531_CyclesAndUnreachableNodesAreRefused(t *testing.T) {
	const wait = "    step: wait\n    with:\n      duration: 1m\n"
	t.Run("cycle", func(t *testing.T) {
		doc := replaced(t, refundDoc(t), "    next: refunded\n", "    next: size\n")
		wantCode(t, doc, irreversibleRefund, autodomain.CodeCycle)
	})
	t.Run("a self loop", func(t *testing.T) {
		doc := replaced(t, refundDoc(t), "    next: refunded\n", "    next: confirm\n")
		wantCode(t, doc, irreversibleRefund, autodomain.CodeCycle)
	})
	t.Run("a cycle nothing reaches", func(t *testing.T) {
		doc := replaced(t, refundDoc(t), "  - id: refunded\n",
			"  - id: a\n"+wait+"    next: b\n  - id: b\n"+wait+"    next: a\n  - id: refunded\n")
		wantCode(t, doc, irreversibleRefund, autodomain.CodeCycle)
		wantCode(t, doc, irreversibleRefund, autodomain.CodeUnreachableNode)
	})
	t.Run("unreachable", func(t *testing.T) {
		doc := replaced(t, refundDoc(t), "  - id: refunded\n", "  - id: hidden\n"+wait+"    next: filed\n  - id: refunded\n")
		wantCode(t, doc, irreversibleRefund, autodomain.CodeUnreachableNode)
	})
}

// TestV2GraphFindings: each remaining graph code fires on what earns it.
//
// Covers: F678
func TestV2GraphFindings(t *testing.T) {
	route, refund := routeDoc(t), refundDoc(t)
	for _, tc := range []struct{ name, doc, code string }{
		{"a path without a terminal", replaced(t, refund, "    next: filed\n", ""), autodomain.CodePathNotTerminated},
		{"next to nothing", replaced(t, refund, "    next: filed\n", "    next: gone\n"), autodomain.CodePathNotTerminated},
		{"no default", replaced(t, route, "      default: record\n", ""), autodomain.CodeSwitchNoDefault},
		{"repeated case", replaced(t, route, `trigger.params.env == "staging"`, `trigger.params.env == "prod"`), autodomain.CodeSwitchNoDefault},
		{"join misses a predecessor", replaced(t, route, "from: [tell, record]", "from: [tell]"), autodomain.CodeJoinInvalid},
		{"join names a stranger", replaced(t, route, "from: [tell, record]", "from: [tell, record, approve]"), autodomain.CodeJoinInvalid},
		{"join all of two", replaced(t, route, "mode: ANY", "mode: ALL"), autodomain.CodeJoinInvalid},
		{"join mode", replaced(t, route, "mode: ANY", "mode: SOME"), autodomain.CodeJoinInvalid},
		{"join with nothing before it", replaced(t, route, "nodes:\n", "nodes:\n  - id: start\n    join:\n      mode: ANY\n      from: []\n    next: route\n"), autodomain.CodeJoinInvalid},
		{"terminal outcome", replaced(t, refund, "outcome: FAILED", "outcome: FINE"), autodomain.CodeTerminalMissing},
		{"finish on a request", replaced(t, refund, "condition: CASE_OPENED", "condition: EFFECT_CONFIRMED"), autodomain.CodeCompletionRequestOnly},
		{"finish on the other branch", replaced(t, refund, "      - step: file\n        condition: CASE_OPENED", "      - step: confirm\n        condition: EFFECT_CONFIRMED"), autodomain.CodeNotOnAllPaths},
		{"template from the other branch", replaced(t, refund, "title: Ticket zero", `title: "{{steps.launch.output.run_id}}"`), autodomain.CodeNotOnAllPaths},
		{"wait on the wrong kind", replaced(t, refund, "      step: launch\n      operation", "      step: file\n      operation"), autodomain.CodeLimitRange},
		{"guard reads the other branch", replaced(t, refund, "    step: open_case\n    with:\n      title", "    step: open_case\n    when: steps.launch.output.run_id != \"\"\n    with:\n      title"), autodomain.CodeNotOnAllPaths},
		{"not a guard", replaced(t, refund, `trigger.params.ticket != "T-0"`, "trigger.params.ticket +"), autodomain.CodeLimitRange},
		{"compensation names no node", replaced(t, refund, "compensates: launch", "compensates: gone"), autodomain.CodeLimitRange},
		{"compensation needs a node", replaced(t, refund, "      compensates: launch\n", ""), autodomain.CodeLimitRange},
		{"compensation of a wait", replaced(t, refund, "compensates: launch", "compensates: confirm"), autodomain.CodeLimitRange},
		{"two nodes one id", replaced(t, refund, "id: filed", "id: refunded"), autodomain.CodeLimitRange},
	} {
		t.Run(tc.name, func(t *testing.T) { wantCode(t, tc.doc, irreversibleRefund, tc.code) })
	}
}

// TestV2Bounds: 40 nodes, 64 paths, depth 20.
//
// Covers: F678
func TestV2Bounds(t *testing.T) {
	head, _, _ := strings.Cut(routeDoc(t), "nodes:\n")
	const end = "  - id: open\n    step: open_case\n    with:\n      title: t\n    next: end\n" +
		"  - id: end\n    outcome: FAILED\n    finish_when:\n      - step: open\n        condition: CASE_OPENED\n"
	env := fakeEnv{approvers: 1}
	chain := func(n int) string {
		var b strings.Builder
		b.WriteString(head + "nodes:\n")
		for i := range n {
			next := fmt.Sprintf("n%d", i+1)
			if i == n-1 {
				next = "open"
			}
			fmt.Fprintf(&b, "  - id: n%d\n    step: wait\n    with:\n      duration: 1m\n    next: %s\n", i, next)
		}
		return b.String() + end
	}
	if fs := validate(t, chain(19), env); autodomain.HasErrors(fs) {
		t.Fatalf("depth 20: %+v", fs)
	}
	wantCode(t, chain(20), env, autodomain.CodeLimitRange)
	wantCode(t, chain(41), env, autodomain.CodeLimitRange)

	// Seven branches in a row make 128 paths in 23 nodes.
	var b strings.Builder
	b.WriteString(head + "nodes:\n")
	for i := range 7 {
		fmt.Fprintf(&b, "  - id: b%d\n    branch:\n      when: trigger.params.env == \"p%d\"\n      then: w%d\n      else: j%d\n", i, i, i, i)
		fmt.Fprintf(&b, "  - id: w%d\n    step: wait\n    with:\n      duration: 1m\n    next: j%d\n", i, i)
		next := fmt.Sprintf("b%d", i+1)
		if i == 6 {
			next = "open"
		}
		fmt.Fprintf(&b, "  - id: j%d\n    join:\n      mode: ANY\n      from: [b%d, w%d]\n    next: %s\n", i, i, i, next)
	}
	wantCode(t, b.String()+end, env, autodomain.CodeLimitRange)
}

// TestHR532_AuthorityHoldsOnEveryPath: each path alone carries its waits
// and stays inside the ceiling, whatever the whole definition shows.
//
// Covers: F678
func TestHR532_AuthorityHoldsOnEveryPath(t *testing.T) {
	refund := refundDoc(t)
	const launch = "    step: launch_run\n    with:\n      agent: 0192f000-0000-7000-8000-000000000003\n"
	again := "    next: again\n  - id: again\n" + launch + "    next: confirm\n"
	t.Run("an irreversible launch on a path without its wait", func(t *testing.T) {
		// A wait exists, so the whole-definition check passes: it is on the
		// other branch.
		doc := replaced(t, refund, "      else: file\n", "      else: late\n")
		doc = replaced(t, doc, "  - id: file\n", "  - id: late\n"+launch+"    next: file\n  - id: file\n")
		wantCode(t, doc, irreversibleRefund, autodomain.CodeIrreversibleUnwaitedOnPath)
		if slices.Contains(codes(validate(t, doc, irreversibleRefund)), autodomain.CodeIrreversibleUnreconciled) {
			t.Error("the whole-definition check refused it: this test no longer needs the per-path one")
		}
	})
	t.Run("a guarded wait may be skipped", func(t *testing.T) {
		doc := replaced(t, refund, "    step: wait_effect\n", "    step: wait_effect\n    when: trigger.params.ticket != \"T-1\"\n")
		wantCode(t, doc, irreversibleRefund, autodomain.CodeIrreversibleUnwaitedOnPath)
	})
	t.Run("a launch outside the ceiling on one branch", func(t *testing.T) {
		doc := replaced(t, refund, "      agent: 0192f000-0000-7000-8000-000000000003\n      task_ref", "      agent: 0192f000-0000-7000-8000-000000000009\n      task_ref")
		wantCode(t, doc, irreversibleRefund, autodomain.CodePathOutsideCeiling)
	})
	t.Run("more launches on a path than grants a day", func(t *testing.T) {
		doc := replaced(t, refund, "grants: 5", "grants: 1")
		doc = replaced(t, doc, "    next: confirm\n", again)
		wantCode(t, doc, fakeEnv{approvers: 1}, autodomain.CodePathOutsideCeiling)
	})
	t.Run("two launches each need their own wait", func(t *testing.T) {
		wantCode(t, replaced(t, refund, "    next: confirm\n", again), irreversibleRefund, autodomain.CodeIrreversibleUnwaitedOnPath)
	})
	t.Run("the whole-definition check stays", func(t *testing.T) {
		doc := replaced(t, refund, "    - step: open_case\n", "")
		wantCode(t, doc, irreversibleRefund, autodomain.CodeUnsupportedCapability)
		wantCode(t, doc, irreversibleRefund, autodomain.CodePathOutsideCeiling)
	})
}

// TestT230_BranchesHideNothing: every step counts for the whole-definition
// readers, on whichever branch it hides.
//
// Covers: F678
func TestT230_BranchesHideNothing(t *testing.T) {
	d, err := autodomain.Parse([]byte(refundDoc(t)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{autodomain.KindLaunchRun, autodomain.KindOpenCase, autodomain.KindRevokeGrant, autodomain.KindWaitEffect}
	slices.Sort(want)
	if got := d.Kinds(); !slices.Equal(got, want) {
		t.Errorf("kinds %v", got)
	}
	if got := d.RequiredConfirmerPermissions(); len(got.Agents) == 0 {
		t.Errorf("confirmers %+v: the branch's launch is not counted", got)
	}
	doc := replaced(t, refundDoc(t), "    - step: revoke_grant\n      scopes: [EXECUTION]\n", "")
	wantCode(t, doc, irreversibleRefund, autodomain.CodeUnsupportedCapability)
}
