// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	exdomain "github.com/katocxl/pantherclaw/internal/exposure/domain"
)

// scheduledDoc is the v2 refund document on a schedule.
func scheduledDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../domain/testdata/v2_refund.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, rest, ok := strings.Cut(string(b), "when:\n  inbound:")
	_, rest, ok2 := strings.Cut(rest, "authority:\n")
	if !ok || !ok2 {
		t.Fatal("the fixture changed")
	}
	doc += "when:\n  schedule:\n    cron: \"0 * * * *\"\n    timezone: UTC\nauthority:\n" + rest
	return strings.Replace(doc, `task_ref: "ticket {{params.ticket}}"`, "task_ref: hourly", 1)
}

func parseDoc(t *testing.T, doc string) *autodomain.Definition {
	t.Helper()
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// scheduledRefund is the v2 refund on a schedule, branching on guard.
func scheduledRefund(t *testing.T, guard string) *autodomain.Definition {
	t.Helper()
	return parseDoc(t, strings.Replace(scheduledDoc(t), `trigger.params.ticket != "T-0"`, guard, 1))
}

// scheduledNodes is the refund on a schedule with its nodes replaced.
func scheduledNodes(t *testing.T, nodes string) *autodomain.Definition {
	t.Helper()
	head, rest, ok := strings.Cut(scheduledDoc(t), "nodes:\n")
	_, tail, ok2 := strings.Cut(rest, "if_fails:\n")
	if !ok || !ok2 {
		t.Fatal("the fixture changed")
	}
	return parseDoc(t, head+"nodes:\n"+nodes+"if_fails:\n"+tail)
}

func replaySteps(t *testing.T, d *autodomain.Definition) []assurance.SimStep {
	t.Helper()
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := assurance.Replay(context.Background(), d, assurance.History{Approvers: 1}, from, from.Add(2*time.Hour))
	if len(r.Samples) == 0 {
		t.Fatal("no samples")
	}
	return r.Samples[0].Steps
}

func simIDs(steps []assurance.SimStep) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.ID)
	}
	return out
}

// TestReplayShowsBothBranchesOfAnUnevaluableGuard: history keeps no
// parameters, so a guard on them is UNEVALUABLE and both ways out are shown,
// each with its branch (D301, HR-288).
//
// Covers: F678
func TestReplayShowsBothBranchesOfAnUnevaluableGuard(t *testing.T) {
	steps := replaySteps(t, scheduledRefund(t, `trigger.params.ticket != "T-0"`))
	if !slices.Equal(simIDs(steps), []string{"size", "launch", "confirm", "file"}) {
		t.Fatalf("steps %+v", steps)
	}
	if steps[0].Decision != "UNEVALUABLE" || steps[0].Reason != "GUARD" {
		t.Errorf("guard %+v", steps[0])
	}
	if steps[1].Branch != "size then" || steps[3].Branch != "size else" {
		t.Errorf("branches %+v", steps)
	}
}

// TestReplayNeverGuessesAGuardOnWhatHistoryLacks: a guard reading parameters
// or steps is not evaluated, even where empty values would give an answer.
//
// Covers: F678
func TestReplayNeverGuessesAGuardOnWhatHistoryLacks(t *testing.T) {
	for _, guard := range []string{
		`has(trigger.params.ticket)`,
		`trigger.kind != "" && "ticket" in trigger.params`,
		`size(steps) == 0`,
		`size(trigger) > 0`,
		`trigger.kind == "MANUAL" || has(trigger.params.ticket)`,
	} {
		t.Run(guard, func(t *testing.T) {
			steps := replaySteps(t, scheduledRefund(t, guard))
			if !slices.Equal(simIDs(steps), []string{"size", "launch", "confirm", "file"}) || steps[0].Decision != "UNEVALUABLE" {
				t.Fatalf("steps %+v", steps)
			}
		})
	}
}

// TestOpenBranchesShareOneGrant: one would-be execution behind an open guard
// takes one grant of the day's count, however many ways out launch.
//
// Covers: F678
func TestOpenBranchesShareOneGrant(t *testing.T) {
	d := scheduledRefund(t, `trigger.params.ticket != "T-0"`)
	file := d.Flow().Node("file")
	launch := d.Flow().Node("launch")
	if file == nil || launch == nil {
		t.Fatal("the fixture changed")
	}
	file.Step, file.With = launch.Step, launch.With
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := assurance.Replay(context.Background(), d, assurance.History{Approvers: 1}, from, from.Add(2*time.Hour))
	if r.Forecast.ExecutionsPerDay == 0 || r.Forecast.GrantsPerDay != r.Forecast.ExecutionsPerDay {
		t.Fatalf("forecast %+v", r.Forecast)
	}
	for _, s := range r.Samples {
		for _, st := range s.Steps {
			if st.Reason == "USAGE_EXCEEDED" {
				t.Errorf("sample %+v", s)
			}
		}
	}
}

// launchNode is a launch_run node.
func launchNode(id, next string) string {
	return "  - id: " + id + "\n    step: launch_run\n    with:\n      agent: 0192f000-0000-7000-8000-000000000003\n      task_ref: hourly\n    next: " + next + "\n"
}

// TestReplayCountsEveryLaunchOnThePath: launches one after another on a path
// each take a grant, on a branch and past a join, and a launch is judged by
// the path that brings the most (D320).
//
// Covers: F678
func TestReplayCountsEveryLaunchOnThePath(t *testing.T) {
	const file = "  - id: file\n    step: open_case\n    with:\n      title: Ticket zero\n    next: "
	const meet = "  - id: meet\n    join:\n      mode: ANY\n      from: [launch, file]\n    next: again\n"
	const ends = "  - id: done\n    outcome: SUCCEEDED\n    finish_when:\n      - step: again\n        condition: RUN_ENDED\n" +
		"  - id: filed\n    outcome: FAILED\n    finish_when:\n      - step: file\n        condition: CASE_OPENED\n"
	route := func(then, els string) string {
		return "  - id: size\n    branch:\n      when: trigger.params.ticket != \"T-0\"\n      then: " + then + "\n      else: " + els + "\n"
	}
	for name, nodes := range map[string]string{
		"in sequence on a branch":                route("launch", "file") + launchNode("launch", "again") + launchNode("again", "done") + file + "filed\n" + ends,
		"after a join, the launching arm first":  route("launch", "file") + launchNode("launch", "meet") + file + "meet\n" + meet + launchNode("again", "done") + ends,
		"after a join, the launching arm second": route("file", "launch") + launchNode("launch", "meet") + file + "meet\n" + meet + launchNode("again", "done") + ends,
	} {
		t.Run(name, func(t *testing.T) {
			from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
			r := assurance.Replay(context.Background(), scheduledNodes(t, nodes), assurance.History{Approvers: 1}, from, from.Add(2*time.Hour))
			if r.Forecast.ExecutionsPerDay == 0 || r.Forecast.GrantsPerDay != 2*r.Forecast.ExecutionsPerDay {
				t.Fatalf("forecast %+v", r.Forecast)
			}

			d := scheduledNodes(t, nodes)
			d.Authority.Ceiling.PerDay.Grants = 1
			steps := replaySteps(t, d)
			if n := slices.Index(simIDs(steps), "again"); n < 0 || steps[n].Decision != "REFUSED" || steps[n].Reason != "USAGE_EXCEEDED" {
				t.Fatalf("steps %+v", steps)
			}
			if n := slices.Index(simIDs(steps), "launch"); n < 0 || steps[n].Decision != "ALLOWED" {
				t.Fatalf("steps %+v", steps)
			}
			if !slices.Equal(simIDs(steps), slices.Compact(slices.Clone(simIDs(steps)))) {
				t.Errorf("a node listed twice: %+v", steps)
			}
		})
	}
}

// TestReplayFollowsAGuardItCanEvaluate: a guard on what history keeps takes
// one way out, and the other branch is not shown.
//
// Covers: F678
func TestReplayFollowsAGuardItCanEvaluate(t *testing.T) {
	steps := replaySteps(t, scheduledRefund(t, `trigger.kind == "MANUAL"`))
	if !slices.Equal(simIDs(steps), []string{"file"}) || steps[0].Branch != "" {
		t.Fatalf("steps %+v", steps)
	}
}

// TestInspectListsEveryPath: inspection shows each path and its outcome, and
// a step on any branch.
//
// Covers: F678
func TestInspectListsEveryPath(t *testing.T) {
	in := assurance.Inspect(scheduledRefund(t, `trigger.kind == "MANUAL"`), exdomain.Inputs{})
	if len(in.Paths) != 2 {
		t.Fatalf("paths %+v", in.Paths)
	}
	if !slices.Equal(in.Paths[0].Nodes, []string{"size", "launch", "confirm", "refunded"}) || in.Paths[0].Outcome != "SUCCEEDED" {
		t.Errorf("path %+v", in.Paths[0])
	}
	if in.Paths[1].Outcome != "FAILED" {
		t.Errorf("path %+v", in.Paths[1])
	}
	if !slices.ContainsFunc(in.Steps, func(s assurance.InspectedStep) bool { return s.ID == "launch" }) {
		t.Errorf("steps %+v", in.Steps)
	}
}
