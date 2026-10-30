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

// scheduledRefund is the v2 refund on a schedule, branching on guard.
func scheduledRefund(t *testing.T, guard string) *autodomain.Definition {
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
	doc = strings.Replace(doc, `trigger.params.ticket != "T-0"`, guard, 1)
	doc = strings.Replace(doc, `task_ref: "ticket {{params.ticket}}"`, "task_ref: hourly", 1)
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
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
