// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// D35: an hourly schedule replayed over two days fires 48 times; the
// launch's per-day grant cap refuses what exceeds it in the prospective
// steps and the forecast; the hourly cap is applied.
func TestReplaySchedule(t *testing.T) {
	doc := strings.Replace(sample, `  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:
      ticket:
        from: /ticket/id
        type: string
        pattern: "T-[0-9]{1,10}"
`, `  schedule:
    cron: "0 * * * *"
    timezone: UTC
`, 1)
	doc = strings.Replace(doc, `task_ref: "ticket {{params.ticket}}"`, `task_ref: "hourly"`, 1)
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := assurance.Replay(context.Background(), d, assurance.History{Approvers: 2}, from, from.Add(48*time.Hour))
	if len(r.Days) != 2 || r.Days[0].WouldFire != 24 || r.Days[1].WouldFire != 24 {
		t.Fatalf("days %+v", r.Days)
	}
	if r.Forecast.ExecutionsPerDay != 24 || r.Forecast.GrantsPerDay != 5 || r.Forecast.EligibleApprovers != 2 {
		t.Errorf("forecast %+v", r.Forecast)
	}
	if len(r.Samples) == 0 || len(r.Samples) > 50 {
		t.Fatalf("%d samples", len(r.Samples))
	}
	refused := 0
	for _, s := range r.Samples {
		if s.Steps[0].Kind == "launch_run" && s.Steps[0].Reason == "USAGE_EXCEEDED" {
			refused++
		}
	}
	if refused == 0 {
		t.Error("no sample shows the per-day grant cap")
	}
	if r.Missing[assurance.MissingIssuancePreview] != 48 {
		t.Errorf("missing %v", r.Missing)
	}
}

// D35, HR-288: an inbound trigger replays only receipts that are kept and
// says that their parameters and older days cannot be evaluated; a manual
// trigger is never replayed.
func TestHR288_SimulationReportsWhatItCannotEvaluate(t *testing.T) {
	d := parse(t)
	src := d.When.Inbound.Source.UUID()
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	from := now.Add(-10 * 24 * time.Hour)
	h := assurance.History{
		ReceiptsFrom: now.Add(-7 * 24 * time.Hour),
		Receipts: []assurance.Receipt{
			{Source: src, Type: "ticket.created", At: now.Add(-time.Hour)},
			{Source: src, Type: "ticket.updated", At: now.Add(-time.Hour)},
			{Source: ids.NewV7(), Type: "ticket.created", At: now.Add(-time.Hour)},
		},
	}
	r := assurance.Replay(context.Background(), d, h, from, now)
	total := 0
	for _, day := range r.Days {
		total += day.WouldFire
	}
	if total != 1 || r.Missing[assurance.MissingParams] != 1 || r.Missing[assurance.MissingReceipts] != 3 {
		t.Errorf("fires %d, missing %v", total, r.Missing)
	}
	d.When.Inbound, d.When.Manual = nil, &autodomain.ManualWhen{}
	if r := assurance.Replay(context.Background(), d, assurance.History{Events: []feed.Event{{}}}, from, now); r.Missing[assurance.MissingManual] != 1 {
		t.Errorf("manual: %v", r.Missing)
	}
}

// D94 S5, S6: a launch the dry-run issuance refuses is refused in every
// sample, counts no grant, and the ceiling-only note is gone; each sample
// names the agents it involves.
func TestReplayUsesTheIssuancePreview(t *testing.T) {
	doc := strings.Replace(sample, `  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:
      ticket:
        from: /ticket/id
        type: string
        pattern: "T-[0-9]{1,10}"
`, `  schedule:
    cron: "0 * * * *"
    timezone: UTC
`, 1)
	doc = strings.Replace(doc, `task_ref: "ticket {{params.ticket}}"`, `task_ref: "hourly"`, 1)
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	h := assurance.History{Issuance: map[string]assurance.IssueDecision{"launch": {Refused: true, Reason: "AGENT_NOT_ELIGIBLE"}}}
	r := assurance.Replay(context.Background(), d, h, from, from.Add(24*time.Hour))
	if _, ok := r.Missing[assurance.MissingIssuancePreview]; ok {
		t.Errorf("missing %v", r.Missing)
	}
	if r.Forecast.GrantsPerDay != 0 {
		t.Errorf("a refused launch forecasts %v grants a day", r.Forecast.GrantsPerDay)
	}
	if len(r.Samples) == 0 {
		t.Fatal("no samples")
	}
	for _, s := range r.Samples {
		if s.Steps[0].Decision != "REFUSED" || s.Steps[0].Reason != "AGENT_NOT_ELIGIBLE" {
			t.Fatalf("launch step %+v", s.Steps[0])
		}
		if len(s.Agents) != 1 {
			t.Fatalf("sample agents %v", s.Agents)
		}
	}
}

// D94 S7: a threshold replays the trigger path's sliding window: three
// runs ending within ten minutes fire whenever the window holds three,
// once per ten-minute bucket, not only within one fixed bucket.
func TestReplayThresholdSlidingWindow(t *testing.T) {
	doc := strings.Replace(sample, `  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:
      ticket:
        from: /ticket/id
        type: string
        pattern: "T-[0-9]{1,10}"
`, `  threshold:
    on: run.ended
    over: 10m
    at_least: 3
`, 1)
	doc = strings.Replace(doc, `task_ref: "ticket {{params.ticket}}"`, `task_ref: "burst"`, 1)
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var h assurance.History
	for _, m := range []int{0, 4, 8, 12, 25} {
		h.Events = append(h.Events, feed.Event{ID: ids.NewV7(), Kind: "audit.run.ended", OccurredAt: from.Add(time.Duration(m) * time.Minute)})
	}
	r := assurance.Replay(context.Background(), d, h, from, from.Add(time.Hour))
	if len(r.Days) != 1 || r.Days[0].WouldFire != 2 {
		t.Fatalf("days %+v, missing %v", r.Days, r.Missing)
	}
}

// D107 A4: a threshold sample lists the agents of every event its window
// counts; over 64 it lists none and no reader sees it.
func TestThresholdSampleAgents(t *testing.T) {
	doc := strings.Replace(sample, `  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:
      ticket:
        from: /ticket/id
        type: string
        pattern: "T-[0-9]{1,10}"
`, `  threshold:
    on: run.ended
    over: 10m
    at_least: 3
`, 1)
	doc = strings.Replace(doc, `task_ref: "ticket {{params.ticket}}"`, `task_ref: "burst"`, 1)
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	events := func(n int) assurance.History {
		var h assurance.History
		for i := range n {
			h.Events = append(h.Events, feed.Event{
				ID: ids.NewV7(), Kind: "audit.run.ended", OccurredAt: from.Add(time.Duration(i) * time.Second),
				Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: ids.NewV7().String()}},
			})
		}
		return h
	}
	r := assurance.Replay(context.Background(), d, events(3), from, from.Add(time.Hour))
	if len(r.Samples) != 1 || len(r.Samples[0].Agents) != 4 { // three events' agents and the launch's
		t.Fatalf("samples %+v", r.Samples)
	}
	h := events(70)
	d.When.Threshold.AtLeast = 70
	r = assurance.Replay(context.Background(), d, h, from, from.Add(time.Hour))
	if len(r.Samples) != 1 || len(r.Samples[0].Agents) != 1 || r.Samples[0].Agents[0] != assurance.AgentsOverflow ||
		r.Samples[0].Note != assurance.NoteTooManyAgents {
		t.Fatalf("overflow samples %+v", r.Samples)
	}
}
