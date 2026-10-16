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
func TestReplayInboundAndManual(t *testing.T) {
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
