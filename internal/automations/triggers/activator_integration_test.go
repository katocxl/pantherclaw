// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package triggers

import (
	"context"
	"slices"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type harness struct {
	f   *triggerstest.Fixture
	st  *triggerstest.Starter
	svc *Service
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	f := triggerstest.New(t)
	st := &triggerstest.Starter{}
	return &harness{f: f, st: st, svc: New(Deps{Pool: f.Pool, Starter: st, Editions: triggerstest.Team})}
}

// fire fires one manual-like candidate for a with base key key.
func (h *harness) fire(t *testing.T, a triggerstest.Automation, key string, params map[string]autodomain.Value, lin Lineage) Outcome {
	t.Helper()
	var out Outcome
	h.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		au, err := h.svc.loadAutomation(ctx, dbq.New(tx), h.f.Org, a.ID)
		if err != nil {
			return err
		}
		out, err = h.svc.Fire(ctx, tx, Candidate{
			Automation: au, Kind: autodomain.TriggerManual, Authenticity: autodomain.AuthUserSession,
			Params: params, BaseKey: key, Lineage: lin, QueueOK: true,
		})
		return err
	})
	return out
}

func (h *harness) activator(t *testing.T, fn func(ctx context.Context, act Activator, tx db.TenantTx) error) {
	t.Helper()
	h.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error { return fn(ctx, h.svc.Activator(), tx) })
}

// TestActivator_SchedulesFollowTheEnabledVersion: Activate materializes
// the next occurrence in the zone, Deactivate pauses it and Resume
// restarts it from now (a missed SKIP occurrence never fires).
func TestActivator_SchedulesFollowTheEnabledVersion(t *testing.T) {
	h := newHarness(t)
	f := h.f
	def := f.Definition(`"schedule":{"cron":"30 1 * * *","timezone":"Europe/London"}`, "")
	a := f.Automation(t, "nightly", def, autodomain.RolloutFull)
	h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
		return act.Activate(ctx, tx.Pgx(), a.ID, a.Version)
	})
	var next time.Time
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		s, err := dbq.New(tx).GetAutomationSchedule(ctx, f.Org, a.ID)
		if err != nil {
			return err
		}
		if s.State != "ACTIVE" || s.NextFireAt == nil || s.Cron != "30 1 * * *" {
			t.Fatalf("schedule: %+v", s)
		}
		next = *s.NextFireAt
		return nil
	})
	lon, _ := time.LoadLocation("Europe/London")
	if l := next.In(lon); l.Hour() != 1 || l.Minute() != 30 || !next.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("next fire %v (%v)", next, l)
	}
	h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
		return act.Deactivate(ctx, tx.Pgx(), a.ID, autodomain.PausedDiscard)
	})
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_schedules WHERE org_id = $1 AND state = 'PAUSED'"); n != 1 {
		t.Fatalf("paused schedules: %d", n)
	}
	// A due occurrence while paused is not replayed on resume (SKIP).
	f.Exec(t, "UPDATE pc.automation_schedules SET next_fire_at = now() - interval '3 hours' WHERE org_id = $1", f.Org)
	h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
		_, err := act.Resume(ctx, tx.Pgx(), a.ID)
		return err
	})
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_schedules WHERE org_id = $1 AND state = 'ACTIVE' AND next_fire_at > now()"); n != 1 {
		t.Fatal("resume did not restart the schedule from now")
	}
	// A version without a schedule removes it.
	v2 := f.NewVersion(t, a, f.Definition(`"manual":{}`, ""))
	h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
		return act.Activate(ctx, tx.Pgx(), a.ID, v2)
	})
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_schedules WHERE org_id = $1"); n != 0 {
		t.Fatalf("schedules after a manual version: %d", n)
	}
	// Activate refuses a version of another automation.
	b := f.Automation(t, "other", f.Definition(`"manual":{}`, ""), autodomain.RolloutFull)
	if err := f.Pool.InTenantTx(context.Background(), f.Org, func(ctx context.Context, tx db.TenantTx) error {
		return h.svc.Activator().Activate(ctx, tx.Pgx(), a.ID, b.Version)
	}); err == nil {
		t.Fatal("activated a foreign version")
	}
}

// TestHR278_PausedAutomationsFollowTheirPolicy: DISCARD discards, QUEUE
// queues (up to queue_max) and Resume replays through the Starter; a
// trigger queued for an earlier version expires (VERSION_CHANGED, D58).
func TestHR278_PausedAutomationsFollowTheirPolicy(t *testing.T) {
	h := newHarness(t)
	f := h.f
	disc := f.Automation(t, "discard", f.Definition(`"manual":{}`, ""), autodomain.RolloutFull)
	f.Pause(t, disc)
	if out := h.fire(t, disc, "manual:d1", nil, Lineage{}); out.State != StateDiscarded || out.Reason != ReasonPaused {
		t.Fatalf("DISCARD: %+v", out)
	}

	q := f.Automation(t, "queue", f.Definition(`"manual":{}`, `"paused_triggers":"QUEUE","queue_max":2`), autodomain.RolloutFull)
	f.Pause(t, q)
	for i, want := range []State{StateQueued, StateQueued, StateDiscarded} {
		out := h.fire(t, q, "manual:q"+string(rune('a'+i)), nil, Lineage{})
		if out.State != want {
			t.Fatalf("QUEUE #%d: %+v, want %s", i, out, want)
		}
	}
	// A duplicate of a queued trigger is refused while it waits.
	if out := h.fire(t, q, "manual:qa", nil, Lineage{}); out.State != StateRefusedDuplicate {
		t.Fatalf("duplicate of a queued trigger: %+v", out)
	}
	if h.st.Count() != 0 {
		t.Fatal("a paused automation started work")
	}
	f.Unpause(t, q)
	var replayed int
	h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
		var err error
		replayed, err = act.Resume(ctx, tx.Pgx(), q.ID)
		return err
	})
	if replayed != 2 || h.st.Count() != 2 {
		t.Fatalf("replayed %d, starts %d", replayed, h.st.Count())
	}
	if got := f.States(t, q); !slices.Equal(got, []string{"ACCEPTED", "ACCEPTED", "DISCARDED", "REFUSED_DUPLICATE"}) {
		t.Fatalf("states: %v", got)
	}

	// Queued for v1, resumed under v2: expired, never started.
	e := f.Automation(t, "expire", f.Definition(`"manual":{}`, `"paused_triggers":"EXPIRE"`), autodomain.RolloutFull)
	f.Pause(t, e)
	if out := h.fire(t, e, "manual:e1", nil, Lineage{}); out.State != StateQueued {
		t.Fatalf("EXPIRE queues: %+v", out)
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_triggers WHERE org_id = $1 AND automation_id = $2 AND queued_until > now() + interval '23 hours'", e.ID); n != 1 {
		t.Fatal("EXPIRE trigger has no 24 h time to live")
	}
	f.NewVersion(t, e, f.Definition(`"manual":{}`, `"paused_triggers":"EXPIRE"`))
	f.Unpause(t, e)
	before := h.st.Count()
	h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
		_, err := act.Resume(ctx, tx.Pgx(), e.ID)
		return err
	})
	if h.st.Count() != before {
		t.Fatal("a trigger of an earlier version was replayed")
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_triggers WHERE org_id = $1 AND automation_id = $2 AND state = 'EXPIRED' AND reason = 'VERSION_CHANGED'", e.ID); n != 1 {
		t.Fatal("no VERSION_CHANGED expiry")
	}
	// Its keys are given back: the same request can start the new version.
	if out := h.fire(t, e, "manual:e1", nil, Lineage{}); out.State != StateAccepted {
		t.Fatalf("after expiry: %+v", out)
	}
}

// TestHR277_OneExecutionPerKey: a base key and a declared parameter key
// each start at most one execution; duplicates are recorded and never
// reach the Starter; a refused start gives its keys back.
func TestHR277_OneExecutionPerKey(t *testing.T) {
	h := newHarness(t)
	f := h.f
	a := f.Automation(t, "dedupe", f.Definition(`"manual":{"params":{"ticket":{"type":"string","pattern":"T-[0-9]+"}}},"dedupe":{"key":"{{params.ticket}}","window":"1d"}`, ""), autodomain.RolloutFull)
	p := func(v string) map[string]autodomain.Value { return map[string]autodomain.Value{"ticket": str(v)} }
	if out := h.fire(t, a, "manual:1", p("T-1"), Lineage{}); out.State != StateAccepted || out.Execution.IsZero() {
		t.Fatalf("first: %+v", out)
	}
	if out := h.fire(t, a, "manual:1", p("T-2"), Lineage{}); out.State != StateRefusedDuplicate {
		t.Fatalf("same base key: %+v", out)
	}
	if out := h.fire(t, a, "manual:2", p("T-1"), Lineage{}); out.State != StateRefusedDuplicate {
		t.Fatalf("same declared key: %+v", out)
	}
	if out := h.fire(t, a, "manual:3", p("T-3"), Lineage{}); out.State != StateAccepted {
		t.Fatalf("new ticket: %+v", out)
	}
	if h.st.Count() != 2 {
		t.Fatalf("starts: %d", h.st.Count())
	}
	// The engine refusing (concurrency) releases the keys.
	h.st.Err = autodomain.ErrConcurrency
	if out := h.fire(t, a, "manual:4", p("T-4"), Lineage{}); out.State != StateRefusedConcurrency {
		t.Fatalf("concurrency: %+v", out)
	}
	h.st.Err = nil
	if out := h.fire(t, a, "manual:4", p("T-4"), Lineage{}); out.State != StateAccepted {
		t.Fatalf("retry after concurrency: %+v", out)
	}
	// An expired claim may be taken over.
	f.Exec(t, "UPDATE pc.automation_dedupe SET expires_at = now() - interval '1 second' WHERE org_id = $1", f.Org)
	if out := h.fire(t, a, "manual:1", p("T-1"), Lineage{}); out.State != StateAccepted {
		t.Fatalf("after expiry: %+v", out)
	}
	// Every refusal is recorded.
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_triggers WHERE org_id = $1 AND state = 'REFUSED_DUPLICATE'"); n != 2 {
		t.Fatalf("recorded duplicates: %d", n)
	}
	// The database refuses a second live claim of the same key.
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).ClaimDedupeKey(ctx, dbq.ClaimDedupeKeyParams{
			OrgID: f.Org, AutomationID: a.ID, Key: "manual:1", TriggerID: ids.NewV7(), ExpiresAt: time.Now().Add(time.Hour),
		})
		if !db.IsNoRows(err) {
			t.Fatalf("second claim: %v", err)
		}
		return nil
	})
}
