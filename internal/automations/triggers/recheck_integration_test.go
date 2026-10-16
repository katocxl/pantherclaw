// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package triggers

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestT123_ConcurrentTriggersNeverOverrunTheHourlyCap (D87 L4, D97 N5):
// the cap counts ACCEPTED triggers under the automation's lock, so
// concurrent triggers start exactly per_hour executions; SHADOW triggers
// are not counted against it.
func TestT123_ConcurrentTriggersNeverOverrunTheHourlyCap(t *testing.T) {
	h, _ := newRecordingHarness(t)
	f := h.f
	a := f.Automation(t, "concurrent", f.Definition(`"manual":{}`, `"limits":{"per_hour":2}`), autodomain.RolloutFull)

	fire := func(key string, mode autodomain.Mode) (Outcome, error) {
		var out Outcome
		err := f.Pool.InTenantTx(context.Background(), f.Org, func(ctx context.Context, tx db.TenantTx) error {
			au, err := h.svc.loadAutomation(ctx, dbq.New(tx), f.Org, a.ID)
			if err != nil {
				return err
			}
			out, err = h.svc.Fire(ctx, tx, Candidate{
				Automation: au, Kind: autodomain.TriggerManual, Authenticity: autodomain.AuthUserSession,
				BaseKey: key, Mode: mode, QueueOK: true,
			})
			return err
		})
		return out, err
	}

	// SHADOW triggers past the cap are all SHADOW and use none of it.
	for _, k := range []string{"manual:s1", "manual:s2", "manual:s3"} {
		out, err := fire(k, autodomain.ModeShadow)
		if err != nil || out.State != StateShadow {
			t.Fatalf("shadow %s: %+v %v", k, out, err)
		}
	}

	const n = 8
	var wg sync.WaitGroup
	states := make([]State, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			out, err := fire("manual:c"+string(rune('a'+i)), "")
			states[i], errs[i] = out.State, err
		})
	}
	wg.Wait()
	accepted, refused := 0, 0
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("trigger %d: %v", i, errs[i])
		}
		switch states[i] {
		case StateAccepted:
			accepted++
		case StateRefusedLimit:
			refused++
		default:
			t.Fatalf("trigger %d: %s", i, states[i])
		}
	}
	if accepted != 2 || refused != n-2 {
		t.Fatalf("accepted %d, refused %d: %v", accepted, refused, states)
	}
}

// TestThresholds_AFiredBucketAddsNoRows (D87 L5, D97 N5): once a bucket
// has fired, further events in it add no count rows.
func TestThresholds_AFiredBucketAddsNoRows(t *testing.T) {
	h, _ := newRecordingHarness(t)
	f := h.f
	thr := f.Automation(t, "rows", f.Definition(`"threshold":{"on":"grant.revoked","over":"1h","at_least":2}`, ""), autodomain.RolloutFull)
	h.feed(t)
	for range 2 {
		h.record(t, "grant.revoked", person(h), nil)
	}
	h.feed(t)
	if got := f.States(t, thr); !slices.Equal(got, []string{"ACCEPTED"}) {
		t.Fatalf("after 2 events: %v", got)
	}
	const rows = "SELECT count(*) FROM pc.automation_threshold_counts WHERE org_id = $1"
	before := f.Count(t, rows)
	for range 3 {
		h.record(t, "grant.revoked", person(h), nil)
	}
	h.feed(t)
	if after := f.Count(t, rows); after != before {
		t.Fatalf("a fired bucket gained rows: %d → %d", before, after)
	}
	if got := f.States(t, thr); !slices.Equal(got, []string{"ACCEPTED"}) {
		t.Fatalf("a fired bucket fired again: %v", got)
	}
}

// TestT123_GateRequestsInheritTheirExecutionsLineage (D87 L6): an event
// about an automation's gate request, and the approval.waiting probe's
// subject for it, descend from the gate's execution.
func TestT123_GateRequestsInheritTheirExecutionsLineage(t *testing.T) {
	h, _ := newRecordingHarness(t)
	f := h.f
	a := f.Automation(t, "gated", f.Definition(`"event":{"on":"approval.expired"}`, ""), autodomain.RolloutFull)
	b := f.Automation(t, "watcher", f.Definition(`"event":{"on":"approval.expired"}`, ""), autodomain.RolloutFull)
	h.feed(t)
	first := h.fire(t, a, "manual:1", nil, Lineage{})
	if first.State != StateAccepted {
		t.Fatalf("first: %+v", first)
	}
	gate := ids.NewV7()
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		now, err := dbq.New(tx).DBNow(ctx)
		if err != nil {
			return err
		}
		step := "approve"
		bind, disp := ids.NewV7(), ids.NewV7()
		return dbq.New(tx).InsertAutomationGateRequest(ctx, dbq.InsertAutomationGateRequestParams{
			OrgID: f.Org, ID: gate, AutomationID: &a.ID, ExecutionID: &first.Execution, StepID: &step,
			Binding: append(bind[:], bind[:]...), BindingInput: []byte(`{}`), Requirements: []byte(`[{}]`),
			Display: []byte(`{}`), DisplayHash: append(disp[:], disp[:]...), DeadlineAt: now.Add(time.Hour).Truncate(time.Second),
		})
	})

	// The probe's subject carries the gate's execution.
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		subs, _, err := RunProbe(ctx, dbq.New(tx), f.Org, ProbeApprovalWait, time.Now())
		if err != nil {
			return err
		}
		if len(subs) != 1 || subs[0].Execution == nil || *subs[0].Execution != first.Execution {
			t.Fatalf("probe subjects: %+v", subs)
		}
		return nil
	})

	// The engine's gate expiry, recorded by the system, descends from A.
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "approval.expired", Actor: evdomain.Actor{Type: "system", ID: "automation_engine"}, Outcome: audit.Success,
			Object: &audit.Object{Type: "approval_request", ID: gate.String()},
		})
		return err
	})
	h.chain(t)
	h.feed(t)
	if got := f.States(t, a); !slices.Equal(got, []string{"ACCEPTED", "REFUSED_LOOP"}) {
		t.Fatalf("A on its own gate: %v", got)
	}
	var depth int
	var anc []ids.UUID
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT depth, ancestry FROM pc.automation_triggers WHERE org_id = $1 AND automation_id = $2", f.Org, b.ID).Scan(&depth, &anc)
	})
	if depth != 1 || !slices.Equal(anc, []ids.UUID{a.ID}) {
		t.Fatalf("B lineage: depth %d ancestry %v", depth, anc)
	}
}
