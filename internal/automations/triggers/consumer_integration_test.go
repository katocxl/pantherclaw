// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package triggers

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

type recorder struct {
	mu       sync.Mutex
	signals  []reflexdomain.Signal
	failures []reflexdomain.Failure
	paused   [][]ids.UUID
}

func (r *recorder) Raise(_ context.Context, _ pgx.Tx, s reflexdomain.Signal) (ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signals = append(r.signals, s)
	return ids.NewV7(), s.Validate()
}

func (r *recorder) Report(_ context.Context, _ pgx.Tx, f reflexdomain.Failure) (ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, f)
	return ids.NewV7(), nil
}

func (r *recorder) Pause(_ context.Context, _ pgx.Tx, _ ids.OrgID, sel autodomain.PauseSelector, _ autodomain.PauseReason) ([]ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paused = append(r.paused, sel.Automations)
	return sel.Automations, nil
}

func (r *recorder) failuresOf(kind string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, f := range r.failures {
		if f.Kind == kind {
			n++
		}
	}
	return n
}

func newRecordingHarness(t *testing.T) (*harness, *recorder) {
	t.Helper()
	h := newHarness(t)
	rec := &recorder{}
	h.svc = New(Deps{
		Pool: h.f.Pool, Starter: h.st, Editions: triggerstest.Team, Raiser: rec, Failures: rec, Pauser: rec,
		Log: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	return h, rec
}

// record writes one audit event and chains the ledger, so the feed sees it.
func (h *harness) record(t *testing.T, name string, actor evdomain.Actor, details map[string]string) {
	t.Helper()
	h.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: name, Actor: actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "grant", ID: ids.NewV7().String()}, Details: details,
		})
		return err
	})
	h.chain(t)
}

func (h *harness) feed(t *testing.T) FeedResult {
	t.Helper()
	r, err := h.svc.ProcessFeed(context.Background(), h.f.Org)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func person(h *harness) evdomain.Actor { return evdomain.Actor{Type: "user", ID: h.f.User.String()} }

// TestT123_TriggerLoopsAreRefusedOncePerRoot: an event an automation's own
// execution caused (its identity recorded it, naming the execution) is
// refused for that automation (REFUSED_LOOP), raises one grouped signal
// and one owned failure per root, and pauses it; an unrelated automation
// still runs on the same event.
func TestT123_TriggerLoopsAreRefusedOncePerRoot(t *testing.T) {
	h, rec := newRecordingHarness(t)
	f := h.f
	when := `"event":{"on":"grant.issued","params":{"agent":{"from":"attrs.agent","type":"uuid","required":false}}}`
	a := f.Automation(t, "loopy", f.Definition("loopy", when, ""), autodomain.RolloutFull)
	b := f.Automation(t, "bystander", f.Definition("bystander", `"event":{"on":"grant.issued"}`, ""), autodomain.RolloutFull)
	h.feed(t) // the cursor starts at the head: history never triggers

	// A starts by hand; its execution issues a grant.
	first := h.fire(t, a, "manual:1", nil, Lineage{})
	if first.State != StateAccepted {
		t.Fatalf("first: %+v", first)
	}
	saA := evdomain.Actor{Type: "service_account", ID: a.ServiceAccount.String()}
	h.record(t, "grant.issued", saA, map[string]string{"execution": first.Execution.String(), "automation": a.ID.String()})
	res := h.feed(t)
	if res.Events < 1 {
		t.Fatalf("feed: %+v", res)
	}
	states := f.States(t, a)
	if !slices.Equal(states, []string{"ACCEPTED", "REFUSED_LOOP"}) {
		t.Fatalf("A: %v", states)
	}
	if got := f.States(t, b); !slices.Equal(got, []string{"ACCEPTED"}) {
		t.Fatalf("B, triggered by A's work at depth 1: %v", got)
	}
	var depth int
	var anc []ids.UUID
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT depth, ancestry FROM pc.automation_triggers WHERE org_id = $1 AND automation_id = $2", f.Org, b.ID).Scan(&depth, &anc)
	})
	if depth != 1 || !slices.Equal(anc, []ids.UUID{a.ID}) {
		t.Fatalf("B lineage: depth %d ancestry %v", depth, anc)
	}
	if len(rec.signals) != 1 || rec.signals[0].RuleID != RuleLoop || rec.failuresOf(FailureLoopStopped) != 1 || len(rec.paused) != 1 {
		t.Fatalf("issue: %d signals, %d failures, %d pauses", len(rec.signals), rec.failuresOf(FailureLoopStopped), len(rec.paused))
	}
	// The same root loops again: refused, but no second issue.
	h.record(t, "grant.issued", saA, map[string]string{"execution": first.Execution.String()})
	h.feed(t)
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_triggers WHERE org_id = $1 AND state = 'REFUSED_LOOP'"); n != 2 {
		t.Fatalf("loops recorded: %d", n)
	}
	if len(rec.signals) != 1 || rec.failuresOf(FailureLoopStopped) != 1 {
		t.Fatalf("a second issue for the same root: %d signals", len(rec.signals))
	}
	// Depth: a chain at depth 3 may go on; at depth 4 it stops.
	deep := Lineage{Root: ids.NewV7(), Ancestry: []ids.UUID{ids.NewV7(), ids.NewV7(), ids.NewV7()}, Depth: 3}
	if out := h.fire(t, b, "manual:d3", nil, deep); out.State != StateAccepted {
		t.Fatalf("depth 3: %+v", out)
	}
	deep.Depth, deep.Ancestry = 4, append(deep.Ancestry, ids.NewV7())
	if out := h.fire(t, b, "manual:d4", nil, deep); out.State != StateRefusedLoop || out.Reason != ReasonDepth {
		t.Fatalf("depth 4: %+v", out)
	}
	// A by hand, B on each of the two events, B at depth 3.
	if h.st.Count() != 4 {
		t.Fatalf("starts: %d", h.st.Count())
	}
}

// TestT123_HourlyCapRefusesExcessWithOneIssue: beyond limits.per_hour,
// triggers are refused with one grouped owned failure for the hour.
func TestT123_HourlyCapRefusesExcessWithOneIssue(t *testing.T) {
	h, rec := newRecordingHarness(t)
	f := h.f
	a := f.Automation(t, "capped", f.Definition("capped", `"manual":{}`, `"limits":{"per_hour":2}`), autodomain.RolloutFull)
	var states []State
	for i := range 4 {
		states = append(states, h.fire(t, a, "manual:"+string(rune('a'+i)), nil, Lineage{}).State)
	}
	if !slices.Equal(states, []State{StateAccepted, StateAccepted, StateRefusedLimit, StateRefusedLimit}) {
		t.Fatalf("states: %v", states)
	}
	if rec.failuresOf(FailureHourlyCap) != 1 || h.st.Count() != 2 {
		t.Fatalf("failures %d, starts %d", rec.failuresOf(FailureHourlyCap), h.st.Count())
	}
	// A refused-at-cap request keeps no key: it can be sent again later.
	f.Exec(t, "UPDATE pc.automation_triggers SET state = state WHERE org_id = $1", f.Org)
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_dedupe WHERE org_id = $1 AND key = 'manual:c'"); n != 0 {
		t.Fatal("a refused trigger claimed its key")
	}
}

// TestThresholds_CountOncePerBucketAndNeverTheirOwnWork: a threshold fires
// when the window's count reaches at_least, once per bucket; events its
// own executions caused are not counted (D58).
func TestThresholds_CountOncePerBucketAndNeverTheirOwnWork(t *testing.T) {
	h, _ := newRecordingHarness(t)
	f := h.f
	thr := f.Automation(t, "burst", f.Definition("burst", `"threshold":{"on":"grant.revoked","over":"1h","at_least":3}`, ""), autodomain.RolloutFull)
	h.feed(t)
	own := h.fire(t, thr, "manual:own", nil, Lineage{})
	saT := evdomain.Actor{Type: "service_account", ID: thr.ServiceAccount.String()}
	for range 3 {
		h.record(t, "grant.revoked", saT, map[string]string{"execution": own.Execution.String()})
	}
	h.feed(t)
	if got := f.States(t, thr); len(got) != 1 {
		t.Fatalf("own work counted: %v", got)
	}
	for range 3 {
		h.record(t, "grant.revoked", person(h), nil)
	}
	h.feed(t)
	if got := f.States(t, thr); !slices.Equal(got, []string{"ACCEPTED", "ACCEPTED"}) {
		t.Fatalf("after 3 events: %v", got)
	}
	h.record(t, "grant.revoked", person(h), nil)
	h.feed(t)
	if got := f.States(t, thr); !slices.Equal(got, []string{"ACCEPTED", "ACCEPTED", "REFUSED_DUPLICATE"}) {
		t.Fatalf("a fourth event in the same bucket: %v", got)
	}
}

// TestEvents_TestEventsNeverTrigger: simulated (test) events never start
// work, and parameters come only from declared event fields.
func TestEvents_TestEventsNeverTrigger(t *testing.T) {
	h, _ := newRecordingHarness(t)
	f := h.f
	when := `"event":{"on":"grant.issued","where":"event.attrs.?env.orValue('') == 'prod'","params":{"op":{"from":"attrs.operation_name","type":"string","pattern":"[a-z.]+"}}}`
	a := f.Automation(t, "watch", f.Definition("watch", when, ""), autodomain.RolloutFull)
	h.feed(t)
	h.record(t, "grant.issued", person(h), map[string]string{"simulated": "true", "env": "prod", "operation_name": "refund"})
	h.record(t, "grant.issued", person(h), map[string]string{"env": "dev", "operation_name": "refund"})
	h.record(t, "grant.issued", person(h), map[string]string{"env": "prod", "operation_name": "refund"})
	h.record(t, "grant.issued", person(h), map[string]string{"env": "prod", "operation_name": "Refund!"})
	h.feed(t)
	if got := f.States(t, a); !slices.Equal(got, []string{"ACCEPTED", "REFUSED_INVALID"}) {
		t.Fatalf("states: %v", got)
	}
	if h.st.Count() != 1 || h.st.Starts[0].Params["op"].String != "refund" || len(h.st.Starts[0].Evidence) != 1 {
		t.Fatalf("start: %+v", h.st.Starts)
	}
}

// TestSchedules_FireMissAndCatchUp: a due occurrence fires once; one more
// than two minutes late is recorded missed (SKIP) or, with CATCH_UP, the
// latest one inside the window fires.
func TestSchedules_FireMissAndCatchUp(t *testing.T) {
	h, _ := newRecordingHarness(t)
	f := h.f
	ctx := context.Background()
	skip := f.Automation(t, "minutely", f.Definition("minutely", `"schedule":{"cron":"* * * * *","timezone":"UTC"}`, ""), autodomain.RolloutFull)
	catch := f.Automation(t, "catchup", f.Definition("catchup", `"schedule":{"cron":"*/5 * * * *","timezone":"Europe/London","missed":"CATCH_UP","catch_up_window":"1h"}`, ""), autodomain.RolloutFull)
	for _, a := range []triggerstest.Automation{skip, catch} {
		h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
			return act.Activate(ctx, tx.Pgx(), a.ID, a.Version)
		})
	}
	set := func(a triggerstest.Automation, ago string) {
		f.Exec(t, "UPDATE pc.automation_schedules SET next_fire_at = date_trunc('minute', now()) - $2::interval WHERE org_id = $1 AND automation_id = $3", f.Org, ago, a.ID)
	}
	set(skip, "0 minutes")
	if n, err := h.svc.DispatchSchedules(ctx, f.Org); err != nil || n != 1 {
		t.Fatalf("due occurrence: %d %v", n, err)
	}
	if n, _ := h.svc.DispatchSchedules(ctx, f.Org); n != 0 {
		t.Fatal("an occurrence fired twice")
	}
	set(skip, "10 minutes")
	set(catch, "30 minutes")
	if n, err := h.svc.DispatchSchedules(ctx, f.Org); err != nil || n != 1 {
		t.Fatalf("missed and caught up: %d %v", n, err)
	}
	if got := f.States(t, skip); !slices.Equal(got, []string{"ACCEPTED", "DISCARDED"}) {
		t.Fatalf("SKIP: %v", got)
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_triggers WHERE org_id = $1 AND reason = 'MISSED'"); n != 1 {
		t.Fatal("missed occurrence not recorded")
	}
	if got := f.States(t, catch); !slices.Equal(got, []string{"ACCEPTED"}) {
		t.Fatalf("CATCH_UP: %v", got)
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_schedules WHERE org_id = $1 AND next_fire_at > now() - interval '2 minutes'"); n != 2 {
		t.Fatal("schedules did not advance")
	}
	if p, err := PreviewSchedule("30 1 * * *", "Europe/London", false, time.Date(2027, 3, 27, 12, 0, 0, 0, time.UTC), 2); err != nil || len(p) != 2 || p[0].Note != "DST_SKIPPED" {
		t.Fatalf("preview: %+v %v", p, err)
	}
}

// TestConditions_FireOncePerEpisode: a condition fires once its subject has
// matched for `for`, once per episode; an episode ends when the subject no
// longer matches.
func TestConditions_FireOncePerEpisode(t *testing.T) {
	h, _ := newRecordingHarness(t)
	f := h.f
	ctx := context.Background()
	when := `"condition":{"probe":"agent.unclaimed","for":"1m","params":{"agent":{"from":"agent","type":"uuid"}}}`
	a := f.Automation(t, "claims", f.Definition("claims", when, ""), autodomain.RolloutFull)
	agent := ids.NewV7()
	f.Exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'stray', 'DISCOVERED', 'system')", f.Org, agent)
	if n, err := h.svc.EvaluateConditions(ctx, f.Org); err != nil || n != 0 {
		t.Fatalf("first look: %d %v", n, err)
	}
	f.Exec(t, "UPDATE pc.automation_condition_state SET since = now() - interval '2 minutes' WHERE org_id = $1", f.Org)
	if n, err := h.svc.EvaluateConditions(ctx, f.Org); err != nil || n != 1 {
		t.Fatalf("after for: %d %v", n, err)
	}
	if n, _ := h.svc.EvaluateConditions(ctx, f.Org); n != 0 {
		t.Fatal("fired twice in one episode")
	}
	if h.st.Starts[0].Params["agent"].String != agent.String() {
		t.Fatalf("params: %+v", h.st.Starts[0].Params)
	}
	f.Exec(t, "UPDATE pc.agents SET state = 'SUSPENDED', suspended_from = 'DISCOVERED' WHERE org_id = $1", f.Org)
	if _, err := h.svc.EvaluateConditions(ctx, f.Org); err != nil {
		t.Fatal(err)
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_condition_state WHERE org_id = $1 AND automation_id = $2", a.ID); n != 0 {
		t.Fatal("episode did not end")
	}
}

// chain links every ledger entry of the org. Chaining waits for older
// transactions anywhere in the cluster (xmin), so it retries for a while.
func (h *harness) chain(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := ledger.ChainAll(context.Background(), h.f.Pool, h.f.Org, 500); err != nil {
			t.Fatal(err)
		}
		n := h.f.Count(t, `SELECT count(*) FROM pc.ledger_entries l WHERE l.org_id = $1
			AND NOT EXISTS (SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = l.org_id AND c.entry_id = l.id)`)
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d ledger entries stay unchained", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
