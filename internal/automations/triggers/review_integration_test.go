// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package triggers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeExecutions answers RetryExecution's lookup.
type fakeExecutions map[ids.UUID]ExecutionInfo

func (f fakeExecutions) Execution(_ context.Context, _ pgx.Tx, _ ids.OrgID, id ids.UUID) (ExecutionInfo, error) {
	x, ok := f[id]
	if !ok {
		return ExecutionInfo{}, errors.New("no such execution")
	}
	return x, nil
}

// fakeOperations says which operations are irreversible.
type fakeOperations map[string]defs.Reversibility

func (f fakeOperations) Active(_ context.Context, _ db.TenantTx, _ ids.OrgID, op string) (*defs.Definition, error) {
	r, ok := f[op]
	if !ok {
		return nil, nil
	}
	return &defs.Definition{Reversibility: r}, nil
}

func ceilingDef(f *triggerstest.Fixture, name, op string) string {
	return strings.Replace(f.Definition(name, `"manual":{}`, ""), `"authority":{"principal":"self"}`,
		`"authority":{"principal":"self","ceiling":{"agents":["`+ids.NewV7().String()+
			`"],"bounds":{"operations":["`+op+`"]},"per_grant":{"ttl":"1h"},"per_day":{"grants":5,"runs":5}}}`, 1)
}

// TestD87_ActivateWhilePausedKeepsTheSchedulePaused (P1).
func TestD87_ActivateWhilePausedKeepsTheSchedulePaused(t *testing.T) {
	h := newHarness(t)
	f := h.f
	a := f.Automation(t, "paused", f.Definition("paused", `"schedule":{"cron":"* * * * *","timezone":"UTC"}`, ""), autodomain.RolloutFull)
	f.Pause(t, a)
	h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
		return act.Activate(ctx, tx.Pgx(), a.ID, a.Version)
	})
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_schedules WHERE org_id = $1 AND state = 'PAUSED'"); n != 1 {
		t.Fatal("a version enabled while paused turned its schedule on")
	}
}

// TestHR277_DiscardedAndExpiredQueuedTriggersReleaseTheirKeys (P5).
func TestHR277_DiscardedAndExpiredQueuedTriggersReleaseTheirKeys(t *testing.T) {
	h := newHarness(t)
	f := h.f
	a := f.Automation(t, "queue", f.Definition("queue", `"manual":{}`, `"paused_triggers":"EXPIRE"`), autodomain.RolloutFull)
	f.Pause(t, a)
	if out := h.fire(t, a, "manual:x", nil, Lineage{}); out.State != StateQueued {
		t.Fatalf("queued: %+v", out)
	}
	f.Exec(t, "UPDATE pc.automation_triggers SET queued_until = now() - interval '1 second' WHERE org_id = $1 AND state = 'QUEUED'", f.Org)
	if err := h.svc.Janitor(context.Background(), f.Org); err != nil {
		t.Fatal(err)
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_dedupe WHERE org_id = $1"); n != 0 {
		t.Fatal("an expired queued trigger kept its key")
	}
	if out := h.fire(t, a, "manual:y", nil, Lineage{}); out.State != StateQueued {
		t.Fatalf("queued again: %+v", out)
	}
	h.activator(t, func(ctx context.Context, act Activator, tx db.TenantTx) error {
		return act.Deactivate(ctx, tx.Pgx(), a.ID, autodomain.PausedDiscard)
	})
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_dedupe WHERE org_id = $1"); n != 0 {
		t.Fatal("a discarded queued trigger kept its key")
	}
}

// TestHR278_TooWideOrTooLargeIsRefusedNotFailed (L1, L3): an ancestry
// wider than 8 is REFUSED_LOOP and oversize parameters REFUSED_INVALID,
// each recorded, never an insert failure.
func TestHR278_TooWideOrTooLargeIsRefusedNotFailed(t *testing.T) {
	h := newHarness(t)
	f := h.f
	a := f.Automation(t, "wide", f.Definition("wide", `"manual":{}`, ""), autodomain.RolloutFull)
	var anc []ids.UUID
	for range 9 {
		anc = append(anc, ids.NewV7())
	}
	if out := h.fire(t, a, "manual:w", nil, Lineage{Root: ids.NewV7(), Ancestry: anc, Depth: 2}); out.State != StateRefusedLoop || out.Reason != ReasonWidth {
		t.Fatalf("width: %+v", out)
	}
	big := map[string]autodomain.Value{}
	for i := range 16 {
		big["p"+string(rune('a'+i))] = autodomain.Value{Type: autodomain.ParamString, String: strings.Repeat("x", 256)}
	}
	if out := h.fire(t, a, "manual:b", big, Lineage{}); out.State != StateRefusedInvalid || out.Reason != ReasonParamsSize {
		t.Fatalf("size: %+v", out)
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_triggers WHERE org_id = $1 AND reason IN ('ANCESTRY_WIDTH', 'PARAMS_SIZE')"); n != 2 {
		t.Fatalf("recorded refusals: %d", n)
	}
	if h.st.Count() != 0 {
		t.Fatal("started")
	}
}

// TestD87_ManualStartsAndRetries: a ceiling with an irreversible operation
// needs a step-up (P3); keys are per person and a repeat returns the
// original (L7); only LIVE executions are retried (P2).
func TestD87_ManualStartsAndRetries(t *testing.T) {
	h := newHarness(t)
	f := h.f
	xs := fakeExecutions{}
	h.svc = New(Deps{Pool: f.Pool, Starter: h.st, Editions: triggerstest.Team, Executions: xs, Operations: fakeOperations{
		"payments.refund.create": defs.Irreversible, "tickets.comment.create": defs.Reversible,
	}})
	op := f.As(td.KindUser, td.RoleAutomationOperator)
	irr := f.Automation(t, "refunds", ceilingDef(f, "refunds", "payments.refund.create"), autodomain.RolloutFull)
	rev := f.Automation(t, "comments", ceilingDef(f, "comments", "tickets.comment.create"), autodomain.RolloutFull)
	pre := f.Automation(t, "prefix", ceilingDef(f, "prefix", "payments.*"), autodomain.RolloutFull)
	for _, a := range []triggerstest.Automation{irr, pre} {
		if _, err := h.svc.StartExecution(op, ManualStart{Automation: a.ID, IdempotencyKey: "k"}, nil); !stepup.Is(err) {
			t.Fatalf("irreversible ceiling without a step-up: %v", err)
		}
	}
	first, err := h.svc.StartExecution(op, ManualStart{Automation: rev.ID, IdempotencyKey: "k"}, nil)
	if err != nil || first.State != StateAccepted {
		t.Fatalf("reversible: %+v %v", first, err)
	}
	again, err := h.svc.StartExecution(op, ManualStart{Automation: rev.ID, IdempotencyKey: "k"}, nil)
	if err != nil || again.Trigger != first.Trigger || again.Execution != first.Execution {
		t.Fatalf("a repeat must return the original: %+v vs %+v (%v)", again, first, err)
	}
	if h.st.Count() != 1 {
		t.Fatalf("starts: %d", h.st.Count())
	}
	// Another person's same key is their own.
	other := ids.NewV7()
	f.Exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", f.Org, other)
	bob := f.As(td.KindUser, td.RoleAutomationOperator)
	bobCaller := withPrincipal(bob, other)
	if out, err := h.svc.StartExecution(bobCaller, ManualStart{Automation: rev.ID, IdempotencyKey: "k"}, nil); err != nil || out.Trigger == first.Trigger {
		t.Fatalf("another person's key: %+v %v", out, err)
	}

	// Retries: LIVE only, of the enabled version, not an unknown effect.
	xs[first.Execution] = ExecutionInfo{Automation: rev.ID, Version: rev.Version, State: autodomain.ExecFailed, Trigger: first.Trigger}
	r1, err := h.svc.RetryExecution(op, first.Execution, "r", nil)
	if err != nil || r1.State != StateAccepted {
		t.Fatalf("retry: %+v %v", r1, err)
	}
	if r2, err := h.svc.RetryExecution(op, first.Execution, "r", nil); err != nil || r2.Trigger != r1.Trigger {
		t.Fatalf("a repeated retry must return the original: %+v %v", r2, err)
	}
	shadow := f.Automation(t, "shadowed", f.Definition("shadowed", `"manual":{}`, ""), autodomain.RolloutShadow)
	sh, err := h.svc.StartExecution(op, ManualStart{Automation: shadow.ID, IdempotencyKey: "s"}, nil)
	if err != nil || sh.State != StateShadow {
		t.Fatalf("shadow start: %+v %v", sh, err)
	}
	f.Exec(t, "UPDATE pc.automations SET rollout = 'FULL' WHERE org_id = $1 AND id = $2", f.Org, shadow.ID)
	xs[sh.Execution] = ExecutionInfo{Automation: shadow.ID, Version: shadow.Version, State: autodomain.ExecFailed, Trigger: sh.Trigger}
	if _, err := h.svc.RetryExecution(op, sh.Execution, "s", nil); !errors.Is(err, ErrNotRetry) {
		t.Fatalf("a SHADOW execution was retried LIVE: %v", err)
	}
	xs[first.Execution] = ExecutionInfo{Automation: rev.ID, Version: rev.Version, State: autodomain.ExecFailed, UnknownIrreversible: true}
	if _, err := h.svc.RetryExecution(op, first.Execution, "u", nil); !errors.Is(err, ErrNotRetry) {
		t.Fatalf("an unknown irreversible effect was retried: %v", err)
	}
}

func withPrincipal(ctx context.Context, user ids.UUID) context.Context {
	c, _ := tenancy.CallerFrom(ctx)
	c.Principal.ID = user
	return tenancy.WithCaller(ctx, c)
}
