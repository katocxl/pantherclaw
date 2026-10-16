// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package promotions_test

import (
	"context"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/policytest"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/promotions/promotiontest"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// publishTest publishes a policy with a scenario test of refunds in the
// production environment, so only COVERAGE can be missing.
func (w *world) publishTest() {
	w.t.Helper()
	policytest.Publish(context.Background(), w.t, w.pool, w.org, &pdomain.Bundle{
		ID: "prod", Version: 1,
		Rules: []pdomain.Rule{{
			ID: "label", Kind: pdomain.Annotate, Summary: "label refunds", Operations: []string{refund}, When: "true",
			Reason: "REFUNDS", Labels: map[string]string{"kind": "refund"},
		}},
		Tests: []pdomain.TestCase{{
			ID: "refund", Summary: "a refund", Expect: pdomain.TestExpect{Decision: "DENY", Reason: "NO_GRANT"},
			Action: pdomain.TestAction{Operation: refund, Environment: w.prod.String(), Params: []byte(`{}`)},
		}},
	})
}

func (w *world) promote(p promotiontest.Promoter) promotions.Result {
	w.t.Helper()
	res, err := w.svc.PromoteAgent(p.Ctx, promotions.PromoteInput{
		Agent: w.agent, Environment: w.prod, Operations: []string{refund}, FailureBehavior: promotions.FailClosed,
	}, p.StepUp())
	if err != nil {
		w.t.Fatal(err)
	}
	return res
}

func (w *world) promotion(id ids.UUID) (state string, confirmed, expired bool) {
	w.t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state, confirmed_at IS NOT NULL, expired_at IS NOT NULL FROM pc.agent_promotions WHERE id = $1", id).
			Scan(&state, &confirmed, &expired)
	}); err != nil {
		w.t.Fatal(err)
	}
	return state, confirmed, expired
}

// TestHR290_ANewAgentIsPromotedProvisionallyAndItsGrantsEndWithIt (D80,
// F7): with every check passing but COVERAGE, and no coverage record at
// all, the promotion is PROVISIONAL for 7 days and readiness says so; a
// grant under it is capped at its expiry; once the promotion's expiry has
// passed it covers nothing, before any sweep.
func TestHR290_ANewAgentIsPromotedProvisionallyAndItsGrantsEndWithIt(t *testing.T) {
	w := newWorld(t)
	w.publishTest()
	p := promotiontest.NewPromoter(t, w.scope)
	res := w.promote(p)
	if len(res.Promoted) != 1 || res.Promoted[0].State != promotions.StateProvisional || res.Promoted[0].ExpiresAt == nil {
		t.Fatalf("promoted %+v", res.Promoted)
	}
	pr := res.Promoted[0]
	if d := time.Until(*pr.ExpiresAt); d < 7*24*time.Hour-time.Hour || d > 7*24*time.Hour {
		t.Fatalf("a provisional promotion lasting %s", d)
	}
	r := res.Readiness[0]
	if r.Ready() || !r.Provisional() || !strings.HasPrefix(r.Checks[4].Detail, "coverage pending until ") {
		t.Fatalf("readiness %+v", r)
	}
	g, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	if err != nil {
		t.Fatalf("a grant under the provisional promotion: %v", err)
	}
	if g.ExpiresAt.After(*pr.ExpiresAt) {
		t.Fatalf("grant expiry %s after the promotion's %s", g.ExpiresAt, *pr.ExpiresAt)
	}

	// A provisional promotion ending in a minute caps a day's grant at it,
	// on issue and on a revision that would extend it.
	w.exec("UPDATE pc.agent_promotions SET state = 'REVOKED', revoked_by = $2, revoke_reason = 'test' WHERE id = $1", pr.ID, p.User)
	soon := ids.NewV7()
	w.exec(`INSERT INTO pc.agent_promotions (org_id, id, agent_id, environment_id, operation, state, checks, failure_behavior,
		promoted_by, credential_id, expires_at) VALUES ($1, $2, $3, $4, $5, 'PROVISIONAL', '[]', 'FAIL_CLOSED', $6, $7, now() + interval '1 minute')`,
		w.org, soon, w.agent, w.prod, refund, p.User, p.Key)
	capped, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(capped.ExpiresAt) > 2*time.Minute {
		t.Fatalf("a day's grant under a promotion ending in a minute expires in %s", time.Until(capped.ExpiresAt))
	}
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"]}`))
	revised, _, err := w.grants.Revise(w.issuer, gapp.ReviseRequest{
		ID: capped.ID, Revision: 1, TaskRef: "refunds", Bounds: b, ExpiresAt: time.Now().Add(20 * time.Hour),
	})
	if err != nil || time.Until(revised.ExpiresAt) > 2*time.Minute {
		t.Fatalf("an extending revision: %v, expires in %s", err, time.Until(revised.ExpiresAt))
	}
	w.exec("UPDATE pc.agent_promotions SET state = 'REVOKED', revoked_by = $2, revoke_reason = 'test' WHERE id = $1", soon, p.User)
	gone := ids.NewV7()
	w.exec(`INSERT INTO pc.agent_promotions (org_id, id, agent_id, environment_id, operation, state, checks, failure_behavior,
		promoted_by, credential_id, expires_at) VALUES ($1, $2, $3, $4, $5, 'PROVISIONAL', '[]', 'FAIL_CLOSED', $6, $7, now() + interval '1 second')`,
		w.org, gone, w.agent, w.prod, refund, p.User, p.Key)
	time.Sleep(1500 * time.Millisecond)
	_, err = w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	notPromoted(t, "a provisional promotion past its expiry, not swept yet", err)
}

// TestHR290_AFailingCoverageRecordIsNeverProvisional (D80): a coverage
// record that exists with a failing state fails COVERAGE outright.
func TestHR290_AFailingCoverageRecordIsNeverProvisional(t *testing.T) {
	w := newWorld(t)
	w.publishTest()
	entry := ids.NewV7()
	w.exec(`INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, 'coverage.test', 'test', 'test', '\x7b7d')`, w.org, entry)
	w.exec(`INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body, body_sha256, ledger_entry_id)
		VALUES ($1, $2, $3, $4, $5, 'OBSERVE_ONLY', '{monitor_mode}', '{}', $6, $7)`, w.org, ids.NewV7(), w.agent, w.conn, refund, make([]byte, 32), entry)
	res := w.promote(promotiontest.NewPromoter(t, w.scope))
	if len(res.Promoted) != 0 || res.Readiness[0].Provisional() || res.Readiness[0].Checks[4].Pending {
		t.Fatalf("promoted %+v with readiness %+v", res.Promoted, res.Readiness[0])
	}
}

// TestHR290_TheSweepConfirmsOrExpiresProvisionalPromotions (D80): once
// the agent's route reads PARTIAL the sweep makes the promotion ACTIVE; one
// whose expiry passed first becomes EXPIRED with an owned failure to the
// agent's owner, and the agent can be promoted provisionally again while
// still no coverage record exists.
func TestHR290_TheSweepConfirmsOrExpiresProvisionalPromotions(t *testing.T) {
	w := newWorld(t)
	w.publishTest()
	w.svc.Failures = &failures.Sink{}
	p := promotiontest.NewPromoter(t, w.scope)
	lapsing := ids.NewV7()
	w.exec(`INSERT INTO pc.agent_promotions (org_id, id, agent_id, environment_id, operation, state, checks, failure_behavior,
		promoted_by, credential_id, expires_at) VALUES ($1, $2, $3, $4, $5, 'PROVISIONAL', '[]', 'FAIL_CLOSED', $6, $7, now() + interval '1 second')`,
		w.org, lapsing, w.agent, w.prod, refund, p.User, p.Key)
	time.Sleep(1500 * time.Millisecond)
	confirmed, expired, err := w.svc.Sweep(context.Background(), w.org)
	if err != nil || confirmed != 0 || expired != 1 {
		t.Fatalf("sweep: %d confirmed, %d expired, %v", confirmed, expired, err)
	}
	if st, _, ex := w.promotion(lapsing); st != promotions.StateExpired || !ex {
		t.Fatalf("lapsed promotion %s", st)
	}
	var owner string
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT owner_id::text FROM pc.operational_failures WHERE kind = $1", promotions.FailureLapsed).Scan(&owner)
	}); err != nil || owner != w.alice.String() {
		t.Fatalf("the owned failure: owner %q, %v", owner, err)
	}

	res := w.promote(p) // still no coverage record: provisional again
	if len(res.Promoted) != 1 || res.Promoted[0].State != promotions.StateProvisional {
		t.Fatalf("re-promoting: %+v", res.Promoted)
	}
	again := res.Promoted[0].ID
	promotiontest.Record(t, w.scope, refund) // the route now reads PARTIAL
	if confirmed, expired, err := w.svc.Sweep(context.Background(), w.org); err != nil || confirmed != 1 || expired != 0 {
		t.Fatalf("sweep with coverage: %d confirmed, %d expired, %v", confirmed, expired, err)
	}
	if st, conf, _ := w.promotion(again); st != promotions.StateActive || !conf {
		t.Fatalf("confirmed promotion %s (confirmed %v)", st, conf)
	}
	g, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	if err != nil || time.Until(g.ExpiresAt) < 23*time.Hour {
		t.Fatalf("a grant under the confirmed promotion: %v, expires in %s", err, time.Until(g.ExpiresAt))
	}
	var checks []promotions.Check
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT checks FROM pc.agent_promotions WHERE id = $1", again).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &checks)
	}); err != nil || len(checks) != len(promotions.CheckNames) {
		t.Fatalf("the stored checks: %+v %v", checks, err)
	}
}

// TestHR290_ProvisionalPromotionsMoveOnlyAsTheyMay (D80): the database
// refuses a provisional promotion without an expiry or longer than 7
// days, confirming one past its expiry, expiring one before it, and any
// move out of EXPIRED.
func TestHR290_ProvisionalPromotionsMoveOnlyAsTheyMay(t *testing.T) {
	w := newWorld(t)
	p := promotiontest.NewPromoter(t, w.scope)
	insert := func(id ids.UUID, expiry string) error {
		return w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO pc.agent_promotions (org_id, id, agent_id, environment_id, operation, state, checks,
				failure_behavior, promoted_by, credential_id, expires_at) VALUES ($1, $2, $3, $4, $5, 'PROVISIONAL', '[]', 'FAIL_CLOSED', $6, $7, `+expiry+`)`,
				w.org, id, w.agent, w.prod, refund, p.User, p.Key)
			return err
		})
	}
	update := func(sql string, args ...any) error {
		return w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	for name, expiry := range map[string]string{"no expiry": "NULL", "8 days": "now() + interval '8 days'", "past": "now() - interval '1 second'"} {
		if err := insert(ids.NewV7(), expiry); err == nil {
			t.Errorf("a provisional promotion with %s", name)
		}
	}
	id := ids.NewV7()
	if err := insert(id, "now() + interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	if err := update("UPDATE pc.agent_promotions SET state = 'EXPIRED', expired_at = now() WHERE id = $1", id); err == nil {
		t.Error("expired before its expiry")
	}
	if err := update("UPDATE pc.agent_promotions SET state = 'REVOKED', revoked_by = $2, revoke_reason = 'x' WHERE id = $1", id, p.User); err != nil {
		t.Fatal(err)
	}
	late := ids.NewV7()
	if err := insert(late, "now() + interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if err := update("UPDATE pc.agent_promotions SET state = 'ACTIVE', confirmed_at = now() WHERE id = $1", late); err == nil {
		t.Error("confirmed after its expiry")
	}
	if err := update("UPDATE pc.agent_promotions SET state = 'EXPIRED', expired_at = now() WHERE id = $1", late); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"ACTIVE", "PROVISIONAL"} {
		if err := update("UPDATE pc.agent_promotions SET state = $2 WHERE id = $1", late, to); err == nil {
			t.Errorf("EXPIRED moved to %s", to)
		}
	}
}
