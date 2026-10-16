// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package promotions_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/promotions/promotiontest"
)

// instance is the agent's admitted instance.
func (w *world) instance(agent ids.UUID) ids.UUID {
	w.t.Helper()
	var id ids.UUID
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.agent_instances WHERE agent_id = $1", agent).Scan(&id)
	}); err != nil {
		w.t.Fatal(err)
	}
	return id
}

// prodAgent adds another production agent of the team, never promoted.
func (w *world) prodAgent(name string) ids.UUID {
	w.t.Helper()
	id := ids.NewV7()
	w.exec(`INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'service', 'VERIFIED', 'test', now())`, w.org, id, name, w.team, w.prod, w.alice)
	w.exec(`INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, w.org, ids.NewV7(), id, fmt.Sprintf("%043d", time.Now().UnixNano()%1e12+7))
	return id
}

// replace revokes a promotion and records the same one PROVISIONAL,
// ending after the given interval, and returns its id.
func (w *world) replace(p promotions.Promotion, interval string) ids.UUID {
	w.t.Helper()
	w.exec("UPDATE pc.agent_promotions SET state = 'REVOKED', revoked_by = promoted_by, revoke_reason = 'test' WHERE id = $1", p.ID)
	id := ids.NewV7()
	w.exec(`INSERT INTO pc.agent_promotions (org_id, id, agent_id, environment_id, operation, state, checks, failure_behavior,
		promoted_by, credential_id, expires_at) SELECT org_id, $2, agent_id, environment_id, operation, 'PROVISIONAL', '[]', 'FAIL_CLOSED',
		promoted_by, credential_id, now() + $3::interval FROM pc.agent_promotions WHERE id = $1`, p.ID, id, interval)
	return id
}

// delegateTo starts a run of agent under a delegable grant and a child run
// of child, and delegates to it.
func (w *world) delegateTo(agent, child ids.UUID) (gdomain.Grant, error) {
	w.t.Helper()
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"]}`))
	g, err := w.grants.Issue(w.issuer, gapp.IssueRequest{
		AgentID: agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(24 * time.Hour), Bounds: b, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 1},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	inst, childInst := w.instance(agent), w.instance(child)
	run, childRun := ids.NewV7(), ids.NewV7()
	w.exec(`INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id,
		principal_source, grant_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $6, 'launcher', $7, now() + interval '8 hours')`,
		w.org, run, agent, inst, w.prod, w.alice, g.ID.UUID())
	w.exec(`INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_instance_id, principal_user_id,
		principal_source, parent_run_id, depth, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'parent_run', $8, 1, now() + interval '4 hours')`,
		w.org, childRun, child, childInst, w.prod, inst, w.alice, run)
	return w.grants.Delegate(context.Background(), gapp.Workload{Org: w.org, InstanceID: inst, RunID: run},
		gapp.DelegateRequest{ChildRunID: childRun, TaskRef: "refunds"})
}

// TestHR290_ADelegatedGrantNeedsTheChildAgentsPromotion (D93 V1): a
// promoted agent delegating to an unpromoted production agent's child run
// is refused NOT_PROMOTED in the delegation's transaction; once the child
// agent is promoted provisionally, the delegated grant ends with that
// promotion, as stored.
func TestHR290_ADelegatedGrantNeedsTheChildAgentsPromotion(t *testing.T) {
	w := newWorld(t)
	promotiontest.Promote(t, w.scope, refund)
	b := w.prodAgent("refund-helper")
	_, err := w.delegateTo(w.agent, b)
	notPromoted(t, "a delegation to an unpromoted production agent", err)

	bs := w.scope
	bs.Agent = b
	w.replace(promotiontest.PromoteNew(t, bs, refund)[0], "1 minute")
	child, err := w.delegateTo(w.agent, b)
	if err != nil {
		t.Fatalf("a delegation to a provisionally promoted agent: %v", err)
	}
	if d := time.Until(child.ExpiresAt); d > 2*time.Minute {
		t.Fatalf("a delegated grant under a promotion ending in a minute expires in %s", d)
	}
	var stored time.Time
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT expires_at FROM pc.grant_revisions WHERE grant_id = $1", child.ID.UUID()).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if !stored.Equal(child.ExpiresAt) {
		t.Fatalf("stored expiry %s, returned %s", stored, child.ExpiresAt)
	}
}

// TestHR290_AConfirmedPromotionsOldExpiryNeverCaps (D93 V2): a
// provisional promotion confirmed ACTIVE keeps its old expiry on the row,
// but it neither caps a grant nor refuses one once that time has passed.
func TestHR290_AConfirmedPromotionsOldExpiryNeverCaps(t *testing.T) {
	w := newWorld(t)
	short := w.replace(promotiontest.PromoteNew(t, w.scope, refund)[0], "2 seconds")
	w.exec("UPDATE pc.agent_promotions SET state = 'ACTIVE', confirmed_at = now() WHERE id = $1", short)
	if state, confirmed, _ := w.promotion(short); state != promotions.StateActive || !confirmed {
		t.Fatalf("promotion %s confirmed %v", state, confirmed)
	}
	g, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	if err != nil || time.Until(g.ExpiresAt) < 23*time.Hour {
		t.Fatalf("a day's grant under a confirmed promotion: %v, expires in %s", err, time.Until(g.ExpiresAt))
	}
	time.Sleep(2500 * time.Millisecond)
	if g, err = w.issue(w.agent, `{"operations": ["payments.refund.create"]}`); err != nil || time.Until(g.ExpiresAt) < 23*time.Hour {
		t.Fatalf("a day's grant under a confirmed promotion past its old expiry: %v, expires in %s", err, time.Until(g.ExpiresAt))
	}
}

// ceilings is an automation ceiling that admits the world's agent.
type ceilings struct{ c gapp.AutomationCeiling }

func (f ceilings) IssueCeiling(context.Context, db.TenantTx, gapp.AutomationIssue) (gapp.AutomationCeiling, error) {
	return f.c, nil
}

func (ceilings) Reserve(context.Context, db.TenantTx, gapp.AutomationIssue, map[string]money.Decimal, bool) error {
	return nil
}

// TestHR290_AutomationIssuanceIsGatedAndCapped (D80, D93): automation
// issuance runs the same gate in the engine's transaction: an unpromoted
// production agent is refused NOT_PROMOTED, and a grant under a
// provisional promotion is capped at its expiry.
func TestHR290_AutomationIssuanceIsGatedAndCapped(t *testing.T) {
	w := newWorld(t)
	gate := promotions.Gate{Packages: &defpg.Store{Pool: w.pool}}
	gs := &gpg.Store{Pool: w.pool, Promotions: gate}
	sa, ceiling := ids.NewV7(), ids.NewV7()
	ops := gdomain.Ops{refund}
	lim, err := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"],
		"currency": "USD", "limit": "100", "period": "none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	principal := gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}
	svc := &gapp.Service{
		Repo: gs, Subjects: gs, Defs: &defpg.Store{Pool: w.pool}, Authz: gapp.SubjectAuthorizer{}, Clock: clock.System{},
		Store: gs, Promotions: gate, Ceilings: ceilings{gapp.AutomationCeiling{
			ID: ceiling, AutomationName: "refunds", ServiceAccount: sa, Agents: []ids.UUID{w.agent}, Principal: principal,
			Bounds: gdomain.Bounds{Operations: &ops}, TTL: 24 * time.Hour, Limits: lim,
		}},
	}
	issue := func() (gdomain.Grant, error) {
		var g gdomain.Grant
		err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			g, err = svc.IssueForAutomationTx(ctx, tx, gapp.AutomationIssue{
				Org: w.org, Automation: ids.NewV7(), Version: ids.NewV7(), Execution: ids.NewV7(), Ceiling: ceiling,
				ServiceAccount: sa, AgentID: w.agent, Principal: principal, TaskRef: "ticket T-1",
				Bounds: gdomain.Bounds{Operations: &gdomain.Ops{refund}}, Limits: lim, Live: true, DryRun: true,
			})
			return err
		})
		return g, err
	}
	_, err = issue()
	notPromoted(t, "automation issuance for an unpromoted production agent", err)

	pr := promotiontest.PromoteNew(t, w.scope, refund)
	g, err := issue()
	if err != nil {
		t.Fatalf("automation issuance under a provisional promotion: %v", err)
	}
	if g.ExpiresAt.After(*pr[0].ExpiresAt) {
		t.Fatalf("grant expiry %s after the promotion's %s", g.ExpiresAt, *pr[0].ExpiresAt)
	}
	w.replace(pr[0], "1 minute")
	if g, err = issue(); err != nil || time.Until(g.ExpiresAt) > 2*time.Minute {
		t.Fatalf("automation issuance under a promotion ending in a minute: %v, expires in %s", err, time.Until(g.ExpiresAt))
	}
}

// secondConnection adds another ACTIVE connection serving the payments
// package, with a route of the world's agent through it.
func (w *world) secondConnection() ids.UUID {
	w.t.Helper()
	id := ids.NewV7()
	w.exec(`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode, created_by, updated_by)
		SELECT org_id, $2, 'payments-eu', kind, gateway_id, package, 'https://payments-eu.example.test', access_mode, default_mode, created_by, updated_by
		FROM pc.connections WHERE id = $1`, w.conn, id)
	sc := w.scope
	sc.Connection = id
	promotiontest.Route(w.t, sc)
	return id
}

// TestHR290_CoverageIsCheckedOnEveryServingConnection (D93 V4): with two
// connections serving the operation, a passing record on one only makes
// the promotion PROVISIONAL, on both ACTIVE; a failing record on any
// connection refuses it outright.
func TestHR290_CoverageIsCheckedOnEveryServingConnection(t *testing.T) {
	w := newWorld(t)
	w.publishTest()
	promotiontest.Route(t, w.scope)
	eu := w.secondConnection()
	promotiontest.Record(t, w.scope, refund)
	p := promotiontest.NewPromoter(t, w.scope)
	res := w.promote(p)
	if len(res.Promoted) != 1 || res.Promoted[0].State != promotions.StateProvisional {
		t.Fatalf("a passing record on one of two serving connections promoted %+v", res.Promoted)
	}
	if c := res.Readiness[0].Checks[4]; !c.Pending || !strings.Contains(c.Detail, "coverage pending until ") {
		t.Fatalf("coverage %+v", c)
	}
	sc := w.scope
	sc.Connection = eu
	promotiontest.Record(t, sc, refund)
	if res = w.promote(p); len(res.Promoted) != 1 || res.Promoted[0].State != promotions.StateActive {
		t.Fatalf("passing records on every serving connection promoted %+v", res.Promoted)
	}

	// A failing record on either connection refuses the operation.
	w.exec("UPDATE pc.agent_promotions SET state = 'REVOKED', revoked_by = promoted_by, revoke_reason = 'test' WHERE id = $1", res.Promoted[0].ID)
	entry := ids.NewV7()
	w.exec(`INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, 'coverage.test', 'test', 'test', '\x7b7d')`, w.org, entry)
	w.exec(`INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body, body_sha256, ledger_entry_id)
		VALUES ($1, $2, $3, $4, $5, 'OBSERVE_ONLY', '{monitor_mode}', '{}', $6, $7)`, w.org, ids.NewV7(), w.agent, eu, refund, make([]byte, 32), entry)
	if res = w.promote(p); len(res.Promoted) != 0 || res.Readiness[0].Checks[4].Pending || res.Readiness[0].Provisional() {
		t.Fatalf("a failing record on a serving connection promoted %+v, readiness %+v", res.Promoted, res.Readiness[0])
	}
}

// TestHR290_NoRowCapDropsAFailingRecord (D93 V4): however many coverage
// records the agent has of other operations, the failing record of the
// operation checked is read and refuses it.
func TestHR290_NoRowCapDropsAFailingRecord(t *testing.T) {
	w := newWorld(t)
	w.publishTest()
	promotiontest.Route(t, w.scope)
	entry := ids.NewV7()
	w.exec(`INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, 'coverage.test', 'test', 'test', '\x7b7d')`, w.org, entry)
	w.exec(`WITH e AS (
			INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
			SELECT $1, gen_random_uuid(), 'coverage.test', 'test', 'test', '\x7b7d' FROM generate_series(1, 1100)
			RETURNING id)
		INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body, body_sha256, ledger_entry_id)
		SELECT $1, gen_random_uuid(), $2, $3, 'payments.other.op_' || row_number() OVER (), 'PARTIAL', '{agent_held}', '{}', $4, e.id
		FROM e`, w.org, w.agent, w.conn, make([]byte, 32))
	w.exec(`INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body, body_sha256, ledger_entry_id)
		VALUES ($1, $2, $3, $4, $5, 'OBSERVE_ONLY', '{monitor_mode}', '{}', $6, $7)`, w.org, ids.NewV7(), w.agent, w.conn, refund, make([]byte, 32), entry)
	res := w.promote(promotiontest.NewPromoter(t, w.scope))
	if len(res.Promoted) != 0 || res.Readiness[0].Checks[4].Pending {
		t.Fatalf("promoted %+v with readiness %+v", res.Promoted, res.Readiness[0])
	}
}

// TestHR290_APrefixCoversWhatTheAgentsConnectionsReach (D93 L2): a prefix
// expands to the operations the agent's own connections reach, not the
// org's: an agent with no connection yet finds nothing under payments.*.
func TestHR290_APrefixCoversWhatTheAgentsConnectionsReach(t *testing.T) {
	w := newWorld(t)
	p := promotiontest.NewPromoter(t, w.scope)
	_, err := w.svc.PromoteAgent(p.Ctx, promotions.PromoteInput{
		Agent: w.agent, Environment: w.prod, Operations: []string{"payments.*"}, FailureBehavior: promotions.FailClosed,
	}, p.StepUp())
	if pcerr.ReasonOf(err) != "NO_KNOWN_OPERATION" {
		t.Fatalf("a prefix for an agent without connections: %v, want NO_KNOWN_OPERATION", err)
	}
	promotiontest.Route(t, w.scope)
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		known, err := promotions.KnownUnder(ctx, tx, &defpg.Store{Pool: w.pool}, w.agent, "payments.*")
		if err == nil && !slices.Contains(known, refund) {
			t.Errorf("payments.* through the agent's connection covers %v", known)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
