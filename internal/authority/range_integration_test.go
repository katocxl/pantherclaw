// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// rangeSide is the range agent's workload and run next to the fixture's
// real ones, with a simulated connection on the same gateway.
type rangeSide struct {
	fixture
	simConn ids.UUID
}

// withRange adds a range agent with an admitted instance, a simulated run
// and a simulated connection to the fixture's gateway.
func withRange(t *testing.T, f fixture) rangeSide {
	t.Helper()
	a, err := f.inv.Create(f.ownerCtx(), adomain.Details{
		Name: "range refunder", TeamID: f.team, EnvironmentID: f.env, OwnerUserID: f.owner, Context: adomain.ContextService, RangeAgent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		return aapp.MarkVerified(ctx, dbq.New(tx), f.gw.Org, a.ID, adomain.System)
	}); err != nil {
		t.Fatal(err)
	}
	r := rangeSide{fixture: f, simConn: ids.NewV7()}
	r.wl = f.admitted(t, a.ID)
	r.run = f.startRun(t, a.ID, &r.wl.inst.Instance)
	r.grant = f.grantFor(t, a.ID)
	gw, err := ids.ParseUUID(f.gw.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
		created_by, updated_by, simulated) VALUES ($1, $2, 'payments-sim', 'http', $3, 'pc.mock-payments', 'http://127.0.0.1:9000',
		'none', 'enforce', 'test', 'test', true)`, f.gw.Org, r.simConn, gw)
	return r
}

// via authorizes a refund of the fixture's run through conn.
func (f fixture) via(t *testing.T, conn ids.UUID) authority.Result {
	t.Helper()
	f.conn = conn
	return f.authorize(t, "30.00")
}

// papOf returns the pap claims of a compact JWS.
func papOf(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %.40s", jws)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Pap map[string]any `json:"pap"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Pap
}

// receipts returns the claims of every receipt the org holds, by kind.
func (f fixture) receipts(t *testing.T) map[string][]map[string]any {
	t.Helper()
	out := map[string][]map[string]any{}
	for kind, table := range map[string]string{"decision": "decision_receipts", "execution": "execution_receipts", "effect": "effect_receipts"} {
		var all []string
		if err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
			rows, err := tx.Query(ctx, "SELECT receipt_jws FROM pc."+table+" WHERE org_id = $1", f.gw.Org)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err != nil {
					return err
				}
				all = append(all, s)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		for _, s := range all {
			out[kind] = append(out[kind], papOf(t, s))
		}
	}
	return out
}

// dispatchAndRecord takes a permit through dispatch and an accepted
// execution.
func (f fixture) dispatchAndRecord(t *testing.T, res authority.Result) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch, authority.Outbound{}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(`{"id":"re_1"}`))
	if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{
		Permit: res.PermitID, Outcome: authority.Accepted, TargetStatus: 200, ResponseDigest: digest[:], DispatchMS: 5,
	}); err != nil {
		t.Fatal(err)
	}
}

func allSimulated(t *testing.T, what string, rs map[string][]map[string]any, want bool) {
	t.Helper()
	if len(rs["decision"]) == 0 || len(rs["execution"]) == 0 {
		t.Fatalf("%s: receipts %v, want a decision and an execution receipt", what, rs)
	}
	for kind, list := range rs {
		for _, pap := range list {
			if got, ok := pap["simulated"].(bool); !ok || got != want {
				t.Errorf("%s: a %s receipt says simulated=%v (present %v), want %v", what, kind, pap["simulated"], ok, want)
			}
		}
	}
}

// TestHR120_EveryReceiptOfARangeRunIsSimulated (D5): the decision,
// execution and effect receipts of a range run's transaction all say
// simulated: true.
func TestHR120_EveryReceiptOfARangeRunIsSimulated(t *testing.T) {
	r := withRange(t, setup(t, "1000", 0, time.Minute))
	res := r.via(t, r.simConn)
	if res.Decision != domain.Allow {
		t.Fatalf("a range run on a simulated connection: %+v", res)
	}
	r.dispatchAndRecord(t, res)
	rs := r.receipts(t)
	allSimulated(t, "range run", rs, true)
	t.Logf("range receipts: %d decision, %d execution, %d effect", len(rs["decision"]), len(rs["execution"]), len(rs["effect"]))
}

// TestHR120_RealRunsReceiptsStayUnsimulated: a real run's receipts say
// simulated: false.
func TestHR120_RealRunsReceiptsStayUnsimulated(t *testing.T) {
	f := setup(t, "1000", 0, time.Minute)
	res := f.authorize(t, "30.00")
	if res.Decision != domain.Allow {
		t.Fatalf("real run: %+v", res)
	}
	f.dispatchAndRecord(t, res)
	allSimulated(t, "real run", f.receipts(t), false)
}

// TestT038_ARangeRunNeverReachesARealConnection (HR-120, HR-220): a range
// run on a real connection, and a real run on a simulated one, are denied
// SIMULATION_MISMATCH with no permit.
func TestT038_ARangeRunNeverReachesARealConnection(t *testing.T) {
	base := setup(t, "1000", 0, time.Minute)
	r := withRange(t, base)

	toReal := r.via(t, base.conn)
	wantDecision(t, "range run on a real connection", toReal, domain.Deny, pipeline.ReasonSimulationMismatch, "")
	if toReal.Permit != "" {
		t.Error("a range run got a permit on a real connection")
	}
	toSim := base.via(t, r.simConn)
	wantDecision(t, "real run on a simulated connection", toSim, domain.Deny, pipeline.ReasonSimulationMismatch, "")
	if toSim.Permit != "" {
		t.Error("a real run got a permit on a simulated connection")
	}
	if n := base.count(t, "SELECT count(*) FROM pc.permits WHERE org_id = $1"); n != 0 {
		t.Errorf("%d permits issued across the boundary", n)
	}
	sims := map[bool]int{}
	for _, p := range base.receipts(t)["decision"] {
		sims[p["simulated"] == true]++
	}
	if sims[true] != 1 || sims[false] != 1 {
		t.Errorf("denial receipts by flag: %v, want one each", sims)
	}
}

// TestT090_RangeActivityLeavesRealStateAlone: a range run's decision,
// dispatch and execution change no containment epoch, no kill switch and no
// package state.
func TestT090_RangeActivityLeavesRealStateAlone(t *testing.T) {
	r := withRange(t, setup(t, "1000", 0, time.Minute))
	state := func() string {
		var s string
		if err := r.pool.InTenantTx(context.Background(), r.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT c.epoch::text || '/' || c.kill_switch::text || '/' ||
				coalesce((SELECT string_agg(state, ',' ORDER BY id) FROM pc.package_versions WHERE org_id = c.org_id), '')
				FROM pc.org_containment c WHERE c.org_id = $1`, r.gw.Org).Scan(&s)
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := state()
	res := r.via(t, r.simConn)
	r.dispatchAndRecord(t, res)
	if after := state(); after != before {
		t.Fatalf("real state changed: %s -> %s", before, after)
	}
}

// TestHR222_SecurityEventsOfARangeRunSaySimulated: the audit event written
// when a range run's action id is reused with a changed action (outside the
// notification outbox) says simulated=true; a real run's does not.
func TestHR222_SecurityEventsOfARangeRunSaySimulated(t *testing.T) {
	base := setup(t, "1000", 0, time.Minute)
	r := withRange(t, base)
	tamper := func(f fixture, conn ids.UUID) {
		f.conn = conn
		act, charge := ids.NewV7(), f.charge(t)
		env, inst := f.env.String(), f.wl.inst.Instance.String()
		ctx := context.Background()
		if _, err := f.svc.Authorize(ctx, f.gw, f.actionOn(t, charge, "30.00", f.run, act, env, inst), f.creds(t, f.wl, f.wl.token)); err != nil {
			t.Fatal(err)
		}
		res, err := f.svc.Authorize(ctx, f.gw, f.actionOn(t, charge, "90.00", f.run, act, env, inst), f.creds(t, f.wl, f.wl.token))
		if err != nil || res.Decision != domain.Deny {
			t.Fatalf("tamper: %+v, %v", res, err)
		}
	}
	tamper(r.fixture, r.simConn)
	tamper(base, base.conn)
	body := func(sim bool) int {
		var n int
		if err := base.pool.InTenantTx(context.Background(), base.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.security.action_tampered'
				AND (convert_from(body, 'UTF8') LIKE '%"simulated":"true"%') = $2`, base.gw.Org, sim).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if body(true) != 1 || body(false) != 1 {
		t.Fatalf("tamper events: %d labeled, %d not; want one each", body(true), body(false))
	}
}
