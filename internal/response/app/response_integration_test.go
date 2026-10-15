// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

func (w *world) containAgent() (ids.UUID, ids.UUID) {
	w.t.Helper()
	res, err := w.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: w.agent.String()}, Control: reflexdomain.ControlDenyAll,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	var control ids.UUID
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		cs, err := dbq.New(tx).ControlsOfAction(ctx, w.org, res.ActionID)
		if err == nil && len(cs) == 1 {
			control = cs[0].ID
		}
		return err
	}); err != nil || control.IsZero() {
		w.t.Fatalf("control of %s: %v", res.ActionID, err)
	}
	return res.ActionID, control
}

func (w *world) activeControls() []dbq.ActiveContainmentControlsRow {
	w.t.Helper()
	var out []dbq.ActiveContainmentControlsRow
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ActiveContainmentControls(ctx, w.org)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	return out
}

// TestHR250_RestorationNeedsAnIndependentReviewerAndPreconditions: the
// requester never decides their own restoration; an unmet precondition (the
// agent is suspended) refuses the lift and records why; an independent
// reviewer's approval lifts the control through the plan, raising the
// epoch. Closing nothing else: the run a termination revoked stays revoked.
func TestHR250_RestorationNeedsAnIndependentReviewerAndPreconditions(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	_, control := w.containAgent()
	term, err := w.terminate()
	if err != nil {
		t.Fatal(err)
	}
	bob := ids.NewV7()
	var plan ids.UUID
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		plan, _, err = w.c.RequestRestorationIn(ctx, tx, rapp.RestorationRequest{Controls: []ids.UUID{control}, Reason: "fixed", Requester: w.alice})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	decide := func(reviewer ids.UUID) (string, []rapp.Precondition, error) {
		var state string
		var pre []rapp.Precondition
		var derr error
		err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
			state, pre, derr = w.c.DecideRestorationIn(ctx, tx, plan, reviewer, true)
			if errors.Is(derr, rapp.ErrPreconditions) {
				return nil
			}
			return derr
		})
		if err != nil {
			return "", nil, err
		}
		return state, pre, derr
	}
	if _, _, err := decide(w.alice); !errors.Is(err, rapp.ErrRequesterDecides) {
		t.Fatalf("the requester decided: %v", err)
	}
	w.exec("UPDATE pc.agents SET state = 'SUSPENDED', suspended_from = 'DISCOVERED' WHERE org_id = $1 AND id = $2", w.org, w.agent)
	state, pre, err := decide(bob)
	if !errors.Is(err, rapp.ErrPreconditions) || state != rapp.PlanRequested || len(w.activeControls()) != 1 {
		t.Fatalf("an unmet precondition: %s %v, %d controls", state, err, len(w.activeControls()))
	}
	if pre[0].Check != "identity_reverified" || pre[0].State != rapp.PreUnmet {
		t.Fatalf("preconditions %+v", pre)
	}
	if n := w.count("SELECT count(*) FROM pc.restoration_plans WHERE org_id = $1 AND preconditions::text LIKE '%UNMET%'", w.org); n != 1 {
		t.Fatal("the unmet precondition was not recorded on the plan")
	}
	w.exec("UPDATE pc.agents SET state = 'DISCOVERED', suspended_from = NULL WHERE org_id = $1 AND id = $2", w.org, w.agent)
	before := w.epoch()
	if state, _, err := decide(bob); err != nil || state != rapp.PlanCompleted {
		t.Fatalf("approval: %s %v", state, err)
	}
	if len(w.activeControls()) != 0 || w.epoch() != before+1 {
		t.Fatalf("after the lift: %d controls, epoch %d (was %d)", len(w.activeControls()), w.epoch(), before)
	}
	if n := w.count("SELECT count(*) FROM pc.containment_controls WHERE org_id = $1 AND id = $2 AND restoration_id = $3", w.org, control, plan); n != 1 {
		t.Fatal("the lift does not name its plan")
	}
	if n := w.count("SELECT count(*) FROM pc.runs WHERE org_id = $1 AND id = $2 AND state = 'REVOKED'", w.org, w.run); n != 1 {
		t.Fatalf("restoration revived the terminated run (action %s)", term)
	}
}

// fakeReplay decides every test action as given.
type fakeReplay struct{ permits map[ids.UUID]bool }

func (f fakeReplay) ReplayContained(_ context.Context, _ ids.OrgID, txn ids.UUID, _ int, controls []pipeline.Control) (*replay.Outcome, error) {
	d := adomain.Deny
	if f.permits[txn] && len(controls) == 0 {
		d = adomain.Allow
	}
	return &replay.Outcome{Complete: true, Decision: d, Reason: "TEST"}, nil
}

// TestHR250_StagedRestorationWidensOnlyAfterItsTests: each stage lifts its
// own controls only once its test actions pass, dry run, against the
// controls that would remain; stages go in order, and a failing stage lifts
// nothing.
func TestHR250_StagedRestorationWidensOnlyAfterItsTests(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	_, first := w.containAgent()
	res, err := w.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}, Control: reflexdomain.ControlHoldWrites,
	})
	if err != nil {
		t.Fatal(err)
	}
	var second ids.UUID
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		cs, err := dbq.New(tx).ControlsOfAction(ctx, w.org, res.ActionID)
		second = cs[0].ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	permitted, prohibited := ids.NewV7(), ids.NewV7()
	bob := ids.NewV7()
	var plan ids.UUID
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		plan, _, err = w.c.RequestRestorationIn(ctx, tx, rapp.RestorationRequest{
			Controls: []ids.UUID{first, second}, Reason: "staged", Requester: w.alice,
			Stages: []rapp.StageSpec{
				{Controls: []ids.UUID{first}, Tests: []rapp.TestAction{{Transaction: prohibited, Evaluation: 1, Expect: rapp.ExpectProhibited}}},
				{Controls: []ids.UUID{second}, Tests: []rapp.TestAction{{Transaction: permitted, Evaluation: 1, Expect: rapp.ExpectPermitted}}},
			},
		})
		if err != nil {
			return err
		}
		_, _, err = w.c.DecideRestorationIn(ctx, tx, plan, bob, true)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(w.activeControls()) != 2 {
		t.Fatal("approving a staged plan lifted controls before its stages")
	}
	apply := func(ordinal int32, r rapp.Replayer) (string, error) {
		var sp rapp.StagePlan
		if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
			var err error
			sp, err = w.c.StageToApply(ctx, tx, plan, ordinal)
			return err
		}); err != nil {
			return "", err
		}
		results, passed, err := rapp.RunStageTests(context.Background(), r, w.org, sp)
		if err != nil {
			return "", err
		}
		var state string
		err = w.tx(func(ctx context.Context, tx db.TenantTx) error {
			var err error
			state, err = w.c.ApplyStageIn(ctx, tx, sp, bob, results, passed)
			return err
		})
		return state, err
	}
	if _, err := apply(2, fakeReplay{}); !errors.Is(err, rapp.ErrStageOrder) {
		t.Fatalf("stage 2 first: %v", err)
	}
	// Stage 1: the prohibited action stays denied while the run's control
	// remains, so stage 1 lifts the agent's control.
	if state, err := apply(1, fakeReplay{}); err != nil || state != rapp.PlanStaging {
		t.Fatalf("stage 1: %s %v", state, err)
	}
	if cs := w.activeControls(); len(cs) != 1 || cs[0].ID != second {
		t.Fatalf("after stage 1: %+v", cs)
	}
	// Stage 2's permitted test fails: nothing is lifted.
	if state, err := apply(2, fakeReplay{}); err != nil || state != rapp.PlanStaging || len(w.activeControls()) != 1 {
		t.Fatalf("a failing stage 2: %s %v", state, err)
	}
	if state, err := apply(2, fakeReplay{permits: map[ids.UUID]bool{permitted: true}}); err != nil || state != rapp.PlanCompleted {
		t.Fatalf("stage 2: %s %v", state, err)
	}
	if len(w.activeControls()) != 0 {
		t.Fatal("the plan completed with a control left")
	}
}

// TestHR251_SOARRequestsAreNarrowIdempotentAndAudited: a SOAR request adds
// one control on a run, agent, grant or connection (a grant needs no
// preview), never a resource or a person; a repeated key returns the same
// action, a different request under it is refused; the action records its
// SOAR source and is audited; PARTIAL reads as UNKNOWN. Wide SOAR
// controls are rate limited (D50).
func TestHR251_SOARRequestsAreNarrowIdempotentAndAudited(t *testing.T) {
	w := newWorld(t, "OBSERVE_ONLY")
	sa := reflexdomain.Subject{Type: reflexdomain.SubjectServiceAccount, ID: ids.NewV7().String()}
	req := func(key string, scope reflexdomain.Subject, control string) (rapp.SOARResult, error) {
		var out rapp.SOARResult
		err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
			var err error
			out, err = w.c.RequestControlIn(ctx, tx, rapp.SOARRequest{Key: key, Scope: scope, Control: control, Reason: "edr verdict", Requester: sa})
			return err
		})
		return out, err
	}
	for _, scope := range []reflexdomain.Subject{
		{Type: reflexdomain.SubjectResource, ID: "payments.charge:ch_*"},
		{Type: reflexdomain.SubjectUser, ID: w.alice.String()},
		{Type: reflexdomain.SubjectIncident, ID: ids.NewV7().String()},
	} {
		if _, err := req("k-"+string(scope.Type), scope, rdomain.DenyAll); !errors.Is(err, rapp.ErrSOARScope) {
			t.Errorf("%s: %v", scope.Type, err)
		}
	}
	agent := reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: w.agent.String()}
	first, err := req("edr-1", agent, rdomain.DenyAll)
	if err != nil {
		t.Fatal(err)
	}
	if first.Result != rapp.SOARUnknown {
		t.Fatalf("a bypass route left it %s, want UNKNOWN", first.Result)
	}
	again, err := req("edr-1", agent, rdomain.DenyAll)
	if err != nil || again.ActionID != first.ActionID || !again.Replayed {
		t.Fatalf("repeat: %+v %v", again, err)
	}
	if _, err := req("edr-1", agent, rdomain.HoldWrites); !errors.Is(err, rapp.ErrIdempotency) {
		t.Fatalf("a different request under the key: %v", err)
	}
	if _, err := req("edr-2", reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: w.grant.String()}, rdomain.HoldWrites); err != nil {
		t.Fatalf("a grant: %v", err)
	}
	if n := w.count(`SELECT count(*) FROM pc.response_actions WHERE org_id = $1 AND source = 'SOAR'`, w.org); n != 2 {
		t.Fatalf("%d SOAR actions, want 2", n)
	}
	// D50: at most 10 wide (grant or connection) SOAR controls an hour; past
	// that, FAILED RATE_LIMITED with no action, and one owned failure an hour.
	for i := range 9 {
		if _, err := req("wide-"+strconv.Itoa(i), reflexdomain.Subject{Type: reflexdomain.SubjectConnection, ID: w.conn.String()}, rdomain.HoldWrites); err != nil {
			t.Fatalf("wide request %d: %v", i+2, err)
		}
	}
	for _, key := range []string{"over-1", "over-2"} {
		res, err := req(key, reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: w.grant.String()}, rdomain.DenyAll)
		if err != nil || res.Result != rapp.SOARFailed || res.Reason != rapp.ReasonRateLimited || !res.ActionID.IsZero() {
			t.Fatalf("over the limit: %+v %v", res, err)
		}
	}
	if n := w.count(`SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = 'soar_rate_limited'`, w.org); n != 1 {
		t.Fatalf("%d rate-limit failures, want 1", n)
	}
	if _, err := req("narrow-after", reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}, rdomain.DenyAll); err != nil {
		t.Fatalf("a narrow request past the wide limit: %v", err)
	}
	if n := w.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.response.contain'
		AND convert_from(body, 'UTF8')::jsonb #>> '{details,source}' = 'SOAR' AND convert_from(body, 'UTF8')::jsonb #>> '{details,reason}' = 'edr verdict'`, w.org); n != 12 {
		t.Fatalf("%d audited SOAR actions, want every one of the 12", n)
	}
	if n := w.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.response.soar_rate_limited'`, w.org); n != 2 {
		t.Fatalf("%d audited refusals, want 2", n)
	}
}

// TestHR252_CredentialChangesDiscloseEverySharerFirst: revoking a sealed
// credential needs the digest of a preview listing the agents with a route
// through its connection; a stale preview is refused. Rotating a static
// credential needs a new value sealed first.
func TestHR252_CredentialChangesDiscloseEverySharerFirst(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	w.sealed(1, "ACTIVE")
	preview := func() rapp.CredentialPreview {
		var p rapp.CredentialPreview
		if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
			var err error
			p, err = w.c.PreviewCredentialIn(ctx, tx, w.conn, 1)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	change := func(digest []byte, rotate bool) (reflexdomain.ContainResult, error) {
		var out reflexdomain.ContainResult
		err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
			r := rapp.CredentialChange{
				Connection: w.conn, Version: 1, Reason: "leaked", PreviewDigest: digest,
				Actor: reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: w.alice.String()},
			}
			var err error
			if rotate {
				out, err = w.c.RotateCredentialIn(ctx, tx, r)
			} else {
				out, err = w.c.RevokeCredentialIn(ctx, tx, r)
			}
			return err
		})
		return out, err
	}
	p := preview()
	if len(p.Agents) != 0 {
		t.Fatalf("sharers before any route: %v", p.Agents)
	}
	if _, err := change(nil, false); !errors.Is(err, rapp.ErrCredentialPreview) {
		t.Fatalf("without a preview: %v", err)
	}
	if _, err := change(p.Digest, true); !errors.Is(err, rapp.ErrSealFirst) {
		t.Fatalf("rotating with nothing sealed: %v", err)
	}
	// An agent starts using the connection: the earlier preview is stale.
	w.exec(`INSERT INTO pc.coverage_routes (org_id, id, agent_id, connection_id, kind, channel, observation, source)
		VALUES ($1, $2, $3, $4, 'channel', 'http', 'observed', 'gateway')`, w.org, ids.NewV7(), w.agent, w.conn)
	if _, err := change(p.Digest, false); !errors.Is(err, rapp.ErrCredentialPreview) {
		t.Fatalf("with a stale preview: %v", err)
	}
	p = preview()
	if len(p.Agents) != 1 || p.Agents[0] != w.agent || len(p.Runs) != 1 {
		t.Fatalf("preview %+v", p)
	}
	before := w.epoch()
	res, err := change(p.Digest, false)
	if err != nil {
		t.Fatal(err)
	}
	if w.epoch() != before+1 || w.count("SELECT count(*) FROM pc.credentials WHERE org_id = $1 AND state = 'REVOKED'", w.org) != 1 {
		t.Fatal("the revoke did not take the existing path")
	}
	if a := w.action(res.ActionID); a.Kind != rdomain.KindRevoke || a.Status != string(rdomain.StatusRequested) {
		t.Fatalf("revoke action %s %s", a.Kind, a.Status)
	}
	w.deliver(before + 1)
	if a := w.advance(res.ActionID); a.Status != string(rdomain.StatusConfirmed) {
		t.Fatalf("after the gateway got the epoch: %s", a.Status)
	}
}

// TestT108_TerminationIsConfirmedOnlyWhenDispatchedWorkEnds: a terminated
// run is revoked and denied; its dispatch still in flight is a material,
// not-cancellable path, so the action is not CONFIRMED until that dispatch
// ends, whatever the gateway says.
func TestT108_TerminationIsConfirmedOnlyWhenDispatchedWorkEnds(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	txn := w.inFlight()
	id, err := w.terminate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.terminate(); !errors.Is(err, rapp.ErrRunNotActive) {
		t.Fatalf("terminating twice: %v", err)
	}
	a := w.action(id)
	w.deliver(a.Epoch.Int64)
	if a = w.advance(id); a.Status == string(rdomain.StatusConfirmed) {
		t.Fatal("confirmed while a dispatch is in flight")
	}
	w.exec("UPDATE pc.permits SET state = 'DISPATCHED', finished_at = now() WHERE org_id = $1 AND transaction_id = $2", w.org, txn)
	if a = w.advance(id); a.Status != string(rdomain.StatusConfirmed) {
		t.Fatalf("after the dispatch ended: %s", a.Status)
	}
}

func (w *world) terminate() (ids.UUID, error) {
	var out reflexdomain.ContainResult
	err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = w.c.TerminateIn(ctx, tx, rapp.Termination{
			Run: w.run, Reason: "exfiltration",
			Actor: reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: w.alice.String()},
		})
		return err
	})
	return out.ActionID, err
}

func (w *world) epoch() int64 {
	w.t.Helper()
	var e int64
	w.d.AdminQueryRow(w.t, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", []any{w.org}, &e)
	return e
}

// inFlight records a transaction of the run whose permit is DISPATCHING.
func (w *world) inFlight() ids.UUID {
	w.t.Helper()
	txn, budget := ids.NewV7(), ids.NewV7()
	w.exec(`INSERT INTO pc.budgets (org_id, id, name, currency, limit_amount) VALUES ($1, $2, 'refunds', 'USD', 100)`, w.org, budget)
	w.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id)
		VALUES ($1, $2, $3, $4, decode(repeat('00', 32), 'hex'), 'payments.refund.create', 'ALLOW', 'GRANT_COVERS', $5)`,
		w.org, txn, w.run, ids.NewV7(), w.gateway.String())
	w.exec(`INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, state, budget_id, amount, expires_at, dispatching_at)
		VALUES ($1, $2, $3, $4, 1, 'DISPATCHING', $5, 0, now() + interval '1 minute', now())`, w.org, ids.NewV7(), txn, w.gateway.String(), budget)
	return txn
}

// sealed stores a sealed credential version of the connection, without a
// broker key (its foreign key is not what is tested).
func (w *world) sealed(version int, state string) {
	w.t.Helper()
	w.exec("ALTER TABLE pc.credentials DISABLE TRIGGER ALL")
	w.exec(`INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, state, created_by)
		VALUES ($1, $2, $3, $4, $5, decode(repeat('00', 1200), 'hex'), '{payments.test}', 'X-Api-Key', $6, 'test')`,
		w.org, ids.NewV7(), w.conn, version, ids.NewV7(), state)
	w.exec("ALTER TABLE pc.credentials ENABLE TRIGGER ALL")
}
