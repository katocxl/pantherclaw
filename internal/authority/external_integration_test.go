// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// authzenAction is a refund on a new charge, as an enforcement point's
// action: channel authzen.
func (f fixture) authzenAction(t *testing.T, amount string, act ids.UUID) actionir.Parsed {
	t.Helper()
	p, err := actionir.Parse(f.action(t, amount, f.run, act))
	if err != nil {
		t.Fatal(err)
	}
	a := p.Action
	a.Channel = "authzen"
	out, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHR319_ExternalDecisionsCommitDelegated: an enforcement point's allowed action is
// decided, committed and recorded DELEGATED in one call (G0 M14 D28): its
// reservation is spent, never released, and the same action id never gets
// a second permit. Only actions of the authzen channel are decided here.
func TestHR319_ExternalDecisionsCommitDelegated(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	f.exec(t, "UPDATE pc.connections SET access_mode = 'agent_held' WHERE org_id = $1 AND id = $2", f.gw.Org, f.conn)
	ctx := context.Background()
	act := ids.NewV7()
	var decided ids.UUID
	req := authority.ExternalRequest{
		Gateway: f.gw, Action: f.authzenAction(t, "30.00", act), Credentials: f.creds(t, f.wl, f.wl.token),
		Decided: func(_ context.Context, txn ids.UUID) error { decided = txn; return nil },
	}
	res, err := f.svc.Decide(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed || res.Outcome != authority.ExternalAllow || res.Receipt == "" || res.TransactionID.IsZero() || decided != res.TransactionID {
		t.Fatalf("decide = %+v (decided %s)", res, decided)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.execution_attempts WHERE org_id = $1 AND outcome = 'delegated'`); n != 1 {
		t.Fatalf("delegated attempts: %d", n)
	}
	f.settle(t)
	if b := f.rawBudgetRow(t); b.Reserved.String() != "0" || b.Spent.String() != "30" {
		t.Fatalf("budget: reserved %s spent %s", b.Reserved, b.Spent)
	}

	// The same action again, with fresh credentials: decided already.
	again := req
	again.Credentials = f.creds(t, f.wl, f.wl.token)
	again.Action = f.authzenActionOn(t, req.Action)
	res, err = f.svc.Decide(ctx, again)
	if err != nil || res.Allowed || res.Code != authority.CodeDuplicate {
		t.Fatalf("resubmitted: %+v %v", res, err)
	}

	// An action of another channel is never decided here.
	p, err := actionir.Parse(f.action(t, "10.00", f.run, ids.NewV7()))
	if err != nil {
		t.Fatal(err)
	}
	res, err = f.svc.Decide(ctx, authority.ExternalRequest{Gateway: f.gw, Action: p, Credentials: f.creds(t, f.wl, f.wl.token)})
	if err != nil || res.Allowed || !res.TransactionID.IsZero() {
		t.Fatalf("an mcp action: %+v %v", res, err)
	}

	// A failure to record who asked commits nothing.
	boom := errors.New("not recorded")
	res, err = f.svc.Decide(ctx, authority.ExternalRequest{
		Gateway: f.gw, Action: f.authzenAction(t, "20.00", ids.NewV7()), Credentials: f.creds(t, f.wl, f.wl.token),
		Decided: func(context.Context, ids.UUID) error { return boom },
	})
	if err != nil || res.Allowed || res.Outcome != authority.ExternalCannotAuthorize || res.Code != authority.CodeDecidedVia {
		t.Fatalf("decided failed: %+v %v", res, err)
	}
	f.settle(t)
	if b := f.budgetRow(t); b.Spent.String() != "30" {
		t.Fatalf("a refused record spent: %s", b.Spent)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.execution_attempts WHERE org_id = $1`); n != 1 {
		t.Fatalf("attempts after a refused record: %d", n)
	}

	// Credentials that do not verify decide nothing.
	bad := f.creds(t, f.wl, f.wl.token)
	bad.Proof = "x" + bad.Proof
	res, err = f.svc.Decide(ctx, authority.ExternalRequest{Gateway: f.gw, Action: f.authzenAction(t, "5.00", ids.NewV7()), Credentials: bad})
	if err != nil || res.Allowed || res.Outcome != authority.ExternalCannotAuthorize || !res.TransactionID.IsZero() {
		t.Fatalf("a forged proof: %+v %v", res, err)
	}
}

// authzenActionOn returns p unchanged: the identical action, resubmitted.
func (f fixture) authzenActionOn(_ *testing.T, p actionir.Parsed) actionir.Parsed { return p }

// TestHR320_NothingIsDispatchedWhenWhoAskedIsNotRecorded: who asked for an
// authzen decision is recorded after the decision and before BeginDispatch;
// when that fails the answer is false CANNOT_AUTHORIZE, no attempt is
// recorded, and the permit expires and releases its reservation (D65).
func TestHR320_NothingIsDispatchedWhenWhoAskedIsNotRecorded(t *testing.T) {
	f := setup(t, "1000", 0, time.Microsecond)
	f.exec(t, "UPDATE pc.connections SET access_mode = 'agent_held' WHERE org_id = $1 AND id = $2", f.gw.Org, f.conn)
	res, err := f.svc.Decide(context.Background(), authority.ExternalRequest{
		Gateway: f.gw, Action: f.authzenAction(t, "40.00", ids.NewV7()), Credentials: f.creds(t, f.wl, f.wl.token),
		Decided: func(context.Context, ids.UUID) error { return errors.New("the record failed") },
	})
	if err != nil || res.Allowed || res.Outcome != authority.ExternalCannotAuthorize || res.Code != authority.CodeDecidedVia ||
		res.ActionToken != "" || res.TransactionID.IsZero() {
		t.Fatalf("decide: %+v %v", res, err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.execution_attempts WHERE org_id = $1`); n != 0 {
		t.Fatalf("attempts: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.permits WHERE org_id = $1 AND state = 'ISSUED'`); n != 1 {
		t.Fatalf("issued permits: %d", n)
	}
	if r, err := f.svc.SweepOrg(context.Background(), f.gw.Org, time.Hour); err != nil || r.Released != 1 {
		t.Fatalf("sweep: %+v %v", r, err)
	}
	if b := f.rawBudgetRow(t); b.Reserved.String() != "0" || b.Spent.String() != "0" {
		t.Fatalf("budget after expiry: reserved %s spent %s", b.Reserved, b.Spent)
	}
}

// TestHR320_TheGatewayPathRefusesAuthZEN: a gateway can neither have an
// authzen action decided nor BeginDispatch or record an authzen permit the
// external path issued; only that path commits it (D61, D65, D82 M2).
func TestHR320_TheGatewayPathRefusesAuthZEN(t *testing.T) {
	f := setup(t, "1000", 0, time.Minute)
	f.exec(t, "UPDATE pc.connections SET access_mode = 'agent_held' WHERE org_id = $1 AND id = $2", f.gw.Org, f.conn)
	ctx := authority.WithGateway(context.Background(), f.gw)
	h := authority.NewHandler(f.svc)
	act := f.authzenAction(t, "15.00", ids.NewV7())
	ar, err := h.Authorize(ctx, &pantherclawv1.AuthorizeRequest{ActionIr: act.Canonical})
	if err != nil || ar.GetDecision() != pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE || ar.GetPermit() != "" ||
		len(ar.GetReasons()) == 0 || ar.GetReasons()[0].GetCode() != authority.ReasonChannelNotAllowed {
		t.Fatalf("gateway authorize: %v %v", ar, err)
	}
	// An authzen permit, issued but not committed (who asked was not recorded).
	res, err := f.svc.Decide(context.Background(), authority.ExternalRequest{
		Gateway: f.gw, Action: f.authzenAction(t, "15.00", ids.NewV7()), Credentials: f.creds(t, f.wl, f.wl.token),
		Decided: func(context.Context, ids.UUID) error { return errors.New("not recorded") },
	})
	if err != nil || res.Allowed {
		t.Fatalf("decide: %+v %v", res, err)
	}
	permit := f.str(t, "SELECT id::text FROM pc.permits WHERE org_id = $1 AND transaction_id = $2", res.TransactionID)
	epoch := f.str(t, "SELECT epoch::text FROM pc.permits WHERE org_id = $1 AND transaction_id = $2", res.TransactionID)
	_, err = h.BeginDispatch(ctx, &pantherclawv1.BeginDispatchRequest{PermitId: permit, Epoch: mustInt(t, epoch)})
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("gateway BeginDispatch of an authzen permit: %v", err)
	}
	_, err = h.RecordExecution(ctx, &pantherclawv1.RecordExecutionRequest{PermitId: permit, Outcome: pantherclawv1.Outcome_OUTCOME_DELEGATED})
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("gateway RecordExecution of an authzen permit: %v", err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.permits WHERE org_id = $1 AND state = 'ISSUED'"); n != 1 {
		t.Fatalf("issued permits: %d", n)
	}
}

func (f fixture) str(t *testing.T, sql string, arg any) string {
	t.Helper()
	var s string
	if err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, f.gw.Org, arg).Scan(&s)
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func mustInt(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
