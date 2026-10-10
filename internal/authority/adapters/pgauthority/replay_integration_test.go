// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factpg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// rowCounts counts the rows of every table in schema pc, as the admin: what
// a replay must leave unchanged.
func (w *world) rowCounts() map[string]int64 {
	w.t.Helper()
	var list string
	w.db.AdminQueryRow(w.t, `SELECT string_agg(c.relname, ',' ORDER BY c.relname) FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'pc' AND c.relkind IN ('r', 'p')`, nil, &list)
	tables := strings.Split(list, ",")
	out := make(map[string]int64, len(tables))
	for _, tb := range tables {
		var n int64
		w.db.AdminQueryRow(w.t, fmt.Sprintf("SELECT count(*) FROM pc.%s", pgx.Identifier{tb}.Sanitize()), nil, &n)
		out[tb] = n
	}
	return out
}

func (w *world) replayEngine() *replay.Engine {
	w.t.Helper()
	return &replay.Engine{
		Source: &pgauthority.ReplaySource{Pool: w.pool, Definitions: &defpg.Store{Pool: w.pool}, FactStore: &factpg.Store{Pool: w.pool}},
		Inputs: w.auth.Inputs.(replay.Opener),
	}
}

// publishPolicy stores rules as a new version of the org's policy and
// publishes it unless draft; it returns the version's id.
func (w *world) publishPolicy(version int, draft bool, rules ...pdomain.Rule) ids.UUID {
	w.t.Helper()
	store := &polpg.Store{Pool: w.pool}
	id, got, err := store.CreateVersion(context.Background(), w.org, &pdomain.Bundle{ID: "org-policy", Rules: rules}, w.alice.String(), nil)
	if err != nil || got != version {
		w.t.Fatalf("policy version %d: %v", got, err)
	}
	if !draft {
		if err := store.Publish(context.Background(), w.org, id, w.alice.String(), nil); err != nil {
			w.t.Fatal(err)
		}
	}
	return id
}

var (
	pgHoldOver50 = pdomain.Rule{
		ID: "hold", Kind: pdomain.RequireApproval, Summary: "over 50 needs approval", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("50", "USD")`, Reason: "REFUND_OVER_50", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
	pgForbidOver20 = pdomain.Rule{
		ID: "no-large-refunds", Kind: pdomain.Forbid, Summary: "no refunds over 20", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("20", "USD")`, Reason: "REFUND_TOO_LARGE",
	}
)

// TestHR197_ReplayWritesNothing: replays of an allowed, a held and a denied
// decision, unchanged and under a proposed policy, leave every table of the
// database exactly as it was: no transaction, receipt, reservation, permit,
// claim, ledger entry or audit event (F508). The unchanged ones reproduce
// their decision; the proposed policy denies the allowed refund and names
// its rule.
func TestHR197_ReplayWritesNothing(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2")
	w.publishPolicy(1, false, pgHoldOver50)
	draft := w.publishPolicy(2, true, pgHoldOver50, pgForbidOver20)
	run := w.run(w.grant("500").ID, ids.UUID{})
	results := []finalize.Result{
		w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00")),
		w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00")),
		w.authorize(w.request(run, ids.NewV7(), "ch_2", "125.00")),
	}
	if results[0].Decision != adomain.Allow || results[1].Decision != adomain.RequireApproval || results[2].Decision != adomain.Deny {
		t.Fatalf("decisions: %s %s %s", results[0].Decision, results[1].Decision, results[2].Decision)
	}
	engine := w.replayEngine()
	before := w.rowCounts()
	ctx := context.Background()
	for _, r := range results {
		same, err := engine.Replay(ctx, w.org, r.TransactionID, r.Evaluation, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !same.Reproduced || same.Decision != r.Decision || same.BasisDigest != r.BasisDigest || same.Policy != "org-policy@1" {
			t.Errorf("unchanged replay of %s: %+v", r.Decision, same)
		}
		if _, err := engine.Replay(ctx, w.org, r.TransactionID, r.Evaluation, &draft); err != nil {
			t.Fatal(err)
		}
	}
	proposed, err := engine.Replay(ctx, w.org, results[0].TransactionID, 1, &draft)
	if err != nil {
		t.Fatal(err)
	}
	if !proposed.Complete || proposed.Decision != adomain.Deny || proposed.Reason != "REFUND_TOO_LARGE" ||
		!slices.ContainsFunc(proposed.Differences, func(d replay.Difference) bool {
			return d.Step == pipeline.StepBoundaries && slices.Equal(d.Rules, []string{"no-large-refunds"})
		}) {
		t.Fatalf("proposed: %+v", proposed)
	}
	after := w.rowCounts()
	for tb, n := range before {
		if after[tb] != n {
			t.Errorf("table %s: %d rows before the replays, %d after", tb, n, after[tb])
		}
	}
	if len(after) != len(before) || len(before) < 50 {
		t.Fatalf("tables counted: %d before, %d after", len(before), len(after))
	}
}

// TestIntReplaySourceIsScopedToItsOrg: the source finds an evaluation's
// inputs in its org only, and a missing receipt is not found (T-037).
func TestIntReplaySourceIsScopedToItsOrg(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1")
	r := w.authorize(w.request(w.run(w.grant("500").ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
	src := &pgauthority.ReplaySource{Pool: w.pool, Definitions: &defpg.Store{Pool: w.pool}, FactStore: &factpg.Store{Pool: w.pool}}
	if _, err := src.Inputs(context.Background(), w.org, r.TransactionID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Receipt(context.Background(), w.org, r.TransactionID, 2); err != replay.ErrNotFound { //nolint:errorlint // the sentinel itself
		t.Fatalf("a missing receipt: %v", err)
	}
	other := ids.New[ids.Org]()
	if _, err := src.Inputs(context.Background(), other, r.TransactionID, 1); err != replay.ErrNotFound { //nolint:errorlint // the sentinel itself
		t.Fatalf("another org's inputs: %v", err)
	}
}
