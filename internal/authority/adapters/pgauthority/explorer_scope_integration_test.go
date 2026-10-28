// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// scopedExplorer is a world whose transactions alternate between the
// world's agent (team payments) and an agent of another team, newest
// first hidden, visible, hidden, ...; each has an unknown outcome and so
// an open reconciliation.
type scopedExplorer struct {
	w                *world
	visible, hidden  []ids.UUID // transactions
	otherTeam        ids.UUID
	visibleReconcile []ids.UUID
	hiddenReconcile  []ids.UUID
}

func newScopedExplorer(t *testing.T, n int) *scopedExplorer {
	t.Helper()
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	charges := make([]string, n)
	for i := range charges {
		charges[i] = fmt.Sprintf("ch_%d", i+1)
	}
	w.refundable(charges...)
	s := &scopedExplorer{w: w, otherTeam: ids.NewV7()}
	env, agent, instance := ids.NewV7(), ids.NewV7(), ids.NewV7()
	exec(t, w.pool, w.org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'growth', 'Growth')", w.org, s.otherTeam)
	exec(t, w.pool, w.org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')",
		w.org, env, s.otherTeam)
	exec(t, w.pool, w.org, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, 'growth-bot', $3, $4, $5, 'service', 'VERIFIED', 'test', now())`, w.org, agent, s.otherTeam, env, w.alice)
	exec(t, w.pool, w.org, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, w.org, instance, agent, fmt.Sprintf("%043d", time.Now().UnixNano()%1e12+1))
	g := w.grant("500")
	for i, ch := range charges {
		run := w.run(g.ID, ids.UUID{})
		r := w.recorded(run, ch, "10.00", finalize.Unknown, "")
		task, err := ids.ParseUUID(w.str("SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID))
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 1 {
			// The run (and so its transaction) belongs to the other team's
			// agent from here on.
			w.db.AdminExec(t, "UPDATE pc.runs SET agent_id = $1, instance_id = $2, environment_id = $3 WHERE id = $4", agent, instance, env, run)
			s.hidden, s.hiddenReconcile = append(s.hidden, r.TransactionID), append(s.hiddenReconcile, task)
			continue
		}
		s.visible, s.visibleReconcile = append(s.visible, r.TransactionID), append(s.visibleReconcile, task)
	}
	return s
}

// pages lists every page of size through list, checking that each page
// but the last is full and the last has no next token.
func pages[T any](t *testing.T, size int, list func(page.Request) ([]T, string, error), id func(T) ids.UUID) []ids.UUID {
	t.Helper()
	var out []ids.UUID
	pr := page.Request{Size: size}
	for range 100 {
		items, next, err := list(pr)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			out = append(out, id(it))
		}
		if next == "" {
			if len(items) == 0 && len(out) > 0 {
				t.Fatal("an empty last page after a full one: the cursor stood on a hidden row")
			}
			return out
		}
		if len(items) != size {
			t.Fatalf("a page of %d with a next token, want %d: the page was cut before hidden rows were filtered", len(items), size)
		}
		var err2 error
		if pr, err2 = page.Parse(int32(size), next); err2 != nil { //nolint:gosec // small
			t.Fatal(err2)
		}
	}
	t.Fatal("paging did not end")
	return nil
}

func sameSet(a, b []ids.UUID) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, compareIDs)
	slices.SortFunc(b, compareIDs)
	return slices.Equal(a, b)
}

// TestT042_AScopedViewersTransactionPagesAreFullAndHideOtherTeams (G0 M10
// D60, T-042, T-037): a viewer holding evidence.read on one team pages
// through transactions in full pages that hold every one of the team's and
// none of another team's, newest first, and the cursor ends on the last
// visible one. The org's auditor pages through all of them; the other
// team's viewer sees only theirs.
func TestT042_AScopedViewersTransactionPagesAreFullAndHideOtherTeams(t *testing.T) {
	s := newScopedExplorer(t, 8)
	w := s.w
	e := &txapp.Explorer{Pool: w.pool}
	list := func(who context.Context) func(page.Request) ([]txapp.Summary, string, error) {
		return func(pr page.Request) ([]txapp.Summary, string, error) {
			p, err := e.ListTransactions(who, pr, txapp.Filter{})
			return p.Items, p.Next, err
		}
	}
	id := func(x txapp.Summary) ids.UUID { return x.ID }

	team := w.reader(tdomain.RoleAuditor, tdomain.Scope{Type: tdomain.ScopeTeam, ID: w.teamOfAgent()})
	for _, size := range []int{1, 2, 3} {
		got := pages(t, size, list(team), id)
		if !sameSet(got, s.visible) {
			t.Fatalf("size %d: the team's viewer paged %v, want %v", size, got, s.visible)
		}
		if !slices.IsSortedFunc(got, func(a, b ids.UUID) int { return -compareIDs(a, b) }) {
			t.Fatalf("size %d: not newest first", size)
		}
	}
	p, err := e.ListTransactions(team, page.Request{Size: page.Max}, txapp.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(p.Items, func(x txapp.Summary) bool { return slices.Contains(s.hidden, x.ID) }) {
		t.Fatal("another team's transaction is listed")
	}
	// Filtering by another team's run finds nothing, not a short page.
	var hiddenRun ids.UUID
	w.db.AdminQueryRow(t, "SELECT run_id FROM pc.transactions WHERE id = $1", []any{s.hidden[0]}, &hiddenRun)
	if p, err := e.ListTransactions(team, page.Request{Size: 1}, txapp.Filter{Run: &hiddenRun}); err != nil || len(p.Items) != 0 || p.Next != "" {
		t.Fatalf("another team's run: %d items, next %q, %v", len(p.Items), p.Next, err)
	}
	other := w.reader(tdomain.RoleAuditor, tdomain.Scope{Type: tdomain.ScopeTeam, ID: s.otherTeam})
	if got := pages(t, 2, list(other), id); !sameSet(got, s.hidden) {
		t.Fatalf("the other team's viewer paged %v, want %v", got, s.hidden)
	}
	org := w.reader(tdomain.RoleAuditor, tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()})
	if got := pages(t, 3, list(org), id); !sameSet(got, append(slices.Clone(s.visible), s.hidden...)) {
		t.Fatalf("the org's auditor paged %d transactions, want %d", len(got), len(s.visible)+len(s.hidden))
	}
	nowhere := w.reader(tdomain.RoleAuditor, tdomain.Scope{Type: tdomain.ScopeTeam, ID: ids.NewV7()})
	if p, err := e.ListTransactions(nowhere, page.Request{Size: 2}, txapp.Filter{}); err != nil || len(p.Items) != 0 || p.Next != "" {
		t.Fatalf("a viewer of no team's agents: %d items, next %q, %v", len(p.Items), p.Next, err)
	}
}

// TestT042_AScopedViewersReconciliationPagesAreFullAndHideOtherTeams: the
// same for reconciliations (G0 M10 D60, T-042, T-037).
func TestT042_AScopedViewersReconciliationPagesAreFullAndHideOtherTeams(t *testing.T) {
	s := newScopedExplorer(t, 6)
	w := s.w
	e := &txapp.Explorer{Pool: w.pool}
	list := func(who context.Context) func(page.Request) ([]txapp.Reconciliation, string, error) {
		return func(pr page.Request) ([]txapp.Reconciliation, string, error) {
			p, err := e.ListReconciliations(who, pr, txapp.ReconciliationFilter{})
			return p.Items, p.Next, err
		}
	}
	id := func(x txapp.Reconciliation) ids.UUID { return x.ID }

	team := w.reader(tdomain.RoleReconciler, tdomain.Scope{Type: tdomain.ScopeTeam, ID: w.teamOfAgent()})
	for _, size := range []int{1, 2} {
		if got := pages(t, size, list(team), id); !sameSet(got, s.visibleReconcile) {
			t.Fatalf("size %d: the team's reconciler paged %v, want %v", size, got, s.visibleReconcile)
		}
	}
	other := w.reader(tdomain.RoleReconciler, tdomain.Scope{Type: tdomain.ScopeTeam, ID: s.otherTeam})
	if got := pages(t, 2, list(other), id); !sameSet(got, s.hiddenReconcile) {
		t.Fatalf("the other team's reconciler paged %v, want %v", got, s.hiddenReconcile)
	}
	// A filter by another team's transaction finds nothing.
	if p, err := e.ListReconciliations(team, page.Request{Size: 2}, txapp.ReconciliationFilter{Transaction: &s.hidden[0]}); err != nil ||
		len(p.Items) != 0 || p.Next != "" {
		t.Fatalf("another team's reconciliation by its transaction: %+v %q %v", p.Items, p.Next, err)
	}
	org := w.reader(tdomain.RoleAuditor, tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()})
	if got := pages(t, 4, list(org), id); len(got) != len(s.visibleReconcile)+len(s.hiddenReconcile) {
		t.Fatalf("the org's auditor paged %d reconciliations", len(got))
	}
}
