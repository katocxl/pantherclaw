// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package investigations_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/investigations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// as is a person holding role at the fixture's org.
func (f *fixture) as(role td.RoleName) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.alice},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
	}, Credential: tenancy.CredBrowserSession})
}

// decided records a decision of run on conn through the fixture's gateway
// at, with a receipt claiming snapshot (nil: no claim).
func (f *fixture) decided(t *testing.T, run, conn ids.UUID, op string, at time.Time, snapshot *ids.UUID) ids.UUID {
	t.Helper()
	id, entry := ids.NewV7(), ids.NewV7()
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id,
		connection_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', $7, $8, $9)`,
		f.org, id, run, ids.NewV7(), make([]byte, 32), op, f.gw.String(), conn, at)
	f.exec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
		VALUES ($1, $2, 'decision.test', 'test', 'test', '\x7b7d')`, f.org, entry)
	f.exec(t, `INSERT INTO pc.decision_receipts (org_id, transaction_id, evaluation, receipt_jws, ledger_entry_id, coverage_snapshot_id, created_at)
		VALUES ($1, $2, 1, 'x.y.z', $3, $4, $5)`, f.org, id, entry, snapshot, at)
	return id
}

// TestHR401_RunInspectionReadsEachSectionWithItsOwnPermission: a Developer
// (no approval.read, no automation.read) gets the timeline, budget,
// coverage and gaps, and lineage and approvals are left out whole and
// listed as omitted; an Auditor gets every section; a person without
// evidence.read does not find the run. The gaps carry the new kinds.
// Covers: F224, F065, F227, F229
func TestHR401_RunInspectionReadsEachSectionWithItsOwnPermission(t *testing.T) {
	f := newFixture(t)
	start := time.Now().Add(-20 * time.Hour).UTC().Truncate(time.Microsecond)
	// The run's gateway was created 40 hours ago and never renewed its
	// certificate: it was unseen for longer than its heartbeat window when
	// the run's first action reached it (TELEMETRY_GAP).
	f.gw = ids.NewV7()
	f.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by, created_at) VALUES ($1, $2, 'gw-silent', 'test', $3)",
		f.org, f.gw, start.Add(-40*time.Hour))
	run := ids.NewV7()
	f.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, task_ref,
		created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $5, 'launcher', 'untrusted label', $6::timestamptz, $6::timestamptz + interval '24 hours')`,
		f.org, run, f.agent, f.env, f.alice, start)
	// The run's own agent instance launched a child run.
	inst, child := ids.NewV7(), ids.NewV7()
	f.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, f.org, inst, f.agent, inst.String()[:36]+"0000000")
	f.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_instance_id, principal_user_id, principal_source,
		parent_run_id, depth, expires_at) VALUES ($1, $2, $3, $4, $5, $6, 'parent_run', $7, 1, now() + interval '1 hour')`,
		f.org, child, f.agent, f.env, inst, f.alice, run)

	// A PARTIAL snapshot of the public route.
	snap, entry := ids.NewV7(), ids.NewV7()
	f.exec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
		VALUES ($1, $2, 'coverage.test', 'test', 'test', '\x7b7d')`, f.org, entry)
	f.exec(t, `INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body, body_sha256,
		ledger_entry_id) VALUES ($1, $2, $3, $4, 'paste.create', 'PARTIAL', '{ROUTE_UNCLOSED}', '{}', $5, $6)`,
		f.org, snap, f.agent, f.public, make([]byte, 32), entry)
	unclaimed := f.decided(t, run, f.internal, "wiki.page.read", start.Add(time.Minute), nil)
	partial := f.decided(t, run, f.public, "paste.create", start.Add(2*time.Minute), &snap)

	// The unclaimed action committed 5 USD of a grant's budget account.
	budget, permit, account := ids.NewV7(), ids.NewV7(), ids.NewV7()
	f.exec(t, "INSERT INTO pc.budgets (org_id, id, name, currency, limit_amount) VALUES ($1, $2, 'dev', 'USD', 100)", f.org, budget)
	f.exec(t, `INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, budget_id, amount, expires_at)
		VALUES ($1, $2, $3, $4, 1, $5, 5, now() + interval '1 hour')`, f.org, permit, unclaimed, f.gw.String(), budget)
	f.exec(t, `INSERT INTO pc.budget_accounts (org_id, id, owner_kind, owner_id, rule, key_hash, period_start, rank, currency)
		VALUES ($1, $2, 'grant', $3, 'spend', $4, date_trunc('day', now()), 0, 'USD')`, f.org, account, ids.NewV7(), make([]byte, 32))
	f.exec(t, `INSERT INTO pc.reservations (org_id, id, transaction_id, permit_id, account_id, amount, state, settled_at)
		VALUES ($1, $2, $3, $4, $5, 5, 'COMMITTED', now())`, f.org, ids.NewV7(), unclaimed, permit, account)

	svc := &investigations.Service{Pool: f.p}

	dev, err := svc.InspectRun(f.as(td.RoleDeveloper), run, investigations.InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dev.Omitted, []investigations.Section{investigations.SectionLineage, investigations.SectionApprovals}) {
		t.Errorf("developer omitted = %v, want lineage and approvals", dev.Omitted)
	}
	if dev.Lineage != nil || dev.Approvals != nil {
		t.Errorf("developer got an omitted section: lineage %+v, approvals %+v", dev.Lineage, dev.Approvals)
	}
	if dev.Run.TaskRef != "untrusted label" || dev.Run.Launcher == nil || dev.Run.Launcher.ID != f.alice || dev.ScopeLimited {
		t.Errorf("summary = %+v", dev.Run)
	}
	if !dev.HasTimeline || len(dev.Events) < 2 {
		t.Errorf("timeline = %+v", dev.Events)
	}
	if len(dev.Budget) != 1 || dev.Budget[0].Account != account || dev.Budget[0].Committed != "5" || dev.Budget[0].Count != 1 ||
		dev.Budget[0].Currency != "USD" {
		t.Errorf("budget = %+v", dev.Budget)
	}
	if len(dev.Coverage) != 1 || dev.Coverage[0].Snapshot != snap || dev.Coverage[0].State != "PARTIAL" || dev.Coverage[0].StaleAtDecision {
		t.Errorf("coverage = %+v", dev.Coverage)
	}
	kinds := map[string]ids.UUID{}
	for _, g := range dev.Gaps {
		if g.Gateway != nil {
			kinds[g.Kind] = *g.Gateway
			continue
		}
		kinds[g.Kind] = g.Transaction
	}
	if kinds[investigations.GapNoCoverageClaim] != unclaimed || kinds[investigations.GapCoverageBelowEnforced] != partial ||
		kinds[investigations.GapTelemetry] != f.gw {
		t.Errorf("gaps = %+v", dev.Gaps)
	}

	aud, err := svc.InspectRun(f.as(td.RoleAuditor), run, investigations.InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(aud.Omitted) != 0 || aud.Lineage == nil || len(aud.Lineage.Children) != 1 || aud.Lineage.Children[0].Run != child ||
		aud.Lineage.Upstream != nil {
		t.Errorf("auditor = omitted %v, lineage %+v", aud.Omitted, aud.Lineage)
	}

	// Without coverage.read (an Auditor's key scoped to the rest), coverage
	// and gaps are left out whole (D21a).
	noCov := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.alice},
		Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
		Scopes:   []td.Permission{td.PermEvidenceRead, td.PermAutomationRead, td.PermBudgetRead, td.PermApprovalRead},
	}, Credential: tenancy.CredBrowserSession})
	nc, err := svc.InspectRun(noCov, run, investigations.InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nc.Omitted, []investigations.Section{investigations.SectionCoverage, investigations.SectionGaps}) ||
		nc.Gaps != nil || nc.Coverage != nil || nc.Lineage == nil || !nc.HasTimeline {
		t.Errorf("without coverage.read: omitted %v, gaps %+v, coverage %+v", nc.Omitted, nc.Gaps, nc.Coverage)
	}

	// Only what was asked for is read; nothing asked for is omitted.
	only, err := svc.InspectRun(f.as(td.RoleDeveloper), run, investigations.InspectOptions{Sections: []investigations.Section{investigations.SectionBudget}})
	if err != nil {
		t.Fatal(err)
	}
	if len(only.Omitted) != 0 || only.HasTimeline || only.Gaps != nil || len(only.Budget) != 1 {
		t.Errorf("budget only = %+v", only)
	}

	if _, err := svc.InspectRun(f.as(td.RoleApprover), run, investigations.InspectOptions{}); !errors.Is(err, investigations.ErrRunNotFound) {
		t.Errorf("approver (no evidence.read): %v, want not found", err)
	}
}

// sections is a scope that may read every section of what it sees.
type sections struct{ scope }

func (s sections) Readable(ctx context.Context, _ investigations.Section, agent ids.UUID) (bool, error) {
	return s.Visible(ctx, agent)
}

// children gives run n child runs of agent, launched by an instance of
// the fixture's agent, created at start plus one millisecond each.
func (f *fixture) children(t *testing.T, run, agent ids.UUID, n int, start time.Time) {
	t.Helper()
	inst := ids.NewV7()
	f.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, f.org, inst, f.agent, inst.String()[:36]+"0000000")
	f.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_instance_id, principal_user_id, principal_source,
		parent_run_id, depth, created_at, expires_at)
		SELECT $1, gen_random_uuid(), $2, $3, $4, $5, 'parent_run', $6, 1,
		       $7::timestamptz + i * interval '1 millisecond', $7::timestamptz + i * interval '1 millisecond' + interval '1 hour'
		FROM generate_series(1, $8::int) AS i`, f.org, agent, f.env, inst, f.alice, run, start, n)
}

// TestRunInspectionNeverCountsHiddenChildren: children the caller cannot
// see are neither listed nor counted toward children_truncated, and a
// visible child after more than a page of hidden ones is still found;
// more than 200 visible children are truncated (HR-401, rows26 D25).
// Covers: F224
func TestRunInspectionNeverCountsHiddenChildren(t *testing.T) {
	f := newFixture(t)
	s := sections{scope{f.agent: true}}
	lineage := investigations.InspectOptions{Sections: []investigations.Section{investigations.SectionLineage}}
	start := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)

	run := f.run(t, f.agent)
	f.children(t, run, f.other, investigations.MaxChildren+50, start)
	f.children(t, run, f.agent, 1, start.Add(time.Minute))
	many := f.run(t, f.agent)
	f.children(t, many, f.agent, investigations.MaxChildren+1, start)

	f.read(t, func(ctx context.Context, tx db.TenantTx) error {
		in, err := investigations.InspectRun(ctx, tx, s, run, lineage)
		if err != nil {
			return err
		}
		if in.Lineage == nil || len(in.Lineage.Children) != 1 || in.Lineage.ChildrenTruncated {
			t.Errorf("hidden children counted: %+v", in.Lineage)
		}
		in, err = investigations.InspectRun(ctx, tx, s, many, lineage)
		if err != nil {
			return err
		}
		if in.Lineage == nil || len(in.Lineage.Children) != investigations.MaxChildren || !in.Lineage.ChildrenTruncated {
			t.Errorf("%d visible children, truncated %v", len(in.Lineage.Children), in.Lineage.ChildrenTruncated)
		}
		return nil
	})
}

// TestRunTimelineLanesSkipHiddenChildren: a visible child after more than
// a page of children the caller cannot see still gets a lane and a lane
// event, and no hidden child does (HR-401).
// Covers: F065
func TestRunTimelineLanesSkipHiddenChildren(t *testing.T) {
	f := newFixture(t)
	s := scope{f.agent: true}
	start := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)

	run := f.run(t, f.agent)
	f.children(t, run, f.other, investigations.MaxChildren+50, start)
	f.children(t, run, f.agent, 1, start.Add(time.Minute))

	f.read(t, func(ctx context.Context, tx db.TenantTx) error {
		tl, err := investigations.RunTimeline(ctx, tx, s, run, false)
		if err != nil {
			return err
		}
		if len(tl.Lanes) != 1 || tl.Lanes[0].Agent != f.agent {
			t.Fatalf("lanes = %+v, want the one visible child", tl.Lanes)
		}
		lanes := 0
		for _, e := range tl.Events {
			if e.Kind == investigations.EventLane {
				lanes++
				if e.Run == nil || *e.Run != tl.Lanes[0].Run {
					t.Errorf("lane event for %v, want %v", e.Run, tl.Lanes[0].Run)
				}
			}
		}
		if lanes != 1 {
			t.Errorf("%d lane events, want 1", lanes)
		}
		return nil
	})
}

// TestF284_LanesCarryTheirEventsAndReadsTheirClass: a child's lane holds
// its own decisions, results and gaps, a hidden child stays out, and an
// event of a sensitive read names its class (D16, F285).
// Covers: F284, F285
func TestF284_LanesCarryTheirEventsAndReadsTheirClass(t *testing.T) {
	f := newFixture(t)
	s := scope{f.agent: true}
	start := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	run := f.run(t, f.agent)
	read := f.txn(t, run, f.internal, "wiki.page.read", "ALLOW")
	f.exec(t, "UPDATE pc.transactions SET read_class = 'secret' WHERE id = $1", read)
	f.children(t, run, f.other, 1, start)
	f.children(t, run, f.agent, 1, start.Add(time.Minute))

	var child, hidden ids.UUID
	f.read(t, func(ctx context.Context, tx db.TenantTx) error {
		if err := tx.QueryRow(ctx, "SELECT id FROM pc.runs WHERE parent_run_id = $1 AND agent_id = $2", run, f.other).Scan(&hidden); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT id FROM pc.runs WHERE parent_run_id = $1 AND agent_id = $2", run, f.agent).Scan(&child)
	})
	inner := f.txn(t, child, f.internal, "wiki.page.read", "ALLOW")
	f.exec(t, "UPDATE pc.transactions SET read_class = 'pii' WHERE id = $1", inner)
	f.txn(t, hidden, f.internal, "secret.thing.read", "ALLOW")

	f.read(t, func(ctx context.Context, tx db.TenantTx) error {
		tl, err := investigations.RunTimeline(ctx, tx, s, run, false)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(tl.Events, func(e investigations.Event) bool {
			return e.Kind == investigations.EventDecision && e.ReadClass == "secret"
		}) {
			t.Errorf("no read class on the run's read: %+v", tl.Events)
		}
		if len(tl.Lanes) != 1 || tl.Lanes[0].Run != child {
			t.Fatalf("lanes = %+v", tl.Lanes)
		}
		l := tl.Lanes[0]
		if len(l.Events) == 0 || l.EventsTruncated {
			t.Fatalf("lane: %+v", l)
		}
		for _, e := range l.Events {
			if e.Operation == "secret.thing.read" {
				t.Errorf("a hidden child's action in a lane: %+v", e)
			}
		}
		if !slices.ContainsFunc(l.Events, func(e investigations.Event) bool {
			return e.Kind == investigations.EventDecision && e.ReadClass == "pii"
		}) {
			t.Errorf("lane events: %+v", l.Events)
		}
		if !slices.ContainsFunc(l.Gaps, func(g investigations.Gap) bool { return g.Kind == investigations.GapNoDecisionReceipt }) {
			t.Errorf("lane gaps: %+v", l.Gaps)
		}
		return nil
	})
}

// TestF284_LanesReadTogetherAndSayWhenCutOrNotLoaded: lanes hold their own
// actions up to their bound and flag a cut, one lane's length costs another
// nothing, and a lineage section says its lanes' events were not read (D35).
// Covers: F284
func TestF284_LanesReadTogetherAndSayWhenCutOrNotLoaded(t *testing.T) {
	f := newFixture(t)
	s := scope{f.agent: true}
	start := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	run := f.run(t, f.agent)
	f.children(t, run, f.agent, 2, start)
	var kids []ids.UUID
	f.read(t, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT id FROM pc.runs WHERE parent_run_id = $1 ORDER BY created_at, id", run)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id ids.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			kids = append(kids, id)
		}
		return rows.Err()
	})
	if len(kids) != 2 {
		t.Fatalf("children: %v", kids)
	}
	for range investigations.MaxLaneActions + 1 {
		f.txn(t, kids[0], f.internal, "wiki.page.read", "ALLOW")
	}
	f.txn(t, kids[1], f.internal, "wiki.page.read", "ALLOW")
	decisions := func(l investigations.Lane) int {
		n := 0
		for _, e := range l.Events {
			if e.Kind == investigations.EventDecision {
				n++
			}
		}
		return n
	}
	f.read(t, func(ctx context.Context, tx db.TenantTx) error {
		tl, err := investigations.RunTimeline(ctx, tx, s, run, false)
		if err != nil {
			return err
		}
		if len(tl.Lanes) != 2 {
			t.Fatalf("lanes = %+v", tl.Lanes)
		}
		long, short := tl.Lanes[0], tl.Lanes[1]
		if long.Run != kids[0] || decisions(long) != investigations.MaxLaneActions || !long.EventsTruncated || long.EventsNotLoaded {
			t.Errorf("the long lane: %d decisions, truncated %v, not loaded %v", decisions(long), long.EventsTruncated, long.EventsNotLoaded)
		}
		if decisions(short) != 1 || short.EventsTruncated || short.EventsNotLoaded {
			t.Errorf("the short lane: %d decisions, truncated %v, not loaded %v", decisions(short), short.EventsTruncated, short.EventsNotLoaded)
		}
		return nil
	})
	svc := &investigations.Service{Pool: f.p}
	in, err := svc.InspectRun(f.as(td.RoleAuditor), run, investigations.InspectOptions{Sections: []investigations.Section{investigations.SectionLineage}})
	if err != nil {
		t.Fatal(err)
	}
	if in.Lineage == nil || len(in.Lineage.Children) != 2 || !in.Lineage.Children[0].EventsNotLoaded {
		t.Errorf("lineage: %+v", in.Lineage)
	}
}
