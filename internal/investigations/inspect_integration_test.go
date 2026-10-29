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
