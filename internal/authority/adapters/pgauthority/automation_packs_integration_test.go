// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// automation adds an automation with its execution identity (they name
// each other; the deferred keys hold at commit) and returns both ids.
func (p *packWorld) automation(name string, owner ids.UUID) (automation, account ids.UUID) {
	p.t.Helper()
	automation, account = ids.NewV7(), ids.NewV7()
	exec(p.t, p.pool, p.org, `WITH sa AS (
			INSERT INTO pc.service_accounts (org_id, id, name, created_by, automation_id)
			VALUES ($1, $2, 'automation-' || $4, 'test', $3) RETURNING id)
		INSERT INTO pc.automations (org_id, id, name, purpose, kind, owner_user_id, service_account_id, created_by)
		SELECT $1, $3, $4, 'digest', 'SECURITY_WORK', $5, sa.id, $5 FROM sa`, p.org, account, automation, name, owner)
	return automation, account
}

// automationPack creates an automation's pack in its own transaction and
// builds it.
func (p *packWorld) automationPack(in evapp.AutomationPack) (ids.UUID, error) {
	p.t.Helper()
	in.Org = p.org
	var id ids.UUID
	err := p.pool.InTenantTx(context.Background(), p.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = p.svc.CreateForAutomationTx(ctx, tx.Pgx(), in)
		return err
	})
	if err != nil {
		return id, err
	}
	return id, p.builder.Build(context.Background(), p.org, id)
}

// TestHR286_AnAutomationsPackIsItsOwnWithinItsDeclaredAgents (G0 M11 part 2
// D85): a digest step's evidence pack is created by the automation's own
// execution identity, never a person's borrowed permissions; it holds only
// the evidence of the agents its version declared, built with evidence.read
// alone; the database refuses an automation pack created by any other
// identity; and the person-created path is unchanged.
func TestHR286_AnAutomationsPackIsItsOwnWithinItsDeclaredAgents(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	run := w.run(w.grant("500").ID, ids.UUID{})
	for _, amount := range []string{"10.00", "11.00"} {
		w.authorize(w.request(run, ids.NewV7(), "ch_1", amount))
	}
	p := w.packs(billing.Team)
	auditor := p.person("auditor", td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: p.org.UUID()})
	owner := mustCaller(t, auditor).Principal.ID
	auto, account := p.automation("weekly-digest", owner)
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	req := evapp.PackRequest{Kind: pack.ScopeTimeRange, From: &from, To: &to, Include: pack.Include{Receipts: true}}
	base := evapp.AutomationPack{Automation: auto, Execution: ids.NewV7(), ServiceAccount: account, Request: req}

	for name, tc := range map[string]struct {
		agents []ids.UUID
		want   int
	}{"its agent": {[]ids.UUID{w.agent}, 2}, "all agents": {nil, 2}, "another agent": {[]ids.UUID{ids.NewV7()}, 0}} {
		t.Run(name, func(t *testing.T) {
			in := base
			in.Agents = tc.agents
			id, err := p.automationPack(in)
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.svc.GetEvidencePack(auditor, id)
			if err != nil || got.State != "READY" || got.CreatedBy != account {
				t.Fatalf("pack = %+v, %v", got, err)
			}
			m := manifestOf(t, p.download(auditor, id))
			if len(m.Transactions) != tc.want || (tc.want == 0) != hasGap(m, pack.GapOutsidePermission) {
				t.Fatalf("%d transactions, gaps %+v", len(m.Transactions), m.Gaps)
			}
			var row dbq.EvidencePackAutomationRow
			if err := p.pool.InTenantTx(context.Background(), p.org, func(ctx context.Context, tx db.TenantTx) error {
				row, err = dbq.New(tx).EvidencePackAutomation(ctx, p.org, id)
				return err
			}); err != nil || row.AutomationID == nil || *row.AutomationID != auto || !slices.Equal(row.AutomationAgents, tc.agents) {
				t.Fatalf("stored automation %+v, %v", row, err)
			}
		})
	}

	// Another service account, or a person, cannot create an automation's
	// pack: the database refuses it.
	other := ids.NewV7()
	exec(t, p.pool, p.org, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'ci', 'test')", p.org, other)
	for _, creator := range []ids.UUID{other, owner} {
		in := base
		in.ServiceAccount = creator
		if _, err := p.automationPack(in); err == nil {
			t.Fatalf("an automation pack created by %s", creator)
		}
	}
	// Only time ranges and transactions; Community gets none.
	in := base
	in.Request = evapp.PackRequest{Kind: pack.ScopeRun, Run: run, Include: req.Include}
	if _, err := p.automationPack(in); !errors.Is(err, evapp.ErrBadPackScope) {
		t.Fatalf("a run-scoped automation pack: %v", err)
	}
	p.edition.ed = billing.Community
	if _, err := p.automationPack(base); !errors.Is(err, evapp.ErrPacksEdition) {
		t.Fatalf("on Community: %v", err)
	}
	p.edition.ed = billing.Team

	// A person's pack is unchanged: theirs, built with their permissions.
	if pk := p.create(auditor, req); pk.CreatedBy != owner || len(manifestOf(t, p.download(auditor, pk.ID)).Transactions) != 2 {
		t.Fatalf("a person's pack: %+v", pk)
	}
}

func mustCaller(t *testing.T, ctx context.Context) tapp.Caller {
	t.Helper()
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
