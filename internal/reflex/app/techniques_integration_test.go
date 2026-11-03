// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"slices"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// techniques reads an incident's stored ATLAS and ATT&CK techniques.
func (f *fixture) techniques(t *testing.T, incident ids.UUID) (atlas, attack []string) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT atlas, attack FROM pc.incidents WHERE org_id = $1 AND id = $2", f.org, incident).
			Scan(&atlas, &attack)
	}); err != nil {
		t.Fatal(err)
	}
	return atlas, attack
}

func (f *fixture) incidentOf(t *testing.T, alert ids.UUID) ids.UUID {
	t.Helper()
	var id ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT incident_id FROM pc.alerts WHERE org_id = $1 AND id = $2", f.org, alert).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func mapped(s reflexdomain.Signal, atlas, attack []string) reflexdomain.Signal {
	s.ATLAS, s.ATTACK = atlas, attack
	return s
}

// TestHR684_GroupedIncidentListsTheUnionOfItsAlerts: an incident opened by
// grouping starts with its first alert's techniques and widens by each
// alert grouped into it (G0 M28 D718, D718b L4). Covers: F964, HR-684
func TestHR684_GroupedIncidentListsTheUnionOfItsAlerts(t *testing.T) {
	f := newFixture(t, billing.Team)
	page := f.raise(t, mapped(f.signal("pc.integrity.action_tampered", reflexdomain.SeverityCritical, reflexdomain.AttentionPage, f.agentA),
		[]string{"AML.T0051"}, nil))
	inc := f.incidentOf(t, page.Alert)
	if atlas, attack := f.techniques(t, inc); !slices.Equal(atlas, []string{"AML.T0051"}) || len(attack) != 0 {
		t.Fatalf("opened with atlas %v attack %v", atlas, attack)
	}
	later := f.raise(t, mapped(f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentA),
		[]string{"AML.T0024", "AML.T0051"}, []string{"T1078"}))
	if got := f.incidentOf(t, later.Alert); got != inc {
		t.Fatalf("grouped into %v, want %v", got, inc)
	}
	if atlas, attack := f.techniques(t, inc); !slices.Equal(atlas, []string{"AML.T0024", "AML.T0051"}) ||
		!slices.Equal(attack, []string{"T1078"}) {
		t.Errorf("union atlas %v attack %v", atlas, attack)
	}
}

// TestHR684_FirstRaiseWinsTheTechniques: a repeat of an open alert keeps
// the stored alert's techniques, and the incident the repeat escalates to
// opens with those, in its row and in its ledger entry (G0 M28 D718b L2).
// Covers: F964, HR-684
func TestHR684_FirstRaiseWinsTheTechniques(t *testing.T) {
	f := newFixture(t, billing.Community)
	first := f.raise(t, mapped(f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentA),
		[]string{"AML.T0024"}, nil))
	if !first.New || !slices.Equal(first.ATLAS, []string{"AML.T0024"}) {
		t.Fatalf("first raise %+v", first)
	}
	repeat := f.raise(t, mapped(f.signal(rule, reflexdomain.SeverityCritical, reflexdomain.AttentionPage, f.agentA),
		[]string{"AML.T0051"}, []string{"T1078"}))
	if repeat.New || repeat.Alert != first.Alert || !slices.Equal(repeat.ATLAS, []string{"AML.T0024"}) || len(repeat.ATTACK) != 0 {
		t.Fatalf("repeat %+v", repeat)
	}
	inc := f.incidentOf(t, first.Alert)
	if atlas, attack := f.techniques(t, inc); !slices.Equal(atlas, []string{"AML.T0024"}) || len(attack) != 0 {
		t.Errorf("incident atlas %v attack %v", atlas, attack)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE 'reflex.%' "+
		"AND (position('AML.T0051' IN convert_from(body, 'UTF8')) > 0 OR position('T1078' IN convert_from(body, 'UTF8')) > 0)", f.org); n != 0 {
		t.Errorf("%d ledger entries carry the repeat's techniques", n)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2 "+
		"AND position('AML.T0024' IN convert_from(body, 'UTF8')) > 0", f.org, reflexdomain.KindIncident); n == 0 {
		t.Errorf("the incident's ledger entry lacks the stored techniques")
	}
}

// TestHR684_PromotedAndLinkedAlertsWidenTheIncident: a promoted alert opens
// its incident with its techniques; a linked alert widens them (G0 M28
// D718, D718b L4). Covers: F964, HR-684
func TestHR684_PromotedAndLinkedAlertsWidenTheIncident(t *testing.T) {
	f := newFixture(t, billing.Team)
	a := f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentA)
	a.GroupKey = "run:promote"
	ra := f.raise(t, mapped(a, []string{"AML.T0051.000"}, []string{"T1552.001"}))
	b := f.signal(rule, reflexdomain.SeverityLow, reflexdomain.AttentionAlert, f.agentB)
	b.GroupKey = "run:link"
	b.Subjects = []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: f.agentB.String()}}
	rb := f.raise(t, mapped(b, []string{"AML.T0024"}, []string{"T1078", "T1552.001"}))

	ctx := f.as(td.RoleSecurityAdmin)
	inc, err := f.svc.PromoteAlert(ctx, ra.Alert, "looks real")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inc.Atlas, []string{"AML.T0051.000"}) || !slices.Equal(inc.Attack, []string{"T1552.001"}) {
		t.Errorf("promoted atlas %v attack %v", inc.Atlas, inc.Attack)
	}
	if _, err := f.svc.LinkAlert(ctx, rb.Alert, inc.ID); err != nil {
		t.Fatal(err)
	}
	if atlas, attack := f.techniques(t, inc.ID); !slices.Equal(atlas, []string{"AML.T0024", "AML.T0051.000"}) ||
		!slices.Equal(attack, []string{"T1078", "T1552.001"}) {
		t.Errorf("linked atlas %v attack %v", atlas, attack)
	}
}
