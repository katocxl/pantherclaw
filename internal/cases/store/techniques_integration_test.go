// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package store_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func (f *fixture) alert(t *testing.T, atlas, attack []string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	f.exec(t, `INSERT INTO pc.alerts (org_id, id, source, title, severity, attention, basis, dedupe_key, first_seen, last_seen, atlas, attack)
		VALUES ($1, $2, 'detection', 'a', 'HIGH', 'ALERT', 'RULE_MATCH', $3, now(), now(),
			coalesce($4::text[], '{}'), coalesce($5::text[], '{}'))`,
		f.org, id, "d:"+id.String(), atlas, attack)
	return id
}

func (f *fixture) incident(t *testing.T, atlas, attack []string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	f.exec(t, `INSERT INTO pc.incidents (org_id, id, title, severity, opened_by, atlas, attack)
		VALUES ($1, $2, 'i', 'HIGH', 'user:x', coalesce($3::text[], '{}'), coalesce($4::text[], '{}'))`, f.org, id, atlas, attack)
	return id
}

func (f *fixture) openFrom(t *testing.T, alert, incident *ids.UUID) domain.Case {
	t.Helper()
	var c domain.Case
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		c, err = store.Open(ctx, tx, domain.NewCase{
			Title: "From a signal", Source: "detection", OpenedBy: f.author,
			Alert: alert, Incident: incident,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestHR684_CaseListsTheUnionOfItsSignalsTechniques: a case opened from an
// alert starts with its techniques; each LINK to an alert or an incident
// widens the union, sorted and distinct; other links and ids that name no
// row of the org add nothing (G0 M28 D718). Covers: F964, HR-684
func TestHR684_CaseListsTheUnionOfItsSignalsTechniques(t *testing.T) {
	f := newFixture(t)
	a := f.alert(t, []string{"AML.T0051", "AML.T0024"}, []string{"T1552"})
	c := f.openFrom(t, &a, nil)
	if !slices.Equal(c.ATLAS, []string{"AML.T0024", "AML.T0051"}) || !slices.Equal(c.ATTACK, []string{"T1552"}) {
		t.Fatalf("opened case: atlas %v attack %v", c.ATLAS, c.ATTACK)
	}
	inc := f.incident(t, []string{"AML.T0051", "AML.T0010"}, []string{"T1078"})
	f.must(t, c.ID, domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: "incident", ID: inc.String()}})
	f.must(t, c.ID, domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: "run", ID: f.run.String()}})
	f.must(t, c.ID, domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: "alert", ID: ids.NewV7().String()}})
	f.must(t, c.ID, domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: "alert", ID: "not-a-uuid"}})
	k := f.get(t, c.ID)
	if !slices.Equal(k.ATLAS, []string{"AML.T0010", "AML.T0024", "AML.T0051"}) || !slices.Equal(k.ATTACK, []string{"T1078", "T1552"}) {
		t.Fatalf("after links: atlas %v attack %v", k.ATLAS, k.ATTACK)
	}
	if k.HeadSeq != 4 {
		t.Errorf("head %d, want 4", k.HeadSeq)
	}

	// A case opened by hand, then linked to the alert, gets the same.
	m := f.open(t)
	if len(m.ATLAS) != 0 || len(m.ATTACK) != 0 {
		t.Fatalf("manual case: %v %v", m.ATLAS, m.ATTACK)
	}
	f.must(t, m.ID, domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: "alert", ID: a.String()}})
	if k := f.get(t, m.ID); !slices.Equal(k.ATLAS, []string{"AML.T0024", "AML.T0051"}) {
		t.Errorf("linked manual case: %v", k.ATLAS)
	}

	// The case still changes only by an entry (HR-245): its techniques too.
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.cases SET atlas = '{AML.T0099}' WHERE id = $1", c.ID)
		return err
	}); err == nil {
		t.Error("a case's techniques changed without an entry")
	}
}

// TestHR684_TechniqueUnionIsCappedAtTheSmallest64: an incident or a case
// keeps at most 64 ids of each framework, the 64 smallest, and attaching
// past the cap never fails (G0 M28 D718). Covers: HR-684
func TestHR684_TechniqueUnionIsCappedAtTheSmallest64(t *testing.T) {
	f := newFixture(t)
	big := make([]string, 0, 64)
	for i := range 64 {
		big = append(big, fmt.Sprintf("T%04d", 9000+i))
	}
	inc := f.incident(t, nil, big)
	a := f.alert(t, nil, []string{"T1001", "T9999"})
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.AttachAlert(ctx, &inc, f.org, a); err != nil {
			return err
		}
		_, err := q.UnionIncidentTechniques(ctx, f.org, inc, a)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		i, err := dbq.New(tx).GetIncident(ctx, f.org, inc)
		got = i.Attack
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := append([]string{"T1001"}, big[:63]...)
	if !slices.Equal(got, want) {
		t.Fatalf("incident attack %v", got)
	}

	c := f.openFrom(t, &a, &inc)
	if !slices.Equal(c.ATTACK, want) {
		t.Fatalf("case attack %v", c.ATTACK)
	}
	f.must(t, c.ID, domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: "alert", ID: f.alert(t, nil, []string{"T0001"}).String()}})
	if k := f.get(t, c.ID); len(k.ATTACK) != 64 || k.ATTACK[0] != "T0001" || slices.Contains(k.ATTACK, big[62]) {
		t.Fatalf("case attack after link %v", k.ATTACK)
	}
}
