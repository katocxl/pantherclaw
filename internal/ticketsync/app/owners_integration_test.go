// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tsapp "github.com/katocxl/pantherclaw/internal/ticketsync/app"
	"github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// requests is a change ceremony that opens every request.
type requests struct{ opened int }

func (r *requests) Open(context.Context, db.TenantTx, protect.Request) (ids.UUID, error) {
	r.opened++
	return ids.NewV7(), nil
}
func (r *requests) Void(context.Context, db.TenantTx, ids.UUID, string) error { return nil }
func (r *requests) Pending(context.Context, db.TenantTx, ids.UUID) (bool, error) {
	return true, nil
}

func (f *fixture) owner(field domain.Field) domain.Owner {
	f.t.Helper()
	own, err := f.svc.FieldOwners(f.as())
	if err != nil {
		f.t.Fatal(err)
	}
	return own[field]
}

// TestHR527_FieldOwnersNeverGiveAwayContainment: containment and
// restoration are refused for the ticket system; giving state to it is a
// protected change while COVERAGE_EXCLUSION is on, and taking a field back
// applies at once (D264). Even a ticket-owned state moves nothing.
//
// Covers: F545
func TestHR527_FieldOwnersNeverGiveAwayContainment(t *testing.T) {
	f := newFixture(t)
	for _, field := range []domain.Field{domain.FieldContainment, domain.FieldRestoration} {
		if err := f.svc.SetFieldOwner(f.as(), field, domain.OwnerTicket); !errors.Is(err, tsapp.ErrLockedField) {
			t.Errorf("%s given to the ticket: %v", field, err)
		}
	}
	reqs := &requests{}
	f.svc.RegisterProtected(&protect.Gate{Requests: reqs})
	f.exec(`INSERT INTO pc.protected_change_settings (org_id, category, mode, updated_by) VALUES ($1, 'COVERAGE_EXCLUSION', 'DISTINCT_PUBLISHER', $2)`,
		f.org, f.alice)
	if err := f.svc.SetFieldOwner(f.as(), domain.FieldState, domain.OwnerTicket); !errors.Is(err, protect.ErrPending) {
		t.Fatalf("giving state away was not held: %v", err)
	}
	if f.owner(domain.FieldState) != domain.OwnerPantherClaw || reqs.opened != 1 {
		t.Fatalf("a held change applied: %s, %d requests", f.owner(domain.FieldState), reqs.opened)
	}
	// Taking a field back applies directly, the category notwithstanding.
	if err := f.svc.SetFieldOwner(f.as(), domain.FieldLabels, domain.OwnerPantherClaw); err != nil || f.owner(domain.FieldLabels) != domain.OwnerPantherClaw {
		t.Fatalf("taking labels back: %v", err)
	}
	if n := f.count("SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.ticket.field_owner_changed'", f.org); n != 1 {
		t.Fatalf("%d owner changes audited", n)
	}

	// With the category off, state goes to the ticket system; a Jira Done
	// is mirrored as a note and the containment stays.
	f.exec("UPDATE pc.protected_change_settings SET mode = 'OFF' WHERE org_id = $1", f.org)
	if err := f.svc.SetFieldOwner(f.as(), domain.FieldState, domain.OwnerTicket); err != nil {
		t.Fatal(err)
	}
	kase, control := f.containedCase()
	epoch := f.epoch()
	if out, err := f.deliver("d-1", statusEvent(1793361600000, "Done", "done"), f.secret); err != nil || out != tsapp.OutcomeApplied {
		t.Fatalf("Done on a ticket-owned state: %q %v", out, err)
	}
	if n := f.count("SELECT count(*) FROM pc.containment_controls WHERE org_id = $1 AND id = $2 AND lifted_at IS NULL", f.org, control); n != 1 || f.epoch() != epoch {
		t.Fatal("a ticket-owned state lifted containment")
	}
	if n := f.count("SELECT count(*) FROM pc.cases WHERE org_id = $1 AND id = $2 AND state = 'OPEN'", f.org, kase); n != 1 {
		t.Fatal("a ticket-owned state moved the case")
	}
	if n := f.count("SELECT count(*) FROM pc.case_entries WHERE org_id = $1 AND case_id = $2 AND kind = 'NOTE' AND text LIKE '%never restores%'", f.org, kase); n != 1 {
		t.Fatalf("the Done was not mirrored: %d", n)
	}
}
