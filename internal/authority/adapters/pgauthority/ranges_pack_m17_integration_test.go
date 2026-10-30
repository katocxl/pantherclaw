// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	rangeapp "github.com/katocxl/pantherclaw/internal/ranges/app"
	rdomain "github.com/katocxl/pantherclaw/internal/ranges/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR466_NoPackOfACustomerRange (integration): a finished range of
// customer-authored scenarios gets no assurance pack on any path:
// ExportAssuranceReport and CreateEvidencePack refuse it at once
// (RANGE_CUSTOMER_NOT_ATTESTED), and a pack row queued around the service
// fails in the build with the same code (G0 M17 D126).
// Covers: PN-009.6
func TestHR466_NoPackOfACustomerRange(t *testing.T) {
	w := newWorld(t)
	admin := w.db.Pool(t, w.db.Migrator)
	exec(t, admin, w.org, "UPDATE pc.agents SET range_agent = true WHERE org_id = $1 AND id = $2", w.org, w.agent)

	p := w.packs(billing.Business)
	org := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	owner, auditor := p.person("owner", td.RoleAgentOwner, org), p.person("auditor", td.RoleAuditor, org)
	svc := &rangeapp.Service{Store: pgranges.Store{Pool: w.pool}, Editions: licence{billing.Business}, Exporter: rangePacks{p}}
	cx := rdomain.Scenario{
		ID: "CX-001", Digest: "c0ffee" + "0000000000000000000000000000000000000000000000000000000000", Tier: rdomain.TierBusiness,
		Category: "boundary", Suite: "coding-agent", Title: "close a ticket", StepCount: 1,
	}
	rng, err := svc.StartRange(owner, rangeapp.StartInput{Agent: w.agent, Scenarios: []rdomain.Scenario{cx}, RunnerVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.FinishRange(owner, rng.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExportAssuranceReport(auditor, rng.ID); !errors.Is(err, rangeapp.ErrNotAttested) {
		t.Fatalf("ExportAssuranceReport: %v, want RANGE_CUSTOMER_NOT_ATTESTED", err)
	}
	if _, err := p.svc.CreateEvidencePack(auditor, evapp.PackRequest{
		Kind: pack.ScopeRange, Range: rng.ID, Include: pack.Include{Receipts: true, Versions: true},
	}); !errors.Is(err, evapp.ErrRangeCustomer) {
		t.Fatalf("CreateEvidencePack: %v, want RANGE_CUSTOMER_NOT_ATTESTED", err)
	}
	if len(p.queued) != 0 {
		t.Fatalf("%d packs queued", len(p.queued))
	}

	// A pack row written around the service: the build refuses it too.
	c, err := tenancy.CallerFrom(auditor)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := pack.Canonical(pack.Scope{Kind: pack.ScopeRange, Range: rng.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	include, err := pack.Canonical(pack.Include{Receipts: true, Versions: true})
	if err != nil {
		t.Fatal(err)
	}
	id := ids.NewV7()
	exec(t, admin, w.org, `INSERT INTO pc.evidence_packs (org_id, id, created_by, scope_kind, scope, include)
		VALUES ($1, $2, $3, 'range', $4, $5)`, w.org, id, c.Principal.ID, scope, include)
	if err := p.builder.Build(context.Background(), w.org, id); err != nil {
		t.Fatal(err)
	}
	got, err := p.svc.GetEvidencePack(auditor, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ErrorCode != packbuild.CodeRangeCustomer || got.Manifest != "" {
		t.Fatalf("the build of a customer range pack: state %s, code %q", got.State, got.ErrorCode)
	}
}
