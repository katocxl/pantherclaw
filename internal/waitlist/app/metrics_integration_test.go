// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/waitlistrpc"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// edition is a fixed edition.
type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Edition(e)
	return x, nil
}

// toolReview opens a tool review for a new package version.
func (f *rfx) toolReview() ids.UUID {
	f.t.Helper()
	var id ids.UUID
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = pgwaitlist.OpenToolReview(ctx, tx, f.org, ids.NewV7(), "pc.mock-payments", "1.0.0", pgwaitlist.System)
		return err
	})
	return id
}

// TestT042_MetricsAggregateOnlyTheEntriesTheCallerMayRead: the metrics
// count each kind's entries in the window, their response and decision
// times, expiries, escalations and routing failures, and each decider's
// share; a team reader's metrics leave out what they may not read; without
// the Team edition there are none.
func TestT042_MetricsAggregateOnlyTheEntriesTheCallerMayRead(t *testing.T) {
	f := newRFx(t)
	recon, review, old := f.reconciliation(), f.toolReview(), f.toolReview()
	f.d.AdminExec(t, `UPDATE pc.waitlist_entries SET created_at = now() - interval '1 hour', first_response_at = now() - interval '59 minutes',
		state = 'APPROVED', decided_by = $2, decided_at = now() - interval '55 minutes' WHERE id = $1`, recon, "user:"+f.ben.String())
	f.d.AdminExec(t, `UPDATE pc.waitlist_entries SET created_at = now() - interval '2 hours', state = 'EXPIRED', decided_by = 'system',
		decided_at = now() - interval '1 hour', escalation_step = 2, routing_health = 'NO_ELIGIBLE_DECIDER' WHERE id = $1`, review)
	f.d.AdminExec(t, `UPDATE pc.waitlist_entries SET created_at = now() - interval '40 days', deadline_at = now() WHERE id = $1`, old)

	r := waitlist.NewReader(f.p)
	h := waitlistrpc.NewWaitlist(r)
	admin := f.as(f.ben, td.RoleSecurityAdmin)
	if _, err := h.GetWaitlistMetrics(admin, &pantherclawv1.GetWaitlistMetricsRequest{}); !errors.Is(err, waitlist.ErrEditionRequired) {
		t.Fatalf("without an edition: %v", err)
	}
	r.WithEntitlements(edition(billing.Community))
	if _, err := h.GetWaitlistMetrics(admin, &pantherclawv1.GetWaitlistMetricsRequest{}); !errors.Is(err, waitlist.ErrEditionRequired) {
		t.Fatalf("Community: %v", err)
	}
	r.WithEntitlements(edition(billing.Team))
	m, err := h.GetWaitlistMetrics(admin, &pantherclawv1.GetWaitlistMetricsRequest{})
	if err != nil || len(m.GetByKind()) != 2 || m.GetEndTime().AsTime().Sub(m.GetStartTime().AsTime()).Hours() != 30*24 {
		t.Fatalf("metrics: %v, %v", m, err)
	}
	rc, tr := m.GetByKind()[0], m.GetByKind()[1]
	if rc.GetKind() != pantherclawv1.WaitlistKind_WAITLIST_KIND_RECONCILIATION || rc.GetCount() != 1 || rc.GetDecided() != 1 ||
		rc.GetFirstResponseP50Seconds() != 60 || rc.GetDecisionP90Seconds() != 300 || rc.GetExpiryRate() != 0 {
		t.Fatalf("reconciliation: %v", rc)
	}
	if tr.GetKind() != pantherclawv1.WaitlistKind_WAITLIST_KIND_TOOL_REVIEW || tr.GetCount() != 1 || tr.GetDecided() != 0 ||
		tr.GetFirstResponseP50Seconds() != 0 || tr.GetExpiryRate() != 1 || tr.GetEscalationRate() != 1 || tr.GetRoutingFailures() != 1 {
		t.Fatalf("tool review: %v", tr)
	}
	if d := m.GetByDecider(); len(d) != 1 || d[0].GetDeciderUserId() != f.ben.String() || d[0].GetCount() != 1 ||
		d[0].GetFirstResponseP50Seconds() != 300 {
		t.Fatalf("by decider: %v", d)
	}
	if m, err := h.GetWaitlistMetrics(admin, &pantherclawv1.GetWaitlistMetricsRequest{WindowDays: 90}); err != nil ||
		m.GetByKind()[1].GetCount() != 2 {
		t.Fatalf("90 days: %v, %v", m, err)
	}
	// A Security Admin of the agent's team reads its reconciliation, not
	// the org's tool reviews; one of another team reads nothing.
	team := func(id ids.UUID) context.Context {
		return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
			Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.ann},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeTeam, ID: id}}},
		}})
	}
	if m, err := h.GetWaitlistMetrics(team(f.team), &pantherclawv1.GetWaitlistMetricsRequest{}); err != nil || len(m.GetByKind()) != 1 ||
		m.GetByKind()[0].GetKind() != pantherclawv1.WaitlistKind_WAITLIST_KIND_RECONCILIATION || len(m.GetByDecider()) != 1 {
		t.Fatalf("the agent's team: %v, %v", m, err)
	}
	if m, err := h.GetWaitlistMetrics(team(ids.NewV7()), &pantherclawv1.GetWaitlistMetricsRequest{}); err != nil ||
		len(m.GetByKind()) != 0 || len(m.GetByDecider()) != 0 {
		t.Fatalf("another team: %v, %v", m, err)
	}
	if m, err := h.GetWaitlistMetrics(admin, &pantherclawv1.GetWaitlistMetricsRequest{
		Kinds: []pantherclawv1.WaitlistKind{pantherclawv1.WaitlistKind_WAITLIST_KIND_TOOL_REVIEW},
	}); err != nil || len(m.GetByKind()) != 1 || len(m.GetByDecider()) != 0 {
		t.Fatalf("one kind: %v, %v", m, err)
	}
}
