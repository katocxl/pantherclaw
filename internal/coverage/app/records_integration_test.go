// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR211_AnEnforcedRecordReadsPartialAtOnceAfterAChange: an ENFORCED
// record reads PARTIAL as soon as a change invalidates it, before any
// reassessment, keeping the ENFORCED snapshot as its last valid record;
// the reassessment then records the downgrade with the same last valid
// record.
func TestHR211_AnEnforcedRecordReadsPartialAtOnceAfterAChange(t *testing.T) {
	f := newFixture(t)
	sc := domain.Scope{Agent: f.agent, Connection: f.conn, Operation: "payments.refund.create"}
	auditor := f.as(td.RoleAuditor)
	if r, err := f.svc.GetCoverage(auditor, sc); err != nil || r.State != domain.Unknown ||
		!slices.Equal(r.Reasons, []string{app.ReasonNotAssessed}) {
		t.Fatalf("before any assessment: %v %v (%v)", r.State, r.Reasons, err)
	}
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), sc.Operation, f.conn)
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	f.reassessOrg(t)
	enforced, err := f.svc.GetCoverage(auditor, sc)
	if err != nil || enforced.State != domain.Enforced || enforced.LastValid != nil ||
		!slices.ContainsFunc(enforced.Body.Routes, func(r app.SnapshotRoute) bool { return r.Status == "closed" }) {
		t.Fatalf("enforced: %v %v (%v)", enforced.State, enforced.Reasons, err)
	}
	f.exec(t, `UPDATE pc.connections SET allowed_hosts = '{api.example.com}' WHERE id = $1`, f.conn)
	r, err := f.svc.GetCoverage(auditor, sc)
	if err != nil || r.State != domain.Partial || r.Computed != domain.Enforced || len(r.Changes) != 1 ||
		r.LastValid == nil || r.LastValid.ID != enforced.Snapshot.ID || r.Lapse != "invalidated:connection" {
		t.Fatalf("after the change, before reassessment: %v/%v lapse %q (%v)", r.State, r.Computed, r.Lapse, err)
	}
	f.reassessOrg(t)
	r, err = f.svc.GetCoverage(auditor, sc)
	if err != nil || r.State != domain.Partial || r.Computed != domain.Partial || r.LastValid == nil ||
		r.LastValid.ID != enforced.Snapshot.ID || r.Lapse != "invalidated:connection" {
		t.Fatalf("after reassessment: %v/%v lapse %q (%v)", r.State, r.Computed, r.Lapse, err)
	}
	list, next, err := f.svc.ListCoverage(f.as(td.RoleSecurityAdmin), app.Filter{Connection: &f.conn}, 10, "")
	if err != nil || len(list) != 1 || list[0].State != domain.Partial || next != "" {
		t.Fatalf("list %v %q (%v)", list, next, err)
	}
	if _, err := f.svc.GetCoverage(f.as(td.RoleViewer), sc); !errors.Is(err, td.ErrPermissionDenied(td.PermCoverageRead)) {
		t.Fatalf("a viewer read coverage: %v", err)
	}
}
