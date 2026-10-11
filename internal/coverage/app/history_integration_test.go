// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestIntAScopesHistoryIsItsSnapshotsNewestFirst: every recorded snapshot
// of a scope is listed newest first with its full record, and one is read
// by id; a viewer reads neither.
func TestIntAScopesHistoryIsItsSnapshotsNewestFirst(t *testing.T) {
	f := newFixture(t)
	sc := domain.Scope{Agent: f.agent, Connection: f.conn, Operation: "payments.refund.create"}
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), sc.Operation, f.conn)
	f.reassessOrg(t)
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	auditor := f.as(td.RoleAuditor)
	list, next, err := f.svc.ListSnapshots(auditor, sc, 10, "")
	if err != nil || len(list) != 2 || next != "" || list[0].State != "ENFORCED" || list[1].State != "PARTIAL" ||
		len(list[0].Body.Routes) == 0 {
		t.Fatalf("history %+v %q (%v)", list, next, err)
	}
	if s, err := f.svc.GetSnapshot(auditor, list[1].ID); err != nil || s.ID != list[1].ID {
		t.Fatalf("snapshot %+v (%v)", s, err)
	}
	if _, err := f.svc.GetSnapshot(f.as(td.RoleViewer), list[0].ID); !errors.Is(err, app.ErrNotFound) &&
		!errors.Is(err, td.ErrPermissionDenied(td.PermCoverageRead)) {
		t.Fatalf("a viewer read a snapshot: %v", err)
	}
}
