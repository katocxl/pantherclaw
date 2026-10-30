// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	casesdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	casesstore "github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// openCase opens a case without a ticket.
func (f *fixture) openCase(title string) ids.UUID {
	f.t.Helper()
	var id ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		k, err := casesstore.Open(ctx, tx, casesdomain.NewCase{Title: title, Source: "manual", OpenedBy: casesdomain.Author{Type: "user", ID: f.alice.String()}})
		id = k.ID
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// lease leases the outbound's task to gw as the gateway would and returns
// the lease hash.
func (f *fixture) lease(outbound, gw ids.UUID) (ids.UUID, []byte) {
	f.t.Helper()
	var task ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT verification_id FROM pc.ticket_outbound WHERE id = $1", outbound).Scan(&task)
	}); err != nil {
		f.t.Fatal(err)
	}
	hash := sha256.Sum256(task[:])
	f.exec(`UPDATE pc.verifications SET state = 'LEASED', lease_hash = $2, leased_by = $3, leased_at = now(),
		lease_expires_at = now() + interval '20 seconds', attempts = attempts + 1 WHERE id = $1`, task, hash[:], gw)
	return task, hash[:]
}

func (f *fixture) report(gw, task ids.UUID, hash []byte, status int, fields map[string]string) bool {
	f.t.Helper()
	var ok bool
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		ok, err = f.svc.ReportTicketSync(ctx, tx, f.org, gw, task, hash, status, fields)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return ok
}

// TestTicketSync_OpenThroughTheGateway: opening a case's ticket stores a
// ticket_sync task for the configuration's connection (the server holds no
// Jira credential, HR-060) with the project, summary and issue type only;
// the gateway's report under its lease links the new issue once; a failed
// write is recorded and never sent again; another project's key is refused.
//
// Covers: F545
func TestTicketSync_OpenThroughTheGateway(t *testing.T) {
	f := newFixture(t)
	var gw ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT gateway_id FROM pc.connections WHERE id = $1", f.conn).Scan(&gw)
	}); err != nil {
		t.Fatal(err)
	}
	kase := f.openCase("token leaked in CI")
	out, err := f.svc.OpenCaseTicket(f.as(), kase, f.config)
	if err != nil {
		t.Fatal(err)
	}
	var purpose, op, request string
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT v.purpose, v.operation, v.request::text FROM pc.verifications v
			JOIN pc.ticket_outbound o ON o.verification_id = v.id WHERE o.id = $1 AND v.connection_id = $2`, out, f.conn).Scan(&purpose, &op, &request)
	}); err != nil {
		t.Fatal(err)
	}
	if purpose != "ticket_sync" || op != "jira.issue.create" || !strings.Contains(request, `"SEC"`) || !strings.Contains(request, "token leaked in CI") {
		t.Fatalf("task %s %s %s", purpose, op, request)
	}
	task, hash := f.lease(out, gw)
	if f.report(ids.NewV7(), task, hash, 201, map[string]string{"/key": "SEC-42"}) {
		t.Fatal("another gateway's report was taken")
	}
	if !f.report(gw, task, hash, 201, map[string]string{"/key": "SEC-42", "/id": "10042"}) {
		t.Fatal("the report was not taken")
	}
	if f.report(gw, task, hash, 201, map[string]string{"/key": "SEC-43"}) {
		t.Fatal("a second report was taken")
	}
	if n := f.count("SELECT count(*) FROM pc.external_refs WHERE case_id = $1 AND external_key = 'SEC-42' AND created_by = 'system:ticketsync'", kase); n != 1 {
		t.Fatalf("%d refs", n)
	}
	if n := f.count("SELECT count(*) FROM pc.verifications WHERE id = $1 AND state = 'DONE'", task); n != 1 {
		t.Fatal("the task is not done")
	}
	if _, err := f.svc.OpenCaseTicket(f.as(), kase, f.config); err == nil {
		t.Fatal("a linked case opened a second ticket")
	}

	// A failed write and a key of another project.
	for status, fields := range map[int]map[string]string{502: nil, 201: {"/key": "OPS-1"}} {
		k := f.openCase("another")
		out, err := f.svc.OpenCaseTicket(f.as(), k, f.config)
		if err != nil {
			t.Fatal(err)
		}
		task, hash := f.lease(out, gw)
		if !f.report(gw, task, hash, status, fields) {
			t.Fatal("the report was not taken")
		}
		if n := f.count("SELECT count(*) FROM pc.ticket_outbound WHERE id = $1 AND state = 'FAILED'", out); n != 1 {
			t.Fatalf("status %d: the outbound is not FAILED", status)
		}
		if n := f.count("SELECT count(*) FROM pc.external_refs WHERE case_id = $1", k); n != 0 {
			t.Fatalf("status %d: a ref was made", status)
		}
		// A write is leased once: the failed task is never due again.
		if n := f.count("SELECT count(*) FROM pc.verifications WHERE id = $1 AND state = 'PENDING'", task); n != 0 {
			t.Fatal("the failed write is due again")
		}
	}
}
