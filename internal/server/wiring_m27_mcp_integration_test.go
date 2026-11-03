// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestIntHR657_ReadIsInTheOrgsLedger: the app role writes the read's record
// to the caller's org's ledger, kind audit.self_mcp.read, before the answer.
// Covers: F948
func TestIntHR657_ReadIsInTheOrgsLedger(t *testing.T) {
	d := dbtest.New(t)
	c := investigatorCaller()
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'self-mcp')", c.Org)
	g := &selfMCPGate{editions: fixedEditions(billing.Team), record: poolRecorder(d.AppPool(t))}
	run := ids.NewV7().String()
	s := &fakeStream{request: &pb.GetRunTimelineRequest{RunId: run}}
	if err := call(g, c, pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure, s, &pb.GetRunTimelineRequest{}, nil); err != nil {
		t.Fatal(err)
	}
	var n int
	d.AdminQueryRow(t, `SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.self_mcp.read'
		AND position(convert_to($2::text, 'UTF8') IN body) > 0`, []any{c.Org, run}, &n)
	if n != 1 || len(s.sent) != 1 {
		t.Errorf("records %d, sent %d", n, len(s.sent))
	}
}

// TestIntHR663_AHeaderedReadIsInTheOrgsLedger: an Org Admin key's read with
// the header of `pclaw mcp self` is in the caller's org's ledger with basis
// client_header, before the answer; the same read without the header is
// not recorded.
// Covers: F948
func TestIntHR663_AHeaderedReadIsInTheOrgsLedger(t *testing.T) {
	d := dbtest.New(t)
	c := adminCaller()
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'self-mcp-header')", c.Org)
	g := &selfMCPGate{editions: fixedEditions(billing.Community), record: poolRecorder(d.AppPool(t))}
	count := func() int {
		var n int
		d.AdminQueryRow(t, `SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.self_mcp.read'
			AND position(convert_to('"basis":"client_header"', 'UTF8') IN body) > 0`, []any{c.Org}, &n)
		return n
	}
	s := &fakeStream{}
	if _, err := served(g, c, pantherclawv1connect.SearchServiceSearchProcedure, "mcp-self", s, nil); err != nil || len(s.sent) != 1 {
		t.Fatalf("headered read: %v, sent %d", err, len(s.sent))
	}
	if n := count(); n != 1 {
		t.Errorf("records %d, want 1", n)
	}
	s = &fakeStream{}
	if _, err := served(g, c, pantherclawv1connect.SearchServiceSearchProcedure, "", s, nil); err != nil || len(s.sent) != 1 {
		t.Fatalf("plain read: %v, sent %d", err, len(s.sent))
	}
	var all int
	d.AdminQueryRow(t, `SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.self_mcp.read'`, []any{c.Org}, &all)
	if all != 1 {
		t.Errorf("%d records after a read without the header, want 1", all)
	}
}
