// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// upstreamMCP is a kind-mcp connection of the reviewed upstream package.
func (e *env) upstreamMCP(t *testing.T, name string, simulated bool) app.Connection {
	t.Helper()
	base := "https://" + name + ".example.test/mcp"
	if simulated {
		base = "http://127.0.0.1:9100/mcp"
	}
	c, err := e.svc.Create(e.admin, app.CreateInput{
		Name: name, Kind: app.KindMCP, Package: upstreamPackage, BaseURL: base, Gateway: e.gateway,
		AccessMode: app.AccessNone, Simulated: simulated,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// txnOf adds a transaction of run through conn and returns its id.
func (e *env) txnOf(t *testing.T, conn, run ids.UUID) ids.UUID {
	t.Helper()
	txn := ids.NewV7()
	e.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, mode, connection_id) VALUES ($1, $2, $3, $4, $5, 'payments.refund.get', 'ALLOW', 'ALLOWED', 'gw',
		'enforce', $6)`, e.org, txn, run, ids.NewV7(), make([]byte, 32), conn)
	return txn
}

// TestHR665_ACallsDriftNamesTheServersOwnRun: a drift report that names a
// transaction of the org on the reported connection quarantines the
// package version, and the quarantine entry names that transaction's run.
// A transaction of another connection, of another organization, or one the
// server has no row of names no run, and the drift is processed exactly as
// without one: quarantined, never refused. A periodic report names none,
// and a simulated connection's drift_reported entry names the run too.
func TestHR665_ACallsDriftNamesTheServersOwnRun(t *testing.T) {
	ctx := context.Background()
	observed := "sha256:" + strings.Repeat("ab", 32)
	// named is the quarantine entry's run detail, "" for none; there is
	// exactly one entry, the drift was processed.
	named := func(e *env) string {
		t.Helper()
		if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.package.transitioned'
			AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'reason' = 'upstream_drift'`); n != 1 {
			t.Fatalf("%d quarantine entries, want 1", n)
		}
		if e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.package.transitioned'
			AND convert_from(body, 'UTF8')::jsonb -> 'details' ? 'run'`) == 1 {
			return "named"
		}
		return ""
	}
	runOf := func(e *env, kind string) int64 {
		return e.int64(t, `SELECT count(*) FROM pc.ledger_entries l JOIN pc.runs r ON r.org_id = l.org_id
			AND r.id::text = convert_from(l.body, 'UTF8')::jsonb -> 'details' ->> 'run' WHERE l.kind = $1`, kind)
	}
	report := func(e *env, conn, txn ids.UUID) {
		t.Helper()
		q, err := e.svc.ReportDriftDescribed(ctx, e.org, e.gateway, conn, "get_refund", upstreamDigest, observed,
			app.ObservedDescription{Transaction: txn})
		if err != nil || !q {
			t.Fatalf("report: quarantined=%v, %v", q, err)
		}
	}

	t.Run("its own transaction", func(t *testing.T) {
		e := newEnv(t)
		e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
		c := e.upstreamMCP(t, "upstream", false)
		_, run := e.agentRun(t, "coder")
		report(e, c.ID, e.txnOf(t, c.ID, run))
		if named(e) != "named" || e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.package.transitioned'
			AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'run' = $1`, run.String()) != 1 {
			t.Fatal("the quarantine entry does not name the transaction's run")
		}
	})
	t.Run("another connection's transaction", func(t *testing.T) {
		e := newEnv(t)
		e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
		c, other := e.upstreamMCP(t, "upstream", false), e.payments(t, "other")
		_, run := e.agentRun(t, "coder")
		report(e, c.ID, e.txnOf(t, other.ID, run))
		if named(e) != "" {
			t.Fatal("a transaction of another connection named a run")
		}
	})
	t.Run("another organization's transaction", func(t *testing.T) {
		e := newEnv(t)
		e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
		c := e.upstreamMCP(t, "upstream", false)
		o := e.withOrg(t)
		o.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
		oc := o.upstreamMCP(t, "upstream", false)
		_, run := o.agentRun(t, "coder")
		report(e, c.ID, o.txnOf(t, oc.ID, run))
		if named(e) != "" || runOf(e, "audit.package.transitioned") != 0 {
			t.Fatal("another organization's transaction named a run")
		}
	})
	t.Run("an unknown transaction and a periodic check", func(t *testing.T) {
		for _, txn := range []ids.UUID{ids.NewV7(), {}} {
			e := newEnv(t)
			e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
			report(e, e.upstreamMCP(t, "upstream", false).ID, txn)
			if named(e) != "" {
				t.Fatalf("transaction %s named a run", txn)
			}
		}
	})
	t.Run("a simulated connection", func(t *testing.T) {
		e := newEnv(t)
		e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
		c := e.upstreamMCP(t, "upstream-sim", true)
		_, run := e.agentRun(t, "coder")
		if q, err := e.svc.ReportDriftDescribed(ctx, e.org, e.gateway, c.ID, "get_refund", upstreamDigest, observed,
			app.ObservedDescription{Transaction: e.txnOf(t, c.ID, run)}); err != nil || q {
			t.Fatalf("simulated drift: quarantined=%v, %v", q, err)
		}
		if runOf(e, "audit.connection.drift_reported") != 1 {
			t.Fatal("the simulated drift_reported entry does not name the run")
		}
	})
}
