// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Covers: F123

// withPIIRefunds declares that a refund read returns the customer's email,
// a pii field (G0 M16 D72).
func withPIIRefunds(raw string) string {
	const op, access = "  - operation: payments.refund.get\n", "    access: read\n"
	i := strings.Index(raw, op)
	j := i + strings.Index(raw[i:], access) + len(access)
	return raw[:j] + "    response:\n      format: json\n      fields:\n        - path: customer.email\n          class: pii\n" + raw[j:]
}

// readRefund reads re_1 in run through conn.
func (w *world) readRefund(conn, run ids.UUID) finalize.Result {
	w.t.Helper()
	p, err := w.mapper.MCP(context.Background(), mapping.Context{
		Org: w.org.String(), Env: w.env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: w.instance.String(),
		Connection: conn.String(),
	}, "get_refund", []byte(`{"refund":"re_1"}`))
	if err != nil {
		w.t.Fatal(err)
	}
	return w.authorize(pipeline.Request{Org: w.org, Action: p, Identity: pipeline.Identity{InstanceID: w.instance, AgentID: w.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}})
}

// childRun starts a child run of parent under the same grant.
func (w *world) childRun(parent ids.UUID, grant ids.UUID) ids.UUID {
	w.t.Helper()
	child := w.run(gdomain.GrantID{}, parent)
	exec(w.t, w.pool, w.org, "UPDATE pc.runs SET grant_id = $1 WHERE id = $2", grant, child)
	return child
}

// TestHR430_AnAllowedReadRecordsItsClass: in PostgreSQL an allowed read of
// a pii field records read_class pii on its transaction, and the write
// that is not a read records none (HR-434: the class, never content).
func TestHR430_AnAllowedReadRecordsItsClass(t *testing.T) {
	w := newWorldWith(t, withPIIRefunds)
	w.refundable("ch_1")
	g := w.grant("500.00")
	run := w.run(g.ID, ids.UUID{})
	r := w.readRefund(w.conn, run)
	if r.Decision != adomain.Allow {
		t.Fatalf("the read: %s (%s)", r.Decision, decisive(r))
	}
	if c := w.scalar("SELECT coalesce(read_class, '') FROM pc.transactions WHERE id = $1", r.TransactionID); c != "pii" {
		t.Fatalf("read_class %q, want pii", c)
	}
	reads, err := w.auth.Pipeline.Reader.SensitiveReads(context.Background(), w.org, run)
	if err != nil || len(reads) != 1 || reads[0].TransactionID != r.TransactionID || reads[0].Class != "pii" ||
		reads[0].Operation != "payments.refund.get" {
		t.Fatalf("sensitive reads: %+v %v", reads, err)
	}
}

// TestT190_APIIReadInAChildRunHoldsADisclosureInTheTree: a pii read in a
// child run holds a public refund (an external disclosure, D74) in its
// parent and in a sibling with DATA_FLOW_HOLD; another run tree is not
// held. In monitor mode the permit is issued and the receipt says it
// would have been held (HR-433).
func TestT190_APIIReadInAChildRunHoldsADisclosureInTheTree(t *testing.T) {
	w := newWorldWith(t, withPIIRefunds)
	w.refundable("ch_1")
	g := w.grant("500.00")
	root, other := w.run(g.ID, ids.UUID{}), w.run(g.ID, ids.UUID{})
	child, sibling := w.childRun(root, g.ID.UUID()), w.childRun(root, g.ID.UUID())

	if r := w.authorize(w.through(w.conn, root, "ch_1", "10.00")); r.Decision != adomain.Allow {
		t.Fatalf("before any read: %s (%s)", r.Decision, decisive(r))
	}
	if r := w.readRefund(w.conn, child); r.Decision != adomain.Allow {
		t.Fatalf("the child's read: %s (%s)", r.Decision, decisive(r))
	}
	for name, run := range map[string]ids.UUID{"parent": root, "sibling": sibling} {
		r := w.authorize(w.through(w.conn, run, "ch_1", "11.00"))
		if r.Decision != adomain.RequireApproval || decisive(r) != pipeline.ReasonDataFlowHold {
			t.Fatalf("%s: %s (%s)", name, r.Decision, decisive(r))
		}
	}
	if r := w.authorize(w.through(w.conn, other, "ch_1", "12.00")); r.Decision != adomain.Allow {
		t.Fatalf("another tree: %s (%s)", r.Decision, decisive(r))
	}

	monitor := w.withConnection(pipeline.ModeMonitor)
	r := w.authorize(w.through(monitor, root, "ch_1", "13.00"))
	const would = "HOLD: " + pipeline.ReasonDataFlowHold
	if r.Permit == "" || r.Would != would {
		t.Fatalf("monitor: permit %q would %q", r.Permit, r.Would)
	}
	if c := claims(t, r.Receipt); c["would"] != would || c["monitor"] != true {
		t.Fatalf("the receipt says would %v, monitor %v", c["would"], c["monitor"])
	}
}

// TestTenancy_transactions_read_class (00196): another org reads none of
// an org's read history, through the Reader or the table.
func TestTenancy_transactions_read_class(t *testing.T) {
	w := newWorldWith(t, withPIIRefunds)
	g := w.grant("500.00")
	run := w.run(g.ID, ids.UUID{})
	if r := w.readRefund(w.conn, run); r.Decision != adomain.Allow {
		t.Fatalf("the read: %s (%s)", r.Decision, decisive(r))
	}
	b := newWorld(t)
	reader := b.auth.Pipeline.Reader.(*pgauthority.Reader)
	if reads, err := reader.SensitiveReads(context.Background(), b.org, run); err != nil || len(reads) != 0 {
		t.Fatalf("another org reads %+v %v", reads, err)
	}
	if n := b.scalar("SELECT count(*)::text FROM pc.transactions WHERE read_class IS NOT NULL"); n != "0" {
		t.Fatalf("another org sees %s classified reads", n)
	}
	if n := w.scalar("SELECT count(*)::text FROM pc.transactions WHERE read_class = 'pii'"); n != "1" {
		t.Fatalf("the org sees %s classified reads", n)
	}
}
