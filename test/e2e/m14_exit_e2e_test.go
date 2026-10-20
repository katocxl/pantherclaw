// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget/pgtargettest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sim/stripe"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M14_SecondMarketDemo is M14's exit flow (G0 M14 D41 as amended
// by D90 and D109): a support agent resolves a ticket with a refund. It
// reads the ticket, the customer's paid orders and the customer through
// the warehouse connection (pc.postgres) under Community bounds only: the
// grant allows the columns it needs and caps the rows, so a column outside
// the bound and a request over the cap are DENY, and the secret column is
// never returned (record scope, F101, is Team and stays in data's Team
// tests). Its refund of 75.00 USD through the gateway's HTTP face to Stripe (test mode) is over
// the 50.00 hold line, so PantherClaw holds it; an approver approves it on
// the approval page with a security key; the identical resubmission is
// dispatched once, with the transaction as its idempotency key; Stripe
// settles it and the verifier confirms it (CONFIRMED); and `pclaw verify`
// checks the transaction's decision, execution and effect receipts
// offline against the keys pinned on first use. The grant has the
// customer-support template's terms (D97): refunds at most 100.00, held
// over 50.00 by the dev seed's hold policy; it is issued here until that
// template lands.
func TestE2E_M14_SecondMarketDemo(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{
		budget: "1000.00", people: &p, stripe: true, stripeFaults: stripe.Faults{SettleAfter: 5 * time.Second},
		postgres: pgtargettest.New(t),
	})
	if res := s.connectionTest(t); res != "PASSED" {
		t.Fatalf("warehouse connection test: %q", res)
	}
	// The gateway admin who sealed the key has a stand-in key, not a real
	// one; it is removed, so the approval needs the approver's own.
	s.db.AdminExec(t, `UPDATE pc.webauthn_credentials SET state = 'REMOVED', state_reason = 'ADMIN_REMOVED', changed_at = now()
		WHERE org_id = $1 AND name = 'key'`, s.org)
	_, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})
	s.grantRun(t, `{"operations": ["stripe.refund.create", "postgres.rows.read"],
	  "params": {"stripe.refund.create": {"amount": {"max": {"USD": "100.00"}}},
	    "postgres.rows.read": {"columns": {"values": {"ids": ["id", "customer_id", "subject", "amount", "status", "tier", "ssn"]}},
	      "limit": {"range": {"max": "5", "unit": "rows"}}}}}`, false)

	// The ticket names its customer; the customer's paid orders are read up
	// to the cap, and the customer's secret column never leaves the database.
	code, r, a := s.pgCall(t, http.MethodPost, "/v1/query",
		`{"table":"support.tickets","columns":["id","customer_id","subject"],"filters":[{"column":"id","op":"eq","value":"100"}],"limit":1}`)
	if code != http.StatusOK || len(a.Rows) != 1 || fmt.Sprint(a.Rows[0][1]) != "1" {
		t.Fatalf("the ticket: %d %+v %+v", code, r, a)
	}
	code, r, a = s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.orders","columns":["id","customer_id","amount","status"],
		"filters":[{"column":"customer_id","op":"eq","value":"1"},{"column":"status","op":"eq","value":"paid"}],"order_by":["id:asc"],"limit":5}`)
	if code != http.StatusOK || len(a.Rows) != 5 || !a.Truncated {
		t.Fatalf("the customer's paid orders: %d %+v %+v", code, r, a)
	}
	for _, row := range a.Rows {
		if fmt.Sprint(row[1]) != "1" || row[3] != "paid" {
			t.Fatalf("an order of another customer or state: %v", row)
		}
	}
	code, r, a = s.pgCall(t, http.MethodPost, "/v1/query",
		`{"table":"shop.customers","columns":["id","tier","ssn"],"filters":[{"column":"id","op":"eq","value":"1"}],"limit":1}`)
	if code != http.StatusOK || len(a.Rows) != 1 || a.Rows[0][1] != "gold" || a.Rows[0][2] != "[redacted:secret]" {
		t.Fatalf("the customer: %d %+v %+v", code, r, a)
	}
	// Outside the bounds: a column the grant does not allow, and more rows
	// than it caps, are DENY.
	if code, r, _ := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.customers","columns":["id","email"],"limit":1}`); code == http.StatusOK ||
		r.Decision != "DENY" {
		t.Fatalf("a column outside the bound: %d %+v", code, r)
	}
	if code, r, _ := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.orders","columns":["id"],"limit":10}`); code == http.StatusOK ||
		r.Decision != "DENY" {
		t.Fatalf("over the row cap: %d %+v", code, r)
	}

	// The refund over 50.00 is held: nothing reaches Stripe.
	act := ids.NewV7()
	code, held := s.stripeRefund(t, act, stripe.FixturePayment, "7500", "usd")
	if code != http.StatusForbidden || held.ErrorClass != "held" || held.Decision != "REQUIRE_APPROVAL" || s.st.writes.Load() != 0 {
		t.Fatalf("the refund over 50.00 is not held: %d %+v (writes %d)", code, held, s.st.writes.Load())
	}

	// Approved on the approval page with the approver's security key; the
	// identical resubmission is dispatched once, keyed by the transaction.
	s.approveStripe(t, b, key, held.TransactionID)
	code, done := s.stripeRefund(t, act, stripe.FixturePayment, "7500", "usd")
	if code != http.StatusOK || done.Outcome != "ACCEPTED" || done.TransactionID != held.TransactionID || s.st.writes.Load() != 1 {
		t.Fatalf("the approved resubmission: %d %+v (writes %d)", code, done, s.st.writes.Load())
	}
	refunds := s.st.sim.Refunds()
	if len(refunds) != 1 || refunds[0].Amount != 7500 || refunds[0].Key != "pc-"+held.TransactionID {
		t.Fatalf("refunds at Stripe %+v, want one of 7500 keyed pc-%s", refunds, held.TransactionID)
	}

	// Pending while Stripe settles, then confirmed by the verifier.
	s.eventually(t, "CONFIRMED", "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", held.TransactionID)

	// The receipts verify offline.
	txn, err := ids.ParseUUID(held.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	pr := s.proof(t)
	pr.checkpointed(t, txn)
	auditor := s.person(t, "demo-auditor", td.RoleAuditor).ctx
	file, x := pr.export(t, auditor, "refund.json", evapp.Selection{Transactions: []ids.UUID{txn}}, 0)
	if x.Receipts < 3 {
		t.Fatalf("export: %d receipts", x.Receipts)
	}
	code, rep := pr.verify(t, file)
	if code != 0 {
		t.Fatalf("pclaw verify exit %d:\n%+v", code, rep.Checks)
	}
	for _, name := range []string{"bundle.origin", "checkpoint.signature", "entry.link", "entry.inclusion", "receipt.signature", "receipt.ledger"} {
		if !all(rep, name, bundle.Passed) {
			t.Errorf("check %s: %v", name, statuses(rep, name))
		}
	}
	var kinds []string
	for _, c := range rep.Checks {
		if c.Name == "receipt.signature" {
			kinds = append(kinds, strings.Fields(c.Subject)[0])
		}
	}
	for _, kind := range []string{"pap-decision", "pap-execution", "pap-effect"} {
		if !slices.Contains(kinds, kind) {
			t.Errorf("no %s receipt verified: %v", kind, kinds)
		}
	}
}
