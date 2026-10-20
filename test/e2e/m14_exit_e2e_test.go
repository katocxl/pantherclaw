// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sim/stripe"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M14_SecondMarketDemo is M14's exit flow (G0 M14 D41 as amended
// by D90): a support agent resolves a ticket with a refund. Its refund of
// 75.00 USD through the gateway's HTTP face to Stripe (test mode) is over
// the 50.00 hold line, so PantherClaw holds it; an approver approves it on
// the approval page with a security key; the identical resubmission is
// dispatched once, with the transaction as its idempotency key; Stripe
// settles it and the verifier confirms it (CONFIRMED); and `pclaw verify`
// checks the transaction's decision, execution and effect receipts
// offline against the keys pinned on first use. The grant is the dev
// seed's refund grant (refunds at most 100.00, held over 50.00), the
// customer-support template's terms (D97) until that template lands.
func TestE2E_M14_SecondMarketDemo(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, stripe: true, stripeFaults: stripe.Faults{SettleAfter: 5 * time.Second}})
	// The gateway admin who sealed the key has a stand-in key, not a real
	// one; it is removed, so the approval needs the approver's own.
	s.db.AdminExec(t, `UPDATE pc.webauthn_credentials SET state = 'REMOVED', state_reason = 'ADMIN_REMOVED', changed_at = now()
		WHERE org_id = $1 AND name = 'key'`, s.org)
	_, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})

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
	code, r := pr.verify(t, file)
	if code != 0 {
		t.Fatalf("pclaw verify exit %d:\n%+v", code, r.Checks)
	}
	for _, name := range []string{"bundle.origin", "checkpoint.signature", "entry.link", "entry.inclusion", "receipt.signature", "receipt.ledger"} {
		if !all(r, name, bundle.Passed) {
			t.Errorf("check %s: %v", name, statuses(r, name))
		}
	}
	var kinds []string
	for _, c := range r.Checks {
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
