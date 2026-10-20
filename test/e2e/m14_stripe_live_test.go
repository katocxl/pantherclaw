// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && stripe_live

package e2e

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The Stripe part of G0 M14 against Stripe itself in test mode (D14): task
// test:stripe-live, manual and opt-in, never part of task check. It needs a
// restricted test key (PC_TEST_STRIPE_KEY: write on refunds, payment
// intents and transfers; read on charges, accounts and events) and a
// connected test account (PC_TEST_STRIPE_CONNECTED_ACCOUNT). It creates a
// customer with a test card directly at Stripe, then charges it, refunds
// part of it and transfers to the connected account through a local
// gateway, and prints the transaction ids. Nothing here can move real
// money: the gateway refuses any key that is not a test key (HR-303).

// stripeAPI is Stripe's API.
const stripeAPI = "https://api.stripe.com"

// liveStripe is Stripe and the key and payee the environment names, or a
// skip without them.
func liveStripe(t *testing.T) (st *stripeSim, key, payee string) {
	t.Helper()
	key, payee = os.Getenv("PC_TEST_STRIPE_KEY"), os.Getenv("PC_TEST_STRIPE_CONNECTED_ACCOUNT")
	if key == "" || payee == "" {
		t.Skip("PC_TEST_STRIPE_KEY and PC_TEST_STRIPE_CONNECTED_ACCOUNT are not set: the live Stripe run is manual (task test:stripe-live)")
	}
	if !strings.HasPrefix(key, "rk_test_") && !strings.HasPrefix(key, "sk_test_") {
		t.Fatal("PC_TEST_STRIPE_KEY must be a Stripe test key")
	}
	return &stripeSim{url: stripeAPI}, key, payee
}

// stripeDirect calls Stripe with key, outside PantherClaw: the test's own
// setup (a customer and its card), never an agent's action.
func stripeDirect(t *testing.T, key, path string, form url.Values) map[string]any {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, stripeAPI+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Stripe-Version", "2026-09-30.endive")
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: %d %s", path, res.StatusCode, b)
	}
	if v["livemode"] != false {
		t.Fatalf("POST %s answered in live mode", path)
	}
	return v
}

// TestLive_Stripe charges a test customer, refunds part of it and transfers
// to the connected account, each through the gateway.
func TestLive_Stripe(t *testing.T) {
	st, key, payee := liveStripe(t)
	s := start(t, options{budget: "1000.00", stripe: true, stripeAt: st, stripeKey: key, stripePayee: payee, timeout: 30 * time.Second})

	// A customer with a test card whose funds are available at once, so the
	// transfer has a balance to draw on.
	cus := stripeDirect(t, key, "/v1/customers", url.Values{"description": {"PantherClaw live test " + ids.NewV7().String()}})
	customer, _ := cus["id"].(string)
	pm := stripeDirect(t, key, "/v1/payment_methods/pm_card_bypassPending/attach", url.Values{"customer": {customer}})
	method, _ := pm["id"].(string)

	code, charged, body := s.stripeCall(t, http.MethodPost, "/v1/payment_intents", url.Values{
		"customer": {customer}, "amount": {"2000"}, "currency": {"usd"}, "payment_method": {method},
	}, ids.NewV7())
	if code != http.StatusOK || charged.Outcome != "ACCEPTED" {
		t.Fatalf("payment intent: %d %+v %s", code, charged, body)
	}
	var pi struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &pi); err != nil || pi.ID == "" {
		t.Fatalf("payment intent answer %s", body)
	}
	t.Logf("payment intent %s: transaction %s", pi.ID, charged.TransactionID)

	code, refunded := s.stripeRefund(t, ids.NewV7(), pi.ID, "500", "usd")
	if code != http.StatusOK || refunded.Outcome != "ACCEPTED" {
		t.Fatalf("refund: %d %+v", code, refunded)
	}
	t.Logf("refund of 5.00 USD: transaction %s", refunded.TransactionID)

	code, transferred, body := s.stripeCall(t, http.MethodPost, "/v1/transfers", url.Values{
		"destination": {payee}, "amount": {"100"}, "currency": {"usd"},
	}, ids.NewV7())
	if code != http.StatusOK || transferred.Outcome != "ACCEPTED" {
		t.Fatalf("transfer: %d %+v %s", code, transferred, body)
	}
	t.Logf("transfer of 1.00 USD to %s: transaction %s", payee, transferred.TransactionID)

	for _, txn := range []string{charged.TransactionID, refunded.TransactionID, transferred.TransactionID} {
		s.eventually(t, "CONFIRMED", "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", txn)
	}
}
