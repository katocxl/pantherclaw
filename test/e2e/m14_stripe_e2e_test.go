// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/stripe"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The Stripe test-mode connector of G0 M14 (PN-017.2, D12–D14, D54) end to
// end on the Stripe simulator: the seeded connection "stripe" is held by the
// gateway with a sealed restricted test key, the gateway reads the
// refundable fact before every refund, and the seeded grant allows refunds
// up to 100.00 USD, one per task, with refunds over 50.00 USD held.

// The keys the simulator knows: the test key every stack seals unless told
// otherwise, a test-shaped key the simulator answers in live mode (D54), and
// a live key the gateway must never send (HR-303).
var (
	stripeTestKey     = stripe.FakeKey("rk", "test", "E2eRestrictedKey00000001")
	stripeLivemodeKey = stripe.FakeKey("rk", "test", "E2eAnswersInLiveMode0001")
	stripeLiveKey     = stripe.FakeKey("sk", "live", "E2eLiveSecretKey00000001")
)

var seededStripe = regexp.MustCompile(`seeded stripe connection ([0-9a-f-]{36}) `)

// stripeSim is the Stripe a stack's connection "stripe" calls
// (options.stripe): the simulator, with its own count of writes.
type stripeSim struct {
	sim    *stripe.Server
	url    string
	conn   ids.UUID
	writes atomic.Int64 // non-GET API requests the simulator received
}

// startStripeSim starts the simulator with faults; it accepts the e2e test
// key, and the live-mode key answering in live mode.
func startStripeSim(t *testing.T, f stripe.Faults) *stripeSim {
	t.Helper()
	sim := stripe.New(f, pclog.Discard()).WithRequire(stripe.Require{Keys: []string{stripeTestKey}, LivemodeKey: stripeLivemodeKey})
	st := &stripeSim{sim: sim}
	h := sim.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			st.writes.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	st.url = srv.URL
	return st
}

// stripeSeeded reads the seeded Stripe connection from dev seed's output.
func (s *stack) stripeSeeded(t *testing.T, out string) {
	t.Helper()
	m := seededStripe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("dev seed output %q", out)
	}
	s.st.conn = mustUUID(t, m[1])
}

// sealStripeKey seals key for the stripe connection as a gateway admin does
// with pclaw seal, and returns the gateway configuration version that
// carries it.
func (s *stack) sealStripeKey(t *testing.T, key string) int64 {
	t.Helper()
	admin := s.person(t, "stripe-admin", td.RoleGatewayAdmin)
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin.ctx, s.st.conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), creddomain.AAD, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin.ctx, credapp.PutInput{
		Connection: s.st.conn, BrokerKey: mustUUID(t, k.Binding.BrokerKey), Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme,
	}); err != nil {
		t.Fatal(err)
	}
	return s.configVersion(t, k.Gateway)
}

// stripeCall sends one form-encoded request through the stripe connection
// as the seeded workload, signed with PAP/1, and returns the status, the
// gateway's refusal or PC-* facts, and the body.
func (s *stack) stripeCall(t *testing.T, method, path string, form url.Values, act ids.UUID) (int, reply, string) {
	t.Helper()
	code, r, body, err := s.tryStripeCall(method, path, form, act)
	if err != nil {
		t.Fatal(err)
	}
	return code, r, body
}

func (s *stack) tryStripeCall(method, path string, form url.Values, act ids.UUID) (int, reply, string, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, s.gateway+"/stripe"+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set(gateway.HeaderRunID, s.run)
	req.Header.Set(gateway.HeaderActionID, act.String())
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, reply{}, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var r reply
	if resp.StatusCode >= 300 {
		_ = json.Unmarshal(b, &r)
		return resp.StatusCode, r, string(b), nil
	}
	r.TransactionID, r.Outcome, r.Receipt = resp.Header.Get("PC-Transaction-Id"), resp.Header.Get("PC-Outcome"), resp.Header.Get("PC-Receipt")
	return resp.StatusCode, r, string(b), nil
}

// stripeRefund refunds amount minor units of payment, in the payment's
// currency written as Stripe writes it (lowercase).
func (s *stack) stripeRefund(t *testing.T, act ids.UUID, payment, amount, currency string) (int, reply) {
	t.Helper()
	code, r, _ := s.stripeCall(t, http.MethodPost, "/v1/refunds", refundForm(payment, amount, currency), act)
	return code, r
}

func refundForm(payment, amount, currency string) url.Values {
	key := "payment_intent"
	if strings.HasPrefix(payment, "ch_") {
		key = "charge"
	}
	return url.Values{key: {payment}, "amount": {amount}, "currency": {currency}, "reason": {"duplicate"}}
}

// TestE2E_M14_StripeRefunds is the second-market refund flow on the Stripe
// simulator (D14).
func TestE2E_M14_StripeRefunds(t *testing.T) {
	t.Run("allowed refund settles to CONFIRMED with the transaction's idempotency key", func(t *testing.T) {
		s := start(t, options{budget: "1000.00", stripe: true, stripeFaults: stripe.Faults{SettleAfter: 4 * time.Second}})
		code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "3000", "usd")
		if code != http.StatusOK || r.Outcome != "ACCEPTED" || r.Receipt == "" {
			t.Fatalf("refund: %d %+v", code, r)
		}
		refunds := s.st.sim.Refunds()
		if len(refunds) != 1 || refunds[0].Amount != 3000 || refunds[0].PaymentIntent != stripe.FixturePayment || refunds[0].Key != "pc-"+r.TransactionID {
			t.Fatalf("refunds at Stripe %+v, want one of 3000 keyed pc-%s", refunds, r.TransactionID)
		}
		// Pending while Stripe settles, then confirmed by the verifier.
		s.eventually(t, "CONFIRMED", "SELECT effect_state FROM pc.transactions WHERE id = $1", r.TransactionID)
		if got := s.row(t, "SELECT count(*)::text FROM pc.effect_receipts WHERE transaction_id = $1 AND state = 'PROPAGATION_PENDING'",
			r.TransactionID); got == "0" {
			t.Fatal("no pending effect receipt before the refund settled")
		}
		if s.st.writes.Load() != 1 {
			t.Fatalf("%d writes at Stripe, want 1", s.st.writes.Load())
		}
	})

	t.Run("a refund over 50 is held, approved and dispatched once", func(t *testing.T) {
		p := inProcessIdP(t)
		s := start(t, options{budget: "1000.00", people: &p, stripe: true})
		_, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})
		act := ids.NewV7()
		code, held := s.stripeRefund(t, act, stripe.FixturePayment, "7500", "usd")
		if code != http.StatusForbidden || held.ErrorClass != "held" || held.Decision != "REQUIRE_APPROVAL" || s.st.writes.Load() != 0 {
			t.Fatalf("hold: %d %+v", code, held)
		}
		s.approve(t, b, key, held.TransactionID)
		code, done := s.stripeRefund(t, act, stripe.FixturePayment, "7500", "usd")
		if code != http.StatusOK || done.Outcome != "ACCEPTED" || done.TransactionID != held.TransactionID || s.st.writes.Load() != 1 {
			t.Fatalf("resubmission: %d %+v (writes %d)", code, done, s.st.writes.Load())
		}
	})

	t.Run("a refund over 100 is denied with nothing to approve", func(t *testing.T) {
		s := start(t, options{budget: "1000.00", stripe: true})
		act := ids.NewV7()
		code, denied := s.stripeRefund(t, act, stripe.FixturePayment, "12500", "usd")
		if code != http.StatusForbidden || denied.Decision != "DENY" || s.requestOf(t, denied.TransactionID) != "" {
			t.Fatalf("deny: %d %+v", code, denied)
		}
		if code, again := s.stripeRefund(t, act, stripe.FixturePayment, "12500", "usd"); code != http.StatusForbidden || again.Decision != "DENY" {
			t.Fatalf("resubmission: %d %+v", code, again)
		}
		if s.st.writes.Load() != 0 {
			t.Fatalf("%d writes at Stripe", s.st.writes.Load())
		}
	})

	t.Run("two concurrent refunds against a one-refund budget: exactly one", func(t *testing.T) {
		s := start(t, options{budget: "1000.00", stripe: true})
		var wg sync.WaitGroup
		codes := make([]int, 2)
		for i := range codes {
			wg.Go(func() {
				code, _, _, err := s.tryStripeCall(http.MethodPost, "/v1/refunds", refundForm(stripe.FixturePayment, "1000", "usd"), ids.NewV7())
				if err != nil {
					t.Error(err)
				}
				codes[i] = code
			})
		}
		wg.Wait()
		ok := 0
		for _, c := range codes {
			if c == http.StatusOK {
				ok++
			}
		}
		if ok != 1 || len(s.st.sim.Refunds()) != 1 {
			t.Fatalf("codes %v, refunds %d: want exactly one", codes, len(s.st.sim.Refunds()))
		}
	})

	t.Run("a lost answer is UNKNOWN, never retried, and reconciled from Stripe", func(t *testing.T) {
		s := start(t, options{
			budget: "1000.00", stripe: true, stripeFaults: stripe.Faults{LoseRate: 1, HangFor: time.Minute},
			timeout: 1500 * time.Millisecond,
		})
		code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "2000", "usd")
		if code != http.StatusGatewayTimeout || r.Outcome != "UNKNOWN" {
			t.Fatalf("lost answer: %d %+v", code, r)
		}
		s.st.sim.SetFaults(stripe.Faults{})
		s.eventually(t, "OCCURRED", "SELECT state FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID)
		if via := s.row(t, "SELECT resolved_via FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID); via != "verifier" && via != "target_log" {
			t.Fatalf("resolved via %q, want evidence", via)
		}
		if s.st.writes.Load() != 1 || len(s.st.sim.Refunds()) != 1 {
			t.Fatalf("writes %d, refunds %d: the gateway retried", s.st.writes.Load(), len(s.st.sim.Refunds()))
		}
	})

	t.Run("a live key is refused before anything reaches Stripe", func(t *testing.T) {
		s := start(t, options{budget: "1000.00", stripe: true, stripeKey: stripeLiveKey})
		code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "1000", "usd")
		if code == http.StatusOK || r.Outcome == "ACCEPTED" {
			t.Fatalf("a refund with a live key: %d %+v", code, r)
		}
		if st := s.st.sim.Stats(); st.Requests != 0 {
			t.Fatalf("Stripe saw %d requests with a live key", st.Requests)
		}
	})

	t.Run("a refundable fact that cannot be read fresh is CANNOT_AUTHORIZE", func(t *testing.T) {
		// Stripe answers slower than the gateway's fact timeout (2 s): no
		// fresh refundable fact, so nothing is decided or sent.
		s := start(t, options{budget: "1000.00", stripe: true})
		s.st.sim.SetFaults(stripe.Faults{Latency: 3 * time.Second})
		code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "1000", "usd")
		if code == http.StatusOK || r.Decision != "CANNOT_AUTHORIZE" || s.st.writes.Load() != 0 {
			t.Fatalf("stale fact: %d %+v (writes %d)", code, r, s.st.writes.Load())
		}
	})

	t.Run("a refund above what is left on the payment is CANNOT_AUTHORIZE", func(t *testing.T) {
		s := start(t, options{budget: "1000.00", stripe: true})
		// 50.00 USD paid; 60.00 cannot be refunded whatever the grant says.
		code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment2, "6000", "usd")
		if code == http.StatusOK || r.Decision != "CANNOT_AUTHORIZE" || !strings.Contains(strings.Join(r.Reasons, " "), "AMOUNT_NOT_REFUNDABLE") ||
			s.st.writes.Load() != 0 {
			t.Fatalf("over the refundable: %d %+v", code, r)
		}
		// A refund in another currency than the payment's.
		code, r = s.stripeRefund(t, ids.NewV7(), stripe.FixturePaymentEUR, "1000", "usd")
		if code == http.StatusOK || r.Decision != "CANNOT_AUTHORIZE" || s.st.writes.Load() != 0 {
			t.Fatalf("another currency: %d %+v", code, r)
		}
	})
}
