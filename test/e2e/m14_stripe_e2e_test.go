// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
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
		s := start(t, options{budget: "1000.00", stripe: true, stripeFaults: stripe.Faults{SettleAfter: 10 * time.Second}})
		code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "3000", "usd")
		if code != http.StatusOK || r.Outcome != "ACCEPTED" || r.Receipt == "" {
			t.Fatalf("refund: %d %+v", code, r)
		}
		refunds := s.st.sim.Refunds()
		if len(refunds) != 1 || refunds[0].Amount != 3000 || refunds[0].PaymentIntent != stripe.FixturePayment || refunds[0].Key != "pc-"+r.TransactionID {
			t.Fatalf("refunds at Stripe %+v, want one of 3000 keyed pc-%s", refunds, r.TransactionID)
		}
		// Pending while Stripe settles, then confirmed by the verifier.
		s.eventually(t, "PROPAGATION_PENDING", "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", r.TransactionID)
		s.eventually(t, "CONFIRMED", "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", r.TransactionID)
		if s.st.writes.Load() != 1 {
			t.Fatalf("%d writes at Stripe, want 1", s.st.writes.Load())
		}
	})

	t.Run("a refund over 50 is held, approved and dispatched once", func(t *testing.T) {
		p := inProcessIdP(t)
		s := start(t, options{budget: "1000.00", people: &p, stripe: true})
		// The gateway admin who sealed the key has a stand-in key, not a
		// real one; it is removed, so the export holds the approver's only.
		s.db.AdminExec(t, `UPDATE pc.webauthn_credentials SET state = 'REMOVED', state_reason = 'ADMIN_REMOVED', changed_at = now()
			WHERE org_id = $1 AND name = 'key'`, s.org)
		_, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})
		act := ids.NewV7()
		code, held := s.stripeRefund(t, act, stripe.FixturePayment, "7500", "usd")
		if code != http.StatusForbidden || held.ErrorClass != "held" || held.Decision != "REQUIRE_APPROVAL" || s.st.writes.Load() != 0 {
			t.Fatalf("hold: %d %+v", code, held)
		}
		s.approveStripe(t, b, key, held.TransactionID)
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
}

// stripeWrite is a request that reaches one pc.stripe write through the
// gateway's HTTP face.
type stripeWrite struct {
	path string
	form url.Values
}

// stripeWrites are the requests for every pc.stripe write.
func stripeWrites() map[string]stripeWrite {
	return map[string]stripeWrite{
		"stripe.refund.create": {"/v1/refunds", refundForm(stripe.FixturePayment, "1000", "usd")},
		"stripe.payment_intent.create": {"/v1/payment_intents", url.Values{
			"customer": {stripe.FixtureCustomer}, "amount": {"1000"}, "currency": {"usd"}, "payment_method": {stripe.FixturePaymentMethod},
		}},
		"stripe.payment_intent.cancel": {"/v1/payment_intents/" + stripe.FixturePayment + "/cancel", url.Values{}},
		"stripe.transfer.create": {"/v1/transfers", url.Values{
			"destination": {stripe.FixturePayee}, "amount": {"1000"}, "currency": {"usd"},
		}},
	}
}

// TestHR303_LiveKeyRefusedBeforeSend: with a live key sealed, every
// pc.stripe write is refused and nothing reaches Stripe, not even a fact
// read (HR-301, HR-303).
func TestHR303_LiveKeyRefusedBeforeSend(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true, stripeKey: stripeLiveKey})
	for op, w := range stripeWrites() {
		code, r, body := s.stripeCall(t, http.MethodPost, w.path, w.form, ids.NewV7())
		if code == http.StatusOK || r.Outcome == "ACCEPTED" {
			t.Errorf("%s with a live key: %d %s", op, code, body)
		}
	}
	if st := s.st.sim.Stats(); st.Requests != 0 {
		t.Fatalf("Stripe saw %d requests with a live key", st.Requests)
	}
}

// TestHR303_RefundableFactLivemodeRefused: a refundable fact read in live
// mode is never a fact: the refund is CANNOT_AUTHORIZE and nothing is
// written.
func TestHR303_RefundableFactLivemodeRefused(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true, stripeKey: stripeLivemodeKey})
	code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "1000", "usd")
	if code == http.StatusOK || r.Decision != "CANNOT_AUTHORIZE" || s.st.writes.Load() != 0 {
		t.Fatalf("a live-mode fact: %d %+v (writes %d)", code, r, s.st.writes.Load())
	}
}

// TestHR303_LivemodeAnswerQuarantines: a Stripe answer in live mode, seen
// by a fact read, a dispatch or a verifier read, quarantines the connection
// (stripe_livemode), records security.stripe_livemode and tells the
// admins; nothing is sent through it until a person restores it.
func TestHR303_LivemodeAnswerQuarantines(t *testing.T) {
	quarantined := func(t *testing.T, s *stack) {
		t.Helper()
		s.eventually(t, "QUARANTINED stripe_livemode", "SELECT state || ' ' || coalesce(quarantine_reason, '') FROM pc.connections WHERE id = $1", s.st.conn)
		if got := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.security.stripe_livemode'"); got == "0" {
			t.Fatal("no security.stripe_livemode audit event")
		}
		if got := s.row(t, "SELECT count(*)::text FROM pc.notifications WHERE type = 'security.connection_quarantined'"); got == "0" {
			t.Fatal("the admins were not told")
		}
		s.st.sim.SetFaults(stripe.Faults{})
		before := s.st.sim.Stats().Requests
		if code, _ := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment2, "1000", "usd"); code == http.StatusOK || s.st.sim.Stats().Requests != before {
			t.Fatalf("a quarantined connection sent: %d", code)
		}
	}
	t.Run("fact read", func(t *testing.T) {
		s := start(t, options{budget: "1000.00", stripe: true, stripeKey: stripeLivemodeKey})
		if code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "1000", "usd"); code == http.StatusOK || s.st.writes.Load() != 0 {
			t.Fatalf("refund: %d %+v", code, r)
		}
		quarantined(t, s)
	})
	t.Run("dispatch answer", func(t *testing.T) {
		// A payment intent reads no fact: Stripe's answer to the write is the
		// first live-mode answer.
		s := start(t, options{budget: "1000.00", stripe: true})
		s.st.sim.SetFaults(stripe.Faults{AnswerLivemode: true})
		w := stripeWrites()["stripe.payment_intent.create"]
		s.stripeCall(t, http.MethodPost, w.path, w.form, ids.NewV7())
		quarantined(t, s)
	})
	t.Run("verifier read", func(t *testing.T) {
		s := start(t, options{budget: "1000.00", stripe: true, stripeFaults: stripe.Faults{SettleAfter: time.Hour}})
		code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "1000", "usd")
		if code != http.StatusOK {
			t.Fatalf("refund: %d %+v", code, r)
		}
		s.st.sim.SetFaults(stripe.Faults{SettleAfter: time.Hour, AnswerLivemode: true})
		quarantined(t, s)
	})
}

// TestHR304_IdempotencyKeyIsTheTransaction: a refund carries
// Idempotency-Key and metadata[pantherclaw_key] pc-<transaction>; the
// agent's retry of the same action refunds nothing more.
func TestHR304_IdempotencyKeyIsTheTransaction(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true})
	act := ids.NewV7()
	code, r := s.stripeRefund(t, act, stripe.FixturePayment, "1500", "usd")
	if code != http.StatusOK {
		t.Fatalf("refund: %d %+v", code, r)
	}
	refunds := s.st.sim.Refunds()
	if len(refunds) != 1 || refunds[0].Key != "pc-"+r.TransactionID || refunds[0].Metadata["pantherclaw_key"] != "pc-"+r.TransactionID {
		t.Fatalf("refunds %+v, want key and metadata pc-%s", refunds, r.TransactionID)
	}
	if code, again := s.stripeRefund(t, act, stripe.FixturePayment, "1500", "usd"); code == http.StatusOK && again.TransactionID != r.TransactionID {
		t.Fatalf("the retry made transaction %s", again.TransactionID)
	}
	if n := len(s.st.sim.Refunds()); n != 1 {
		t.Fatalf("%d refunds after the retry", n)
	}
}

// TestHR305_RefundAboveRemainingIsRefused: what is left on the payment
// bounds the refund, in its currency, whatever the grant says.
func TestHR305_RefundAboveRemainingIsRefused(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true})
	// 50.00 USD paid; 60.00 cannot be refunded.
	code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment2, "6000", "usd")
	if code == http.StatusOK || r.Decision != "CANNOT_AUTHORIZE" || !strings.Contains(strings.Join(r.Reasons, " "), "AMOUNT_NOT_REFUNDABLE") {
		t.Fatalf("over the remaining: %d %+v", code, r)
	}
	code, r = s.stripeRefund(t, ids.NewV7(), stripe.FixturePaymentEUR, "1000", "usd")
	if code == http.StatusOK || r.Decision != "CANNOT_AUTHORIZE" || !strings.Contains(strings.Join(r.Reasons, " "), "CURRENCY_MISMATCH") {
		t.Fatalf("another currency: %d %+v", code, r)
	}
	if s.st.writes.Load() != 0 {
		t.Fatalf("%d writes at Stripe", s.st.writes.Load())
	}
}

// TestHR305_BothOrNeitherPaymentIsRefused: a refund naming both a payment
// intent and a charge, or neither, is refused, never guessed.
func TestHR305_BothOrNeitherPaymentIsRefused(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true})
	for name, form := range map[string]url.Values{
		"both":    {"payment_intent": {stripe.FixturePayment}, "charge": {stripe.FixtureCharge}, "amount": {"1000"}, "currency": {"usd"}},
		"neither": {"amount": {"1000"}, "currency": {"usd"}},
	} {
		if code, _, body := s.stripeCall(t, http.MethodPost, "/v1/refunds", form, ids.NewV7()); code == http.StatusOK {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if n := s.st.sim.Stats().Requests; n != 0 {
		t.Fatalf("Stripe saw %d requests", n)
	}
}

// TestHR305_StaleRefundableFactIsCannotAuthorize: Stripe answers slower
// than the gateway's fact timeout, so there is no fresh refundable fact:
// nothing is decided or sent.
func TestHR305_StaleRefundableFactIsCannotAuthorize(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true})
	s.st.sim.SetFaults(stripe.Faults{Latency: 3 * time.Second})
	code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "1000", "usd")
	if code == http.StatusOK || r.Decision != "CANNOT_AUTHORIZE" || s.st.writes.Load() != 0 {
		t.Fatalf("no fresh fact: %d %+v (writes %d)", code, r, s.st.writes.Load())
	}
}

// TestHR305_LostAnswerIsReconciledNeverRetried: the refund happened but its
// answer was lost: UNKNOWN, never retried, and reconciled from Stripe
// through metadata[pantherclaw_key].
func TestHR305_LostAnswerIsReconciledNeverRetried(t *testing.T) {
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
}

// TestHR306_PayeeChangedRecentlyHoldsTheTransfer: a transfer to a payee
// whose bank details changed within 7 days, or could not be read, is held
// for an approver; to a quiet payee it goes through.
func TestHR306_PayeeChangedRecentlyHoldsTheTransfer(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true})
	// Each transfer is of another amount: a recent success on the same
	// dedupe key would park the next (HR-007).
	amount := 1000
	transfer := func() (int, reply) {
		amount += 100
		form := url.Values{"destination": {stripe.FixturePayee}, "amount": {strconv.Itoa(amount)}, "currency": {"usd"}}
		code, r, _ := s.stripeCall(t, http.MethodPost, "/v1/transfers", form, ids.NewV7())
		return code, r
	}
	if code, r := transfer(); code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("to a quiet payee: %d %+v", code, r)
	}
	s.st.sim.ChangeBank(stripe.FixturePayee, time.Now().Add(-time.Hour))
	if code, r := transfer(); code != http.StatusForbidden || r.Decision != "REQUIRE_APPROVAL" ||
		!strings.Contains(strings.Join(r.Reasons, " "), "PAYEE_CHANGED_RECENTLY") {
		t.Fatalf("to a payee whose bank changed: %d %+v", code, r)
	}
	s.st.sim.SetFaults(stripe.Faults{EventsUnavailable: true})
	if code, r := transfer(); code != http.StatusForbidden || r.Decision != "REQUIRE_APPROVAL" {
		t.Fatalf("with the bank change unreadable: %d %+v", code, r)
	}
	if n := len(s.st.sim.Transfers()); n != 1 {
		t.Fatalf("%d transfers, want only the first", n)
	}
}

// TestT141_LiveKeySwappedIntoTheConnection: an admin who swaps a live key
// into a working test connection stops it: the next refund sends nothing.
func TestT141_LiveKeySwappedIntoTheConnection(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true})
	if code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment, "1000", "usd"); code != http.StatusOK {
		t.Fatalf("with the test key: %d %+v", code, r)
	}
	s.waitConfig(t, s.sealStripeKey(t, stripeLiveKey))
	before := s.st.sim.Stats().Requests
	if code, r := s.stripeRefund(t, ids.NewV7(), stripe.FixturePayment2, "1000", "usd"); code == http.StatusOK {
		t.Fatalf("with the swapped live key: %d %+v", code, r)
	}
	if after := s.st.sim.Stats().Requests; after != before {
		t.Fatalf("Stripe saw %d requests after the swap", after-before)
	}
}

// TestT142_TransferOutsideTheDestinationSetIsDenied: a transfer to a
// connected account the grant does not name is denied with nothing sent.
func TestT142_TransferOutsideTheDestinationSetIsDenied(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true})
	form := url.Values{"destination": {stripe.FixturePayee2}, "amount": {"1000"}, "currency": {"usd"}}
	code, r, _ := s.stripeCall(t, http.MethodPost, "/v1/transfers", form, ids.NewV7())
	if code != http.StatusForbidden || r.Decision != "DENY" || s.st.writes.Load() != 0 {
		t.Fatalf("outside the destination set: %d %+v", code, r)
	}
}

// approveStripe has the approver approve a held Stripe action on its page
// with their security key.
func (s *stack) approveStripe(t *testing.T, b *browser, key *webauthntest.Authenticator, txn string) {
	t.Helper()
	path := "/approvals/" + s.requestOf(t, txn) + "?org=" + s.org.String()
	if code, page := b.page(t, path); code != http.StatusOK || !strings.Contains(page, "stripe.refund.create") {
		t.Fatalf("approval page: %d", code)
	}
	base, _, _ := strings.Cut(path, "?")
	code, body := b.post(t, base+"/approve-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("approve options: %d %v", code, body)
	}
	resp, err := key.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	if code, body = b.post(t, base+"/approve", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)}); code != http.StatusOK ||
		string(body["state"]) != `"APPROVED"` {
		t.Fatalf("approve: %d %v", code, body)
	}
}
