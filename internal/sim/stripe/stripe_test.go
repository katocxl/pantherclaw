// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stripe

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

const key = "rk_test_0123456789abcdefABCDEF"

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harness struct {
	t     *testing.T
	s     *Server
	url   string
	clock *clock
}

func start(t *testing.T, f Faults) *harness {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	s := New(f, pclog.Discard()).WithClock(c.now)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &harness{t: t, s: s, url: ts.URL, clock: c}
}

type answer struct {
	code int
	body map[string]any
	raw  string
	h    http.Header
}

// do sends a request with the test key unless headers name another
// Authorization; a "" Authorization sends none.
func (h *harness) do(method, path string, form url.Values, headers map[string]string) answer {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.url+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Authorization", "Bearer "+key)
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return answer{raw: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	a := answer{code: resp.StatusCode, raw: string(b), h: resp.Header}
	_ = json.Unmarshal(b, &a.body)
	return a
}

func (h *harness) post(path string, form url.Values, idem string) answer {
	h.t.Helper()
	hd := map[string]string{}
	if idem != "" {
		hd["Idempotency-Key"] = idem
	}
	return h.do(http.MethodPost, path, form, hd)
}

func (a answer) errCode() string {
	e, _ := a.body["error"].(map[string]any)
	s, _ := e["code"].(string)
	if s == "" {
		s, _ = e["type"].(string)
	}
	return s
}

func (a answer) str(k string) string { s, _ := a.body[k].(string); return s }
func (a answer) num(k string) int64  { n, _ := a.body[k].(float64); return int64(n) }

func TestHandshake(t *testing.T) {
	h := start(t, Faults{})
	a := h.do(http.MethodGet, handshake.Path+"?nonce=0123456789abcdef0123456789abcdef", nil, map[string]string{"Authorization": ""})
	if a.code != http.StatusOK || a.str("kind") != Kind || a.str("simulator") != handshake.Simulator || a.h.Get("Simulated") != "true" {
		t.Fatalf("handshake = %d %s", a.code, a.raw)
	}
}

// TestKeys: a Stripe test key is required; a live key, a malformed key
// and no key are 401 with Stripe's envelope; the live-mode key answers
// livemode: true.
func TestKeys(t *testing.T) {
	h := start(t, Faults{})
	h.s.WithRequire(Require{LivemodeKey: "sk_live_simulatedLiveKey000000"})
	for name, auth := range map[string]string{
		"none":      "",
		"live":      "Bearer sk_live_0123456789abcdefABCDEF",
		"publish":   "Bearer pk_test_0123456789abcdefABCDEF",
		"short":     "Bearer sk_test_abc",
		"basic":     "Basic " + key,
		"no bearer": key,
	} {
		a := h.do(http.MethodGet, "/v1/charges/"+FixtureCharge, nil, map[string]string{"Authorization": auth})
		if a.code != http.StatusUnauthorized || a.errCode() != "invalid_request_error" {
			t.Errorf("%s: %d %s", name, a.code, a.raw)
		}
	}
	a := h.do(http.MethodGet, "/v1/charges/"+FixtureCharge, nil, nil)
	if a.code != http.StatusOK || a.body["livemode"] != false {
		t.Fatalf("test key read = %d %s", a.code, a.raw)
	}
	a = h.do(http.MethodGet, "/v1/charges/"+FixtureCharge, nil, map[string]string{"Authorization": "Bearer sk_live_simulatedLiveKey000000"})
	if a.code != http.StatusOK || a.body["livemode"] != true {
		t.Fatalf("live-mode key read = %d %s", a.code, a.raw)
	}
	if st := h.s.Stats(); st.Requests != 8 || st.Unauthorized != 6 {
		t.Fatalf("stats = %+v", st)
	}
	// With Keys set, only those keys are accepted.
	h.s.WithRequire(Require{Keys: []string{"sk_test_onlyThisKeyIsAccepted00"}})
	if a := h.do(http.MethodGet, "/v1/balance", nil, nil); a.code != http.StatusUnauthorized {
		t.Fatalf("other test key = %d", a.code)
	}
}

// TestFormStrictness: bodies are form-encoded only; unknown and repeated
// parameters are refused as Stripe refuses them.
func TestFormStrictness(t *testing.T) {
	h := start(t, Faults{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url+"/v1/refunds",
		strings.NewReader(`{"charge":"`+FixtureCharge+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("json body = %d", resp.StatusCode)
	}
	for name, tc := range map[string]struct {
		form url.Values
		code string
	}{
		"unknown":      {url.Values{"charge": {FixtureCharge}, "destination": {"acct_x"}}, "parameter_unknown"},
		"repeated":     {url.Values{"charge": {FixtureCharge}, "amount": {"100", "200"}}, "parameter_invalid"},
		"neither":      {url.Values{"amount": {"100"}}, "parameter_missing"},
		"both":         {url.Values{"charge": {FixtureCharge}, "payment_intent": {FixturePayment}}, "parameter_invalid"},
		"decimal":      {url.Values{"charge": {FixtureCharge}, "amount": {"10.50"}}, "parameter_invalid"},
		"zero":         {url.Values{"charge": {FixtureCharge}, "amount": {"0"}}, "parameter_invalid"},
		"leading zero": {url.Values{"charge": {FixtureCharge}, "amount": {"0100"}}, "parameter_invalid"},
		"reason":       {url.Values{"charge": {FixtureCharge}, "reason": {"other"}}, "parameter_invalid"},
		"no charge":    {url.Values{"charge": {"ch_nope0000"}}, "resource_missing"},
		"nested":       {url.Values{"charge": {FixtureCharge}, "metadata[a][b]": {"x"}}, "parameter_unknown"},
	} {
		if a := h.post("/v1/refunds", tc.form, ""); a.code != http.StatusBadRequest || a.errCode() != tc.code {
			t.Errorf("%s: %d %s", name, a.code, a.raw)
		}
	}
	if len(h.s.Refunds()) != 0 {
		t.Fatal("a refused request refunded")
	}
}

// TestRefunds: by charge or payment intent, partial, defaulting to the
// rest, never more than is left.
func TestRefunds(t *testing.T) {
	h := start(t, Faults{})
	a := h.post("/v1/refunds", url.Values{"payment_intent": {FixturePayment}, "amount": {"5000"}, "reason": {"duplicate"},
		"metadata[order]": {"42"}}, "pc-txn-1")
	if a.code != http.StatusOK || a.str("object") != "refund" || a.str("status") != "succeeded" || a.num("amount") != 5000 ||
		a.str("charge") != FixtureCharge || a.str("currency") != "usd" || a.body["livemode"] != false {
		t.Fatalf("refund = %d %s", a.code, a.raw)
	}
	if !strings.HasPrefix(a.str("id"), "re_") {
		t.Fatalf("refund id %q", a.str("id"))
	}
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge}, "amount": {"10001"}}, "pc-txn-2"); a.errCode() != "amount_too_large" {
		t.Fatalf("over the rest = %d %s", a.code, a.raw)
	}
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge}}, "pc-txn-3"); a.code != http.StatusOK || a.num("amount") != 10000 {
		t.Fatalf("the rest = %d %s", a.code, a.raw)
	}
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge}}, "pc-txn-4"); a.errCode() != "charge_already_refunded" {
		t.Fatalf("again = %d %s", a.code, a.raw)
	}
	ch := h.do(http.MethodGet, "/v1/charges/"+FixtureCharge, nil, nil)
	if ch.num("amount_refunded") != 15000 || ch.body["refunded"] != true {
		t.Fatalf("charge = %s", ch.raw)
	}
	got := h.do(http.MethodGet, "/v1/refunds/"+a.str("id"), nil, nil)
	if got.code != http.StatusOK || got.str("id") != a.str("id") {
		t.Fatalf("get = %d %s", got.code, got.raw)
	}
	if r := h.s.Refunds(); len(r) != 2 || r[0].Key != "pc-txn-1" || r[0].Reason != "duplicate" {
		t.Fatalf("refunds = %+v", r)
	}
	l := h.do(http.MethodGet, "/v1/refunds?charge="+FixtureCharge+"&limit=1", nil, nil)
	data, _ := l.body["data"].([]any)
	if l.code != http.StatusOK || len(data) != 1 || l.body["has_more"] != true {
		t.Fatalf("list = %d %s", l.code, l.raw)
	}
	if a := h.do(http.MethodGet, "/v1/refunds/re_nope", nil, nil); a.code != http.StatusNotFound || a.errCode() != "resource_missing" {
		t.Fatalf("missing = %d %s", a.code, a.raw)
	}
}

// TestIdempotency: the same key and parameters replay the first answer
// byte for byte; other parameters are an idempotency_error.
func TestIdempotency(t *testing.T) {
	h := start(t, Faults{})
	form := url.Values{"charge": {FixtureCharge2}, "amount": {"1000"}, "reason": {"requested_by_customer"}}
	first := h.post("/v1/refunds", form, "pc-0193")
	second := h.post("/v1/refunds", form, "pc-0193")
	if first.code != http.StatusOK || second.raw != first.raw || second.h.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay = %d %s / %s", second.code, second.raw, first.raw)
	}
	other := url.Values{"charge": {FixtureCharge2}, "amount": {"2000"}, "reason": {"requested_by_customer"}}
	if a := h.post("/v1/refunds", other, "pc-0193"); a.code != http.StatusBadRequest || a.errCode() != "idempotency_error" {
		t.Fatalf("reuse = %d %s", a.code, a.raw)
	}
	// The same key on another route is another request too.
	if a := h.post("/v1/transfers", url.Values{"amount": {"1"}, "currency": {"usd"}, "destination": {FixturePayee}}, "pc-0193"); a.errCode() != "idempotency_error" {
		t.Fatalf("cross-route reuse = %d %s", a.code, a.raw)
	}
	st := h.s.Stats()
	if st.Refunds != 1 || st.Replays != 1 || st.IdempotencyErrors != 2 || len(h.s.Refunds()) != 1 {
		t.Fatalf("stats = %+v", st)
	}
	// A refused request is not saved: the key stays free.
	if a := h.post("/v1/refunds", url.Values{"charge": {"ch_nope0000"}}, "pc-0194"); a.code != http.StatusBadRequest {
		t.Fatal(a.raw)
	}
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge2}, "amount": {"500"}}, "pc-0194"); a.code != http.StatusOK {
		t.Fatalf("after a refusal = %d %s", a.code, a.raw)
	}
}

// TestSettlement: pending until SettleAfter, then succeeded, or failed with
// FailAfterPending (the refunded amount is released again).
func TestSettlement(t *testing.T) {
	h := start(t, Faults{SettleAfter: time.Minute})
	a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge2}, "amount": {"1000"}}, "pc-s1")
	if a.str("status") != "pending" {
		t.Fatalf("new = %s", a.raw)
	}
	h.clock.add(2 * time.Minute)
	if g := h.do(http.MethodGet, "/v1/refunds/"+a.str("id"), nil, nil); g.str("status") != "succeeded" {
		t.Fatalf("settled = %s", g.raw)
	}
	h.s.SetFaults(Faults{SettleAfter: time.Minute, FailAfterPending: true})
	b := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge2}, "amount": {"4000"}}, "pc-s2")
	if b.str("status") != "pending" {
		t.Fatalf("new = %s", b.raw)
	}
	if c := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge2}, "amount": {"1"}}, "pc-s3"); c.errCode() != "charge_already_refunded" {
		t.Fatalf("pending counts as refunded: %s", c.raw)
	}
	h.clock.add(2 * time.Minute)
	g := h.do(http.MethodGet, "/v1/refunds/"+b.str("id"), nil, nil)
	if g.str("status") != "failed" || g.str("failure_reason") == "" {
		t.Fatalf("failed = %s", g.raw)
	}
	// The first refund's earlier status is unchanged by the new faults.
	if g := h.do(http.MethodGet, "/v1/refunds/"+a.str("id"), nil, nil); g.str("status") != "succeeded" {
		t.Fatalf("first = %s", g.raw)
	}
	if ch := h.do(http.MethodGet, "/v1/charges/"+FixtureCharge2, nil, nil); ch.num("amount_refunded") != 1000 {
		t.Fatalf("charge = %s", ch.raw)
	}
}

// TestFaults: decline refunds nothing; a lost answer refunds and never
// answers; latency delays.
func TestFaults(t *testing.T) {
	h := start(t, Faults{DeclineRate: 1})
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge}}, "pc-f1"); a.code != http.StatusPaymentRequired || a.errCode() != "card_declined" {
		t.Fatalf("decline = %d %s", a.code, a.raw)
	}
	if len(h.s.Refunds()) != 0 {
		t.Fatal("a declined refund was recorded")
	}
	// A saved 402 replays.
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge}}, "pc-f1"); a.code != http.StatusPaymentRequired || a.h.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("decline replay = %d", a.code)
	}
	h.s.SetFaults(Faults{LoseRate: 1, HangFor: time.Hour})
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge}, "amount": {"100"}}, "pc-f2"); a.code != 0 {
		t.Fatalf("lost answer = %d %s", a.code, a.raw)
	}
	if r := h.s.Refunds(); len(r) != 1 || r[0].Key != "pc-f2" || h.s.Stats().Lost != 1 {
		t.Fatalf("lost refund not recorded: %+v", r)
	}
	// A short hang drops the connection rather than answering empty.
	h.s.SetFaults(Faults{LoseRate: 1, HangFor: 20 * time.Millisecond})
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge}, "amount": {"100"}}, "pc-f3"); a.code != 0 {
		t.Fatalf("dropped = %d", a.code)
	}
	// The retry with the same key replays the effect that happened.
	h.s.SetFaults(Faults{})
	if a := h.post("/v1/refunds", url.Values{"charge": {FixtureCharge}, "amount": {"100"}}, "pc-f2"); a.code != http.StatusOK || a.h.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("retry after loss = %d %s", a.code, a.raw)
	}
	h.s.SetFaults(Faults{Latency: 50 * time.Millisecond})
	t0 := time.Now()
	h.do(http.MethodGet, "/v1/balance", nil, nil)
	if time.Since(t0) < 50*time.Millisecond {
		t.Fatal("no latency")
	}
	if chance(0) || !chance(1) {
		t.Fatal("chance bounds")
	}
}

// TestPaymentIntents: off-session confirm charges at once (processing
// while settling), the declined test card is 402 with the intent left in
// requires_payment_method, latest_charge expands, and only an uncharged
// intent cancels.
func TestPaymentIntents(t *testing.T) {
	h := start(t, Faults{SettleAfter: time.Minute})
	form := url.Values{"amount": {"2500"}, "currency": {"usd"}, "customer": {FixtureCustomer}, "payment_method": {FixturePaymentMethod},
		"confirm": {"true"}, "off_session": {"true"}, "payment_method_types[]": {"card"}}
	a := h.post("/v1/payment_intents", form, "pc-p1")
	if a.code != http.StatusOK || a.str("status") != "processing" || a.str("object") != "payment_intent" || a.str("latest_charge") == "" {
		t.Fatalf("create = %d %s", a.code, a.raw)
	}
	h.clock.add(2 * time.Minute)
	g := h.do(http.MethodGet, "/v1/payment_intents/"+a.str("id")+"?expand[]=latest_charge", nil, nil)
	lc, _ := g.body["latest_charge"].(map[string]any)
	if g.str("status") != "succeeded" || g.num("amount_received") != 2500 || lc["object"] != "charge" {
		t.Fatalf("settled = %s", g.raw)
	}
	if c := h.post("/v1/payment_intents/"+a.str("id")+"/cancel", url.Values{}, "pc-p2"); c.errCode() != "payment_intent_unexpected_state" {
		t.Fatalf("cancel succeeded = %s", c.raw)
	}
	declined := url.Values{"amount": {"2500"}, "currency": {"usd"}, "customer": {FixtureCustomer}, "payment_method": {TestCardDeclined},
		"confirm": {"true"}, "off_session": {"true"}}
	d := h.post("/v1/payment_intents", declined, "pc-p3")
	e, _ := d.body["error"].(map[string]any)
	pi, _ := e["payment_intent"].(map[string]any)
	if d.code != http.StatusPaymentRequired || d.errCode() != "card_declined" || pi["status"] != "requires_payment_method" {
		t.Fatalf("declined = %d %s", d.code, d.raw)
	}
	if c := h.post("/v1/payment_intents/"+pi["id"].(string)+"/cancel", url.Values{"cancellation_reason": {"abandoned"}}, "pc-p4"); c.str("status") != "canceled" || c.str("cancellation_reason") != "abandoned" {
		t.Fatalf("cancel = %s", c.raw)
	}
	unconfirmed := h.post("/v1/payment_intents", url.Values{"amount": {"700"}, "currency": {"eur"}, "customer": {FixtureCustomer}}, "pc-p5")
	if unconfirmed.str("status") != "requires_confirmation" {
		t.Fatalf("unconfirmed = %s", unconfirmed.raw)
	}
	if c := h.post("/v1/payment_intents/"+unconfirmed.str("id")+"/confirm", url.Values{"payment_method": {TestCardVisa}}, "pc-p6"); c.str("status") != "processing" {
		t.Fatalf("confirm = %s", c.raw)
	}
	for name, f := range map[string]url.Values{
		"other method":  {"amount": {"1"}, "currency": {"usd"}, "customer": {FixtureCustomer}, "payment_method": {"pm_someoneElse"}, "confirm": {"true"}},
		"no customer":   {"amount": {"1"}, "currency": {"usd"}, "customer": {"cus_nope0000"}},
		"currency":      {"amount": {"1"}, "currency": {"xyz"}, "customer": {FixtureCustomer}},
		"long currency": {"amount": {"1"}, "currency": {"usdd"}, "customer": {FixtureCustomer}},
		"off session":   {"amount": {"1"}, "currency": {"usd"}, "customer": {FixtureCustomer}, "off_session": {"true"}},
		"types":         {"amount": {"1"}, "currency": {"usd"}, "customer": {FixtureCustomer}, "payment_method_types[]": {"sepa_debit"}},
	} {
		if a := h.post("/v1/payment_intents", f, ""); a.code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, a.code, a.raw)
		}
	}
	if p := h.s.PaymentIntents(); len(p) != 3 || p[0].Key != "pc-p1" || p[0].Status != "succeeded" {
		t.Fatalf("intents = %+v", p)
	}
}

// TestTransfers: to a connected account, from the available balance.
func TestTransfers(t *testing.T) {
	h := start(t, Faults{})
	a := h.post("/v1/transfers", url.Values{"amount": {"12345"}, "currency": {"usd"}, "destination": {FixturePayee},
		"transfer_group": {"order_42"}, "description": {"Invoice 42"}}, "pc-t1")
	if a.code != http.StatusOK || a.str("object") != "transfer" || a.str("destination") != FixturePayee || a.body["reversed"] != false ||
		a.num("amount") != 12345 {
		t.Fatalf("transfer = %d %s", a.code, a.raw)
	}
	if g := h.do(http.MethodGet, "/v1/transfers/"+a.str("id"), nil, nil); g.str("id") != a.str("id") {
		t.Fatalf("get = %s", g.raw)
	}
	b := h.do(http.MethodGet, "/v1/balance", nil, nil)
	avail, _ := b.body["available"].([]any)
	usd, _ := avail[0].(map[string]any)
	if usd["amount"] != float64(startBalance-12345) {
		t.Fatalf("balance = %s", b.raw)
	}
	if a := h.post("/v1/transfers", url.Values{"amount": {"99999999"}, "currency": {"usd"}, "destination": {FixturePayee}}, ""); a.errCode() != "balance_insufficient" {
		t.Fatalf("overdraft = %s", a.raw)
	}
	if a := h.post("/v1/transfers", url.Values{"amount": {"1"}, "currency": {"usd"}, "destination": {"acct_SimUnknown01"}}, ""); a.errCode() != "resource_missing" {
		t.Fatalf("unknown destination = %s", a.raw)
	}
	if a := h.do(http.MethodGet, "/v1/accounts/"+FixturePayee, nil, nil); a.str("object") != "account" || a.body["livemode"] != false {
		t.Fatalf("account = %s", a.raw)
	}
	if a := h.do(http.MethodGet, "/v1/account", nil, nil); a.str("id") != FixturePlatform {
		t.Fatalf("platform = %s", a.raw)
	}
	if tr := h.s.Transfers(); len(tr) != 1 || tr[0].Key != "pc-t1" {
		t.Fatalf("transfers = %+v", tr)
	}
}

// TestBankChangeEvents: the connected account's events (Stripe-Account)
// show account.external_account.* changes; the fault adds one a day ago;
// created[gte] bounds the window; Stripe-Account is refused elsewhere.
func TestBankChangeEvents(t *testing.T) {
	h := start(t, Faults{})
	week := strconv.FormatInt(h.clock.now().Add(-7*24*time.Hour).Unix(), 10)
	q := "/v1/events?type=account.external_account.*&created[gte]=" + week
	events := func(acct string) []any {
		a := h.do(http.MethodGet, q, nil, map[string]string{"Stripe-Account": acct})
		if a.code != http.StatusOK {
			t.Fatalf("events = %d %s", a.code, a.raw)
		}
		d, _ := a.body["data"].([]any)
		return d
	}
	if n := len(events(FixturePayee)); n != 0 {
		t.Fatalf("quiet account has %d events", n)
	}
	h.s.ChangeBank(FixturePayee, h.clock.now().Add(-10*24*time.Hour))
	if n := len(events(FixturePayee)); n != 0 {
		t.Fatalf("a change 10 days ago is inside the window (%d)", n)
	}
	h.s.ChangeBank(FixturePayee, h.clock.now().Add(-2*time.Hour))
	d := events(FixturePayee)
	if len(d) != 1 {
		t.Fatalf("recent change: %d events", len(d))
	}
	ev, _ := d[0].(map[string]any)
	if ev["type"] != "account.external_account.updated" || ev["account"] != FixturePayee || ev["livemode"] != false {
		t.Fatalf("event = %v", ev)
	}
	if n := len(events(FixturePayee2)); n != 0 {
		t.Fatalf("other account has %d events", n)
	}
	h.s.SetFaults(Faults{BankChangedRecently: true})
	if n := len(events(FixturePayee2)); n != 1 {
		t.Fatalf("fault: %d events", n)
	}
	if a := h.do(http.MethodGet, "/v1/events?types[]=charge.refunded", nil, map[string]string{"Stripe-Account": FixturePayee2}); len(a.body["data"].([]any)) != 0 {
		t.Fatalf("types filter = %s", a.raw)
	}
	if a := h.do(http.MethodGet, "/v1/events", nil, nil); a.code != http.StatusOK || len(a.body["data"].([]any)) != 0 {
		t.Fatalf("platform events = %s", a.raw)
	}
	if a := h.do(http.MethodGet, "/v1/events", nil, map[string]string{"Stripe-Account": "acct_SimUnknown01"}); a.code != http.StatusForbidden {
		t.Fatalf("unknown account = %d", a.code)
	}
	if a := h.do(http.MethodGet, "/v1/balance", nil, map[string]string{"Stripe-Account": FixturePayee}); a.code != http.StatusBadRequest {
		t.Fatalf("Stripe-Account on balance = %d", a.code)
	}
}

func TestStatsRoute(t *testing.T) {
	h := start(t, Faults{})
	h.do(http.MethodGet, "/v1/balance", nil, map[string]string{"Authorization": ""})
	a := h.do(http.MethodGet, "/__sim/stats", nil, map[string]string{"Authorization": ""})
	if a.code != http.StatusOK || a.num("requests") != 1 || a.num("unauthorized") != 1 {
		t.Fatalf("stats = %d %s", a.code, a.raw)
	}
}
