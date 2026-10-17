// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stripefacts_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/stripefacts"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/stripe"
)

var (
	testKey = stripe.FakeKey("rk", "test", "0123456789abcdefABCDEF")
	liveKey = stripe.FakeKey("sk", "live", "simulatedLiveKey000000")
)

// getter reads the simulator with key, as the gateway's getter does.
func getter(base, key string) stripefacts.Getter {
	return func(ctx context.Context, path, account string) (egress.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return egress.Response{}, err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Stripe-Version", stripefacts.APIVersion)
		if account != "" {
			req.Header.Set("Stripe-Account", account)
		}
		res, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
		if err != nil {
			return egress.Response{}, err
		}
		defer func() { _ = res.Body.Close() }()
		b, err := io.ReadAll(res.Body)
		return egress.Response{Status: res.StatusCode, Body: b}, err
	}
}

func sim(t *testing.T) (*stripe.Server, string) {
	t.Helper()
	s := stripe.New(stripe.Faults{}, pclog.Discard()).WithRequire(stripe.Require{LivemodeKey: liveKey})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts.URL
}

func refund(t *testing.T, base, charge, amount string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/v1/refunds",
		strings.NewReader(url.Values{"charge": {charge}, "amount": {amount}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+testKey)
	res, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("refund: %v %v", res, err)
	}
	_ = res.Body.Close()
}

func one(t *testing.T, get stripefacts.Getter, target, name string) (map[string]any, string, bool) {
	t.Helper()
	read, unread, live := stripefacts.ReadAll(context.Background(), get, target, []string{name}, time.Now())
	if len(read) == 1 {
		return read[0].Value, "", live
	}
	return nil, unread[name], live
}

func remaining(v map[string]any) string {
	m, _ := v["remaining"].(map[string]any)
	s, _ := m["value"].(string)
	c, _ := m["currency"].(string)
	return s + " " + c
}

// TestRefundable: what is left on a payment, in ActionIR's money shape,
// whether named by its PaymentIntent or its charge.
func TestRefundable(t *testing.T) {
	_, base := sim(t)
	get := getter(base, testKey)
	v, why, _ := one(t, get, stripe.FixturePayment, stripefacts.Refundable)
	if remaining(v) != "150.00 USD" || v["payment"] != stripe.FixtureCharge || v["livemode"] != false {
		t.Fatalf("by intent = %v (%s)", v, why)
	}
	refund(t, base, stripe.FixtureCharge, "2550")
	if v, _, _ := one(t, get, stripe.FixtureCharge, stripefacts.Refundable); remaining(v) != "124.50 USD" {
		t.Fatalf("by charge after a refund = %v", v)
	}
	if v, _, _ := one(t, get, stripe.FixturePaymentEUR, stripefacts.Refundable); remaining(v) != "200.00 EUR" {
		t.Fatalf("eur = %v", v)
	}
	for name, target := range map[string]string{
		"missing": "pi_SimNoSuchPayment", "account": stripe.FixturePayee, "malformed": "pi_x",
	} {
		if v, why, _ := one(t, get, target, stripefacts.Refundable); v != nil || !strings.HasPrefix(why, "not read: ") {
			t.Errorf("%s: %v %q", name, v, why)
		}
	}
	if v, why, _ := one(t, getter(base, "rk_wrong"), stripe.FixturePayment, stripefacts.Refundable); v != nil || !strings.Contains(why, "401") {
		t.Errorf("bad key: %v %q", v, why)
	}
}

// TestRefundableLivemode (HR-303, D54): a live-mode answer is never a fact,
// and is reported.
func TestRefundableLivemode(t *testing.T) {
	s, base := sim(t)
	v, why, live := one(t, getter(base, liveKey), stripe.FixturePayment, stripefacts.Refundable)
	if v != nil || !live || !strings.Contains(why, "live mode") {
		t.Fatalf("live = %v %q %v", v, why, live)
	}
	s.ChangeBank(stripe.FixturePayee, time.Now().Add(-time.Hour))
	_, _, live = one(t, getter(base, liveKey), stripe.FixturePayee, stripefacts.PayoutDetailsChanged)
	if !live {
		t.Fatal("live events not reported")
	}
}

// TestPayoutDetailsChanged: an external-account event within 7 days is a
// change; an older one is not.
func TestPayoutDetailsChanged(t *testing.T) {
	s, base := sim(t)
	get := getter(base, testKey)
	if v, why, _ := one(t, get, stripe.FixturePayee, stripefacts.PayoutDetailsChanged); v["changed"] != false || v["last_changed"] != int64(0) {
		t.Fatalf("quiet = %v (%s)", v, why)
	}
	s.ChangeBank(stripe.FixturePayee, time.Now().Add(-8*24*time.Hour))
	if v, _, _ := one(t, get, stripe.FixturePayee, stripefacts.PayoutDetailsChanged); v["changed"] != false {
		t.Fatalf("old change = %v", v)
	}
	at := time.Now().Add(-time.Hour)
	s.ChangeBank(stripe.FixturePayee, at)
	v, _, _ := one(t, get, stripe.FixturePayee, stripefacts.PayoutDetailsChanged)
	if v["changed"] != true || v["last_changed"] != at.Unix() || v["account"] != stripe.FixturePayee {
		t.Fatalf("recent change = %v", v)
	}
	if v, _, _ := one(t, get, stripe.FixturePayee2, stripefacts.PayoutDetailsChanged); v["changed"] != false {
		t.Fatalf("other account = %v", v)
	}
	if v, why, _ := one(t, get, "acct_SimUnknown0001", stripefacts.PayoutDetailsChanged); v != nil || why == "" {
		t.Fatalf("unknown account = %v", v)
	}
	if v, _, _ := one(t, get, stripe.FixturePayment, stripefacts.PayoutDetailsChanged); v != nil {
		t.Fatalf("not an account = %v", v)
	}
}

func TestUnknownFact(t *testing.T) {
	_, base := sim(t)
	if v, why, _ := one(t, getter(base, testKey), stripe.FixturePayment, "stripe.other"); v != nil || why == "" {
		t.Fatal(v)
	}
	if got := stripefacts.UnreadFact("x"); got["unread"] != "x" || len(got) != 1 {
		t.Fatal(got)
	}
}
