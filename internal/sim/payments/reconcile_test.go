// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package payments

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

type listed struct {
	Data []struct {
		ID             string `json:"id"`
		Charge         string `json:"charge"`
		Amount         string `json:"amount"`
		Currency       string `json:"currency"`
		Status         string `json:"status"`
		IdempotencyKey string `json:"idempotency_key"`
		Created        int64  `json:"created"`
	} `json:"data"`
	HasMore bool `json:"has_more"`
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func list(t *testing.T, url, query string) listed {
	t.Helper()
	code, b := get(t, url+"/v1/refunds?"+query)
	var l listed
	if code != http.StatusOK || json.Unmarshal(b, &l) != nil {
		t.Fatalf("list %s = %d %s", query, code, b)
	}
	return l
}

// TestRefundsKeepTheirIdempotencyKeyAndAreListed: a reconciler finds the
// refund of a transaction by its idempotency key pc-<transaction>, in the
// refunds of its charge or in those created since a time (G0 M7).
func TestRefundsKeepTheirIdempotencyKeyAndAreListed(t *testing.T) {
	now := time.Unix(1_760_097_600, 0)
	s := New(Faults{}, pclog.Discard()).WithClock(func() time.Time { return now })
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	post(t, ts.URL, "pc-txn-0001", okBody)
	now = now.Add(time.Minute)
	post(t, ts.URL, "pc-txn-0002", strings.Replace(okBody, "ch_1", "ch_2", 1))

	l := list(t, ts.URL, "charge=ch_1")
	if len(l.Data) != 1 || l.HasMore || l.Data[0].IdempotencyKey != "pc-txn-0001" || l.Data[0].Amount != "30.00" ||
		l.Data[0].Currency != "USD" || l.Data[0].Status != "succeeded" {
		t.Fatalf("by charge: %+v", l)
	}
	if l := list(t, ts.URL, "created_gte="+strconv.FormatInt(now.Unix(), 10)); len(l.Data) != 1 || l.Data[0].Charge != "ch_2" {
		t.Fatalf("since: %+v", l)
	}
	if l := list(t, ts.URL, "created_gte=0&starting_after="+l.Data[0].ID); len(l.Data) != 1 || l.Data[0].Charge != "ch_2" {
		t.Fatalf("next page: %+v", l)
	}
	code, b := get(t, ts.URL+"/v1/refunds/"+l.Data[0].ID)
	if code != http.StatusOK || !strings.Contains(string(b), `"idempotency_key":"pc-txn-0001"`) {
		t.Fatalf("get = %d %s", code, b)
	}
	for _, q := range []string{
		"", "charge=../x", "created_gte=-1", "created_gte=x", "charge=ch_1&limit=5", "charge=ch_1&charge=ch_2",
		"charge=ch_1&starting_after=../x",
	} {
		if code, _ := get(t, ts.URL+"/v1/refunds?"+q); code != http.StatusBadRequest {
			t.Errorf("query %q = %d, want 400", q, code)
		}
	}
}

func TestListingsArePaged(t *testing.T) {
	s := New(Faults{}, pclog.Discard())
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	for i := range pageSize + 1 {
		post(t, ts.URL, "pc-txn-page-"+strconv.Itoa(i), okBody)
	}
	first := list(t, ts.URL, "charge=ch_1")
	if len(first.Data) != pageSize || !first.HasMore {
		t.Fatalf("first page: %d more=%v", len(first.Data), first.HasMore)
	}
	rest := list(t, ts.URL, "charge=ch_1&starting_after="+first.Data[pageSize-1].ID)
	if len(rest.Data) != 1 || rest.HasMore || rest.Data[0].IdempotencyKey != "pc-txn-page-"+strconv.Itoa(pageSize) {
		t.Fatalf("second page: %+v", rest)
	}
}

// TestSettlementIsPendingFirst: with a settle delay a refund reads pending,
// then succeeded (propagation pending, F483); a replay answers what the
// first answer said.
func TestSettlementIsPendingFirst(t *testing.T) {
	now := time.Unix(1_760_097_600, 0)
	s := New(Faults{SettleAfter: time.Minute}, pclog.Discard()).WithClock(func() time.Time { return now })
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	_, body, _ := post(t, ts.URL, "pc-txn-settle", okBody)
	if !strings.Contains(body, `"status":"pending"`) {
		t.Fatalf("created = %s", body)
	}
	now = now.Add(2 * time.Minute)
	if l := list(t, ts.URL, "charge=ch_1"); l.Data[0].Status != "succeeded" {
		t.Fatalf("settled: %+v", l)
	}
	if _, replay, _ := post(t, ts.URL, "pc-txn-settle", okBody); replay != body {
		t.Fatalf("replay %s, want %s", replay, body)
	}
}

// TestLostResponsesHappenWithoutAnAnswer: the refund is made and its answer
// never arrives (an unknown outcome whose effect happened, S07); a hang
// before the effect makes nothing.
func TestLostResponsesHappenWithoutAnAnswer(t *testing.T) {
	s := New(Faults{LoseRate: 1, HangFor: 50 * time.Millisecond}, pclog.Discard())
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	if code, _, _ := post(t, ts.URL, "pc-txn-lost", okBody); code != 0 {
		t.Fatalf("a lost response answered %d", code)
	}
	if l := list(t, ts.URL, "charge=ch_1"); len(l.Data) != 1 || l.Data[0].IdempotencyKey != "pc-txn-lost" {
		t.Fatalf("the refund was not made: %+v", l)
	}

	h := New(Faults{HangRate: 1, HangFor: 50 * time.Millisecond}, pclog.Discard())
	ts2 := httptest.NewServer(h.Handler())
	defer ts2.Close()
	if code, _, _ := post(t, ts2.URL, "pc-txn-hang", okBody); code != 0 {
		t.Fatalf("a hang answered %d", code)
	}
	if l := list(t, ts2.URL, "charge=ch_1"); len(l.Data) != 0 {
		t.Fatalf("a hang made a refund: %+v", l)
	}
}

// TestShortRefundsDisagreeWithTheRequest: the short fault accepts a refund
// and records it one minor unit short, so a verifier's read disagrees with
// what was asked (G0 M7, a conflicting observation).
func TestShortRefundsDisagreeWithTheRequest(t *testing.T) {
	s := New(Faults{ShortRate: 1}, pclog.Discard())
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	if code, _, _ := post(t, ts.URL, "pc-txn-short", okBody); code != http.StatusOK {
		t.Fatalf("a short refund answered %d", code)
	}
	if l := list(t, ts.URL, "charge=ch_1"); len(l.Data) != 1 || l.Data[0].Amount != "29.99" {
		t.Fatalf("listed %+v, want 29.99", l)
	}
	if got := short(mustMoney(t, "0.01", "USD")); got.Amount.String() != "0.01" {
		t.Fatalf("the smallest refund became %s", got)
	}
	if got := short(mustMoney(t, "3000", "JPY")); got.Amount.String() != "2999" {
		t.Fatalf("a zero-decimal currency: %s", got)
	}
}

func mustMoney(t *testing.T, amount, currency string) money.Money {
	t.Helper()
	m, err := money.ParseMoney(amount, currency)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
