// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stripe

import (
	"context"
	"maps"
	"slices"
	"time"
)

// The fixtures every simulator starts with (dev seed, e2e and range tests
// address them by these ids).
const (
	FixturePlatform = "acct_SimPlatform0001"
	FixtureCustomer = "cus_SimCustomer0001"
	// FixturePaymentMethod is attached to FixtureCustomer.
	FixturePaymentMethod = "pm_SimVisa0001"
	// FixturePayment (150.00 USD), FixturePayment2 (50.00 USD) and
	// FixturePaymentEUR (200.00 EUR) are succeeded payment intents of
	// FixtureCustomer, each with one charge (FixtureCharge…).
	FixturePayment    = "pi_SimPayment0001"
	FixtureCharge     = "ch_SimCharge0001"
	FixturePayment2   = "pi_SimPayment0002"
	FixtureCharge2    = "ch_SimCharge0002"
	FixturePaymentEUR = "pi_SimPayment0003"
	FixtureChargeEUR  = "ch_SimCharge0003"
	// FixturePayee and FixturePayee2 are connected accounts (transfer
	// destinations).
	FixturePayee  = "acct_SimPayee0001"
	FixturePayee2 = "acct_SimPayee0002"
)

// Stripe's test payment methods the simulator understands besides the
// fixture: one that succeeds and one that is declined.
const (
	TestCardVisa     = "pm_card_visa"
	TestCardDeclined = "pm_card_chargeDeclined"
)

// startBalance is the platform's opening available balance per currency,
// in minor units.
const startBalance = 100_000_000

type customer struct {
	id      string
	methods []string
}

type charge struct {
	id, intent, customer, currency string
	amount                         int64
	created                        time.Time
}

type paymentIntent struct {
	id, customer, method, currency, key string
	amount                              int64
	created                             time.Time
	metadata                            map[string]string
	// confirmed is when it was confirmed (zero: requires_confirmation);
	// declined and canceled are terminal.
	confirmed time.Time
	declined  bool
	canceled  string // cancellation reason, or "" when not canceled
	charge    string // the charge a successful confirmation created
	settle    time.Duration
}

type refund struct {
	id, charge, intent, currency, reason, key string
	amount                                    int64
	created                                   time.Time
	metadata                                  map[string]string
	settle                                    time.Duration
	fail                                      bool
}

type transfer struct {
	id, destination, currency, group, description, key string
	amount                                             int64
	created                                            time.Time
	metadata                                           map[string]string
}

type account struct {
	id string
	// bankChanges are when an external (bank) account was added or
	// changed: account.external_account.* events.
	bankChanges []bankChange
}

type bankChange struct {
	event, kind string
	at          time.Time
}

// seed records the fixtures.
func (s *Server) seed() {
	// A fixed past time, before any clock a test sets: the fixtures are
	// settled payments whatever the date.
	at := fixtureTime
	s.customers[FixtureCustomer] = &customer{id: FixtureCustomer, methods: []string{FixturePaymentMethod}}
	for _, p := range []struct {
		intent, charge, currency string
		amount                   int64
	}{
		{FixturePayment, FixtureCharge, "usd", 15000},
		{FixturePayment2, FixtureCharge2, "usd", 5000},
		{FixturePaymentEUR, FixtureChargeEUR, "eur", 20000},
	} {
		s.intents[p.intent] = &paymentIntent{
			id: p.intent, customer: FixtureCustomer, method: FixturePaymentMethod,
			currency: p.currency, amount: p.amount, created: at, confirmed: at, charge: p.charge,
		}
		s.charges[p.charge] = &charge{id: p.charge, intent: p.intent, customer: FixtureCustomer, currency: p.currency, amount: p.amount, created: at}
	}
	for _, id := range []string{FixturePayee, FixturePayee2} {
		s.accounts[id] = &account{id: id}
	}
}

// AddPayment records a succeeded payment of amount (minor units) in
// currency by FixtureCustomer and returns its payment intent and charge.
func (s *Server) AddPayment(amount int64, currency string) (intentID, chargeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	intentID, chargeID = newID("pi_"), newID("ch_")
	s.intents[intentID] = &paymentIntent{
		id: intentID, customer: FixtureCustomer, method: FixturePaymentMethod,
		currency: currency, amount: amount, created: now, confirmed: now, charge: chargeID,
	}
	s.charges[chargeID] = &charge{id: chargeID, intent: intentID, customer: FixtureCustomer, currency: currency, amount: amount, created: now}
	return intentID, chargeID
}

// AddAccount records a connected account.
func (s *Server) AddAccount(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accounts[id] == nil {
		s.accounts[id] = &account{id: id}
	}
}

// ChangeBank records that a connected account's external (bank) account
// was updated at at (an account.external_account.updated event).
func (s *Server) ChangeBank(id string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[id]
	if a == nil {
		a = &account{id: id}
		s.accounts[id] = a
	}
	a.bankChanges = append(a.bankChanges, bankChange{event: newID("evt_"), kind: "account.external_account.updated", at: at})
}

// Refund is a recorded refund as tests see it.
type Refund struct {
	ID, Charge, PaymentIntent, Currency, Reason string
	Amount                                      int64
	// Key is the idempotency key it was created with (pc-<transaction>).
	Key string
	// Metadata is the metadata it was created with.
	Metadata map[string]string
	Created  time.Time
	Status   string
}

// PaymentIntent is a payment intent created through the API as tests see it.
type PaymentIntent struct {
	ID, Customer, PaymentMethod, Currency, Key, Status string
	Amount                                             int64
}

// Transfer is a recorded transfer as tests see it.
type Transfer struct {
	ID, Destination, Currency, Key string
	Amount                         int64
}

// Refunds returns the refunds created through the API, in creation order.
func (s *Server) Refunds() []Refund {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []Refund
	for _, id := range s.order {
		if r, ok := s.refunds[id]; ok {
			out = append(out, Refund{
				ID: r.id, Charge: r.charge, PaymentIntent: r.intent, Currency: r.currency, Reason: r.reason,
				Amount: r.amount, Key: r.key, Created: r.created, Status: r.status(now), Metadata: meta(r.metadata),
			})
		}
	}
	return out
}

// PaymentIntents returns the payment intents created through the API, in
// creation order.
func (s *Server) PaymentIntents() []PaymentIntent {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []PaymentIntent
	for _, id := range s.order {
		if p, ok := s.intents[id]; ok {
			out = append(out, PaymentIntent{
				ID: p.id, Customer: p.customer, PaymentMethod: p.method, Currency: p.currency,
				Key: p.key, Status: p.status(now), Amount: p.amount,
			})
		}
	}
	return out
}

// Transfers returns the transfers, in creation order.
func (s *Server) Transfers() []Transfer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Transfer
	for _, id := range s.order {
		if t, ok := s.transfers[id]; ok {
			out = append(out, Transfer{ID: t.id, Destination: t.destination, Currency: t.currency, Key: t.key, Amount: t.amount})
		}
	}
	return out
}

// status is the refund's status at now: pending until it settles, then
// succeeded, or failed with FailAfterPending.
func (r *refund) status(now time.Time) string {
	switch {
	case now.Before(r.created.Add(r.settle)):
		return "pending"
	case r.fail:
		return "failed"
	}
	return "succeeded"
}

// status is the payment intent's status at now.
func (p *paymentIntent) status(now time.Time) string {
	switch {
	case p.canceled != "":
		return "canceled"
	case p.declined:
		return "requires_payment_method"
	case p.confirmed.IsZero():
		return "requires_confirmation"
	case now.Before(p.confirmed.Add(p.settle)):
		return "processing"
	}
	return "succeeded"
}

// refunded is what is refunded of a charge at now: every refund that has
// not failed or been canceled, pending ones included (Stripe counts them).
func (s *Server) refunded(chargeID string, now time.Time) int64 {
	var n int64
	for _, r := range s.refunds {
		if r.charge == chargeID && r.status(now) != "failed" {
			n += r.amount
		}
	}
	return n
}

// available is the platform's available balance in currency at now: the
// opening balance plus succeeded payments made through the API, less
// refunds that have not failed and transfers.
func (s *Server) available(currency string, now time.Time) int64 {
	n := int64(startBalance)
	for _, id := range s.order {
		switch {
		case s.intents[id] != nil:
			if p := s.intents[id]; p.currency == currency && p.status(now) == "succeeded" {
				n += p.amount
			}
		case s.refunds[id] != nil:
			if r := s.refunds[id]; r.currency == currency && r.status(now) != "failed" {
				n -= r.amount
			}
		case s.transfers[id] != nil:
			if t := s.transfers[id]; t.currency == currency {
				n -= t.amount
			}
		}
	}
	return n
}

// Rendering. Field order and names follow Stripe's objects; fields the
// pc.stripe package never reads are left out, and every object carries
// "livemode" (false, or true for the live-mode key).

func meta(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return maps.Clone(m)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Server) renderRefund(r *refund, c call) map[string]any {
	st := r.status(c.now)
	out := map[string]any{
		"id": r.id, "object": "refund", "amount": r.amount, "charge": r.charge, "created": r.created.Unix(),
		"currency": r.currency, "metadata": meta(r.metadata), "payment_intent": nullable(r.intent), "reason": nullable(r.reason),
		"status": st, "livemode": c.live, "failure_reason": nil,
	}
	if st == "failed" {
		out["failure_reason"] = "declined"
	}
	return out
}

func (s *Server) renderCharge(ch *charge, c call) map[string]any {
	refunded := s.refunded(ch.id, c.now)
	return map[string]any{
		"id": ch.id, "object": "charge", "amount": ch.amount, "amount_captured": ch.amount, "amount_refunded": refunded,
		"captured": true, "created": ch.created.Unix(), "currency": ch.currency, "customer": ch.customer, "livemode": c.live,
		"paid": true, "payment_intent": ch.intent, "refunded": refunded >= ch.amount, "status": "succeeded",
		"billing_details": map[string]any{"email": "customer@example.test", "name": "Simulated Customer"},
		"receipt_email":   "customer@example.test",
	}
}

func (s *Server) renderIntent(p *paymentIntent, c call, expand []string) map[string]any {
	st := p.status(c.now)
	latest := nullable(p.charge)
	if ch := s.charges[p.charge]; ch != nil && slices.Contains(expand, "latest_charge") {
		latest = s.renderCharge(ch, c)
	}
	received := int64(0)
	if st == "succeeded" {
		received = p.amount
	}
	return map[string]any{
		"id": p.id, "object": "payment_intent", "amount": p.amount, "amount_received": received,
		"cancellation_reason": nullable(p.canceled), "created": p.created.Unix(), "currency": p.currency,
		"customer": p.customer, "latest_charge": latest, "livemode": c.live, "metadata": meta(p.metadata),
		"payment_method": p.method, "payment_method_types": []string{"card"}, "status": st,
	}
}

func (s *Server) renderTransfer(t *transfer, c call) map[string]any {
	return map[string]any{
		"id": t.id, "object": "transfer", "amount": t.amount, "amount_reversed": 0, "created": t.created.Unix(),
		"currency": t.currency, "description": nullable(t.description), "destination": t.destination, "livemode": c.live,
		"metadata": meta(t.metadata), "reversals": map[string]any{"object": "list", "data": []any{}, "has_more": false},
		"reversed": false, "transfer_group": nullable(t.group),
	}
}

func renderAccount(id string, c call) map[string]any {
	return map[string]any{
		"id": id, "object": "account", "charges_enabled": true, "payouts_enabled": true, "country": "US",
		"default_currency": "usd", "type": "custom", "livemode": c.live,
	}
}

func renderEvent(acct string, b bankChange, c call) map[string]any {
	return map[string]any{
		"id": b.event, "object": "event", "account": acct, "api_version": APIVersion, "created": b.at.Unix(),
		"data": map[string]any{"object": map[string]any{
			"id": "ba_" + b.event[len("evt_"):], "object": "bank_account", "account": acct, "country": "US",
			"currency": "usd", "last4": "6789", "status": "new",
		}},
		"livemode": c.live, "pending_webhooks": 0, "request": map[string]any{"id": nil, "idempotency_key": nil}, "type": b.kind,
	}
}

// APIVersion is the Stripe API version the simulator speaks (pc.stripe
// pins the same version in its Stripe-Version header).
const APIVersion = "2026-09-30.endive"

type callKey struct{}

func withCall(ctx context.Context, apiKey string, live bool) context.Context {
	return context.WithValue(ctx, callKey{}, call{live: live, apiKey: apiKey})
}

func callOf(r interface{ Context() context.Context }) call {
	c, _ := r.Context().Value(callKey{}).(call)
	return c
}

// fixtureTime is when the fixtures' payments were made.
var fixtureTime = time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
