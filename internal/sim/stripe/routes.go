// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stripe

import (
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	accountID = regexp.MustCompile(`^acct_[A-Za-z0-9]{8,64}$`)
	groupID   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reasons   = []string{"duplicate", "fraudulent", "requested_by_customer"}
)

// get answers a GET whose only parameters are allowed, rendering under the
// lock.
func (s *Server) get(w http.ResponseWriter, r *http.Request, allowed []string, render func(c call, f *form) (int, any)) {
	f, perr := queryForm(r, allowed)
	if perr != nil {
		perr.write(w)
		return
	}
	c := callOf(r)
	s.mu.Lock()
	c.now = s.now()
	status, v := render(c, f)
	s.mu.Unlock()
	if e, ok := v.(*apiError); ok {
		e.write(w)
		return
	}
	writeJSON(w, status, v)
}

// createRefund refunds part or all of a charge, named by the charge or by
// its payment intent (POST /v1/refunds). The amount defaults to what is
// left to refund; more than that is amount_too_large.
func (s *Server) createRefund(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, "refunds", []string{"charge", "payment_intent", "amount", "reason", "metadata", "expand[]"},
		func(c call, f *form) (int, any) {
			chID, piID := f.get("charge"), f.get("payment_intent")
			if (chID == "") == (piID == "") {
				if chID == "" {
					return http.StatusBadRequest, missing("charge")
				}
				return http.StatusBadRequest, invalid("payment_intent", "You cannot pass both charge and payment_intent.")
			}
			if piID != "" {
				p := s.intents[piID]
				if p == nil {
					return http.StatusBadRequest, noSuch("payment_intent", "payment_intent", piID)
				}
				if p.status(c.now) != "succeeded" || p.charge == "" {
					return http.StatusBadRequest, &apiError{
						status: http.StatusBadRequest, Type: "invalid_request_error",
						Code: "payment_intent_unexpected_state", Param: "payment_intent",
						Message: "This PaymentIntent does not have a successful charge to refund.",
					}
				}
				chID = p.charge
			}
			ch := s.charges[chID]
			if ch == nil {
				return http.StatusBadRequest, noSuch("charge", "charge", chID)
			}
			left := ch.amount - s.refunded(ch.id, c.now)
			if left <= 0 {
				return http.StatusBadRequest, &apiError{
					status: http.StatusBadRequest, Type: "invalid_request_error",
					Code: "charge_already_refunded", Message: "Charge " + ch.id + " has already been refunded.",
				}
			}
			amount, given, perr := f.amount("amount", false)
			if perr != nil {
				return perr.status, perr
			}
			if !given {
				amount = left
			}
			if amount > left {
				return http.StatusBadRequest, &apiError{
					status: http.StatusBadRequest, Type: "invalid_request_error",
					Code: "amount_too_large", Param: "amount",
					Message: "Refund amount (" + strconv.FormatInt(amount, 10) + ") is greater than unrefunded amount on charge (" +
						strconv.FormatInt(left, 10) + ")",
				}
			}
			reason := f.get("reason")
			if reason != "" && !slices.Contains(reasons, reason) {
				return http.StatusBadRequest, invalid("reason", "Invalid reason: must be one of duplicate, fraudulent or requested_by_customer")
			}
			if chance(s.faults.DeclineRate) {
				s.stats.Declines++
				return http.StatusPaymentRequired, &apiError{
					status: http.StatusPaymentRequired, Type: "card_error",
					Code: "card_declined", Decline: "generic_decline", Message: "Your card was declined.",
				}
			}
			ref := &refund{
				id: newID("re_"), charge: ch.id, intent: ch.intent, currency: ch.currency, reason: reason,
				key: r.Header.Get("Idempotency-Key"), amount: amount, created: c.now, metadata: f.metadata,
				settle: s.faults.SettleAfter, fail: s.faults.FailAfterPending,
			}
			s.refunds[ref.id] = ref
			s.order = append(s.order, ref.id)
			s.stats.Refunds++
			return http.StatusOK, s.renderRefund(ref, c)
		})
}

func (s *Server) getRefund(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"expand[]"}, func(c call, _ *form) (int, any) {
		ref := s.refunds[r.PathValue("id")]
		if ref == nil {
			return http.StatusNotFound, noSuch("refund", "", r.PathValue("id"))
		}
		return http.StatusOK, s.renderRefund(ref, c)
	})
}

// listRefunds lists refunds newest first, of one charge or payment intent,
// created at or after created[gte], continuing after starting_after.
func (s *Server) listRefunds(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"charge", "payment_intent", "created[gte]", "limit", "starting_after"}, func(c call, f *form) (int, any) {
		limit, since, perr := listParams(f)
		if perr != nil {
			return perr.status, perr
		}
		var items []*refund
		for _, id := range slices.Backward(s.order) {
			if ref := s.refunds[id]; ref != nil &&
				(f.get("charge") == "" || ref.charge == f.get("charge")) &&
				(f.get("payment_intent") == "" || ref.intent == f.get("payment_intent")) &&
				ref.created.Unix() >= since {
				items = append(items, ref)
			}
		}
		page, more, perr := pageAfter(items, f.get("starting_after"), limit, func(r *refund) string { return r.id })
		if perr != nil {
			return perr.status, perr
		}
		data := make([]any, len(page))
		for i, ref := range page {
			data[i] = s.renderRefund(ref, c)
		}
		return http.StatusOK, list("/v1/refunds", data, more)
	})
}

func (s *Server) getCharge(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"expand[]"}, func(c call, _ *form) (int, any) {
		ch := s.charges[r.PathValue("id")]
		if ch == nil {
			return http.StatusNotFound, noSuch("charge", "", r.PathValue("id"))
		}
		return http.StatusOK, s.renderCharge(ch, c)
	})
}

// createIntent creates a payment intent for a customer, and with
// confirm=true charges its payment method at once (POST
// /v1/payment_intents). TestCardDeclined, or a decline fault, leaves it in
// requires_payment_method and answers 402 card_declined with the intent.
func (s *Server) createIntent(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, "payment_intents", []string{
		"amount", "currency", "customer", "payment_method", "confirm", "off_session", "payment_method_types[]",
		"description", "metadata", "expand[]",
	}, func(c call, f *form) (int, any) {
		amount, _, perr := f.amount("amount", true)
		if perr != nil {
			return perr.status, perr
		}
		currency, perr := f.currency()
		if perr != nil {
			return perr.status, perr
		}
		confirm, perr := f.flag("confirm")
		if perr != nil {
			return perr.status, perr
		}
		offSession, perr := f.flag("off_session")
		if perr != nil {
			return perr.status, perr
		}
		if offSession && !confirm {
			return http.StatusBadRequest, invalid("off_session", "off_session can only be used with confirm=true.")
		}
		if types := f.lists["payment_method_types"]; len(types) > 0 && !slices.Equal(types, []string{"card"}) {
			return http.StatusBadRequest, invalid("payment_method_types", "The simulator supports payment_method_types[]=card only.")
		}
		cust := s.customers[f.get("customer")]
		if f.get("customer") == "" {
			return http.StatusBadRequest, missing("customer")
		}
		if cust == nil {
			return http.StatusBadRequest, noSuch("customer", "customer", f.get("customer"))
		}
		pm := f.get("payment_method")
		if confirm && pm == "" {
			return http.StatusBadRequest, missing("payment_method")
		}
		if pm != "" && pm != TestCardVisa && pm != TestCardDeclined && !slices.Contains(cust.methods, pm) {
			return http.StatusBadRequest, noSuch("PaymentMethod", "payment_method", pm)
		}
		p := &paymentIntent{
			id: newID("pi_"), customer: cust.id, method: pm, currency: currency, key: r.Header.Get("Idempotency-Key"),
			amount: amount, created: c.now, metadata: f.metadata, settle: s.faults.SettleAfter,
		}
		s.intents[p.id] = p
		s.order = append(s.order, p.id)
		s.stats.Intents++
		if !confirm {
			return http.StatusOK, s.renderIntent(p, c, f.lists["expand"])
		}
		return s.confirm(p, c, f)
	})
}

// confirm charges a payment intent's payment method.
func (s *Server) confirm(p *paymentIntent, c call, f *form) (int, any) {
	if p.method == TestCardDeclined || chance(s.faults.DeclineRate) {
		p.declined = true
		s.stats.Declines++
		return http.StatusPaymentRequired, &apiError{
			status: http.StatusPaymentRequired, Type: "card_error", Code: "card_declined",
			Decline: "generic_decline", Message: "Your card was declined.", Intent: s.renderIntent(p, c, nil),
		}
	}
	p.declined, p.confirmed = false, c.now
	ch := &charge{id: newID("ch_"), intent: p.id, customer: p.customer, currency: p.currency, amount: p.amount, created: c.now}
	s.charges[ch.id] = ch
	p.charge = ch.id
	return http.StatusOK, s.renderIntent(p, c, f.lists["expand"])
}

func (s *Server) getIntent(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"expand[]"}, func(c call, f *form) (int, any) {
		p := s.intents[r.PathValue("id")]
		if p == nil {
			return http.StatusNotFound, noSuch("payment_intent", "", r.PathValue("id"))
		}
		return http.StatusOK, s.renderIntent(p, c, f.lists["expand"])
	})
}

func unexpectedState(p *paymentIntent, now time.Time, action string) *apiError {
	return &apiError{
		status: http.StatusBadRequest, Type: "invalid_request_error", Code: "payment_intent_unexpected_state",
		Message: "You cannot " + action + " this PaymentIntent because it has a status of " + p.status(now) + ".",
	}
}

// confirmIntent confirms a payment intent that requires confirmation, or
// retries one whose payment method was declined with a new one.
func (s *Server) confirmIntent(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, "confirm "+r.PathValue("id"), []string{"payment_method", "off_session", "expand[]"},
		func(c call, f *form) (int, any) {
			p := s.intents[r.PathValue("id")]
			if p == nil {
				return http.StatusNotFound, noSuch("payment_intent", "", r.PathValue("id"))
			}
			if st := p.status(c.now); st != "requires_confirmation" && st != "requires_payment_method" {
				e := unexpectedState(p, c.now, "confirm")
				return e.status, e
			}
			if pm := f.get("payment_method"); pm != "" {
				if pm != TestCardVisa && pm != TestCardDeclined && !slices.Contains(s.customers[p.customer].methods, pm) {
					return http.StatusBadRequest, noSuch("PaymentMethod", "payment_method", pm)
				}
				p.method = pm
			}
			if p.method == "" {
				return http.StatusBadRequest, missing("payment_method")
			}
			return s.confirm(p, c, f)
		})
}

// cancelIntent cancels a payment intent that has not been charged.
func (s *Server) cancelIntent(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, "cancel "+r.PathValue("id"), []string{"cancellation_reason", "expand[]"},
		func(c call, f *form) (int, any) {
			p := s.intents[r.PathValue("id")]
			if p == nil {
				return http.StatusNotFound, noSuch("payment_intent", "", r.PathValue("id"))
			}
			reason := f.get("cancellation_reason")
			if reason == "" {
				reason = "requested_by_customer"
			}
			if !slices.Contains(append(slices.Clone(reasons), "abandoned"), reason) {
				return http.StatusBadRequest, invalid("cancellation_reason", "Invalid cancellation_reason: "+reason)
			}
			if st := p.status(c.now); st != "requires_confirmation" && st != "requires_payment_method" {
				e := unexpectedState(p, c.now, "cancel")
				return e.status, e
			}
			p.canceled = reason
			return http.StatusOK, s.renderIntent(p, c, f.lists["expand"])
		})
}

// createTransfer sends funds from the platform's available balance to a
// connected account (POST /v1/transfers).
func (s *Server) createTransfer(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, "transfers", []string{"amount", "currency", "destination", "transfer_group", "description", "metadata", "expand[]"},
		func(c call, f *form) (int, any) {
			amount, _, perr := f.amount("amount", true)
			if perr != nil {
				return perr.status, perr
			}
			currency, perr := f.currency()
			if perr != nil {
				return perr.status, perr
			}
			dest := f.get("destination")
			if dest == "" {
				return http.StatusBadRequest, missing("destination")
			}
			if !accountID.MatchString(dest) || s.accounts[dest] == nil {
				return http.StatusBadRequest, noSuch("destination", "destination", dest)
			}
			if g := f.get("transfer_group"); g != "" && !groupID.MatchString(g) {
				return http.StatusBadRequest, invalid("transfer_group", "Invalid transfer_group.")
			}
			if len(f.get("description")) > 500 {
				return http.StatusBadRequest, invalid("description", "Invalid description: at most 500 characters.")
			}
			if s.available(currency, c.now) < amount {
				return http.StatusBadRequest, &apiError{
					status: http.StatusBadRequest, Type: "invalid_request_error",
					Code: "balance_insufficient", Message: "You have insufficient available funds in your Stripe account.",
				}
			}
			t := &transfer{
				id: newID("tr_"), destination: dest, currency: currency, group: f.get("transfer_group"),
				description: f.get("description"), key: r.Header.Get("Idempotency-Key"), amount: amount, created: c.now,
				metadata: f.metadata,
			}
			s.transfers[t.id] = t
			s.order = append(s.order, t.id)
			s.stats.Transfers++
			return http.StatusOK, s.renderTransfer(t, c)
		})
}

func (s *Server) getTransfer(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"expand[]"}, func(c call, _ *form) (int, any) {
		t := s.transfers[r.PathValue("id")]
		if t == nil {
			return http.StatusNotFound, noSuch("transfer", "", r.PathValue("id"))
		}
		return http.StatusOK, s.renderTransfer(t, c)
	})
}

// getPlatform reads the platform account (the connection test's harmless
// read).
func (s *Server) getPlatform(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, nil, func(c call, _ *form) (int, any) { return http.StatusOK, renderAccount(FixturePlatform, c) })
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"expand[]"}, func(c call, _ *form) (int, any) {
		if s.accounts[r.PathValue("id")] == nil {
			return http.StatusNotFound, noSuch("account", "", r.PathValue("id"))
		}
		return http.StatusOK, renderAccount(r.PathValue("id"), c)
	})
}

// eventRetention is how far back Stripe's events listing reaches.
const eventRetention = 30 * 24 * time.Hour

// listEvents lists the events of the connected account named by the
// Stripe-Account header (without it, the platform's, of which the
// simulator has none), newest first: the read behind the
// stripe.account.payout_details_changed fact (account.external_account.*
// events within 7 days). type may end in ".*" as Stripe's does.
func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"type", "types[]", "created[gte]", "limit", "starting_after"}, func(c call, f *form) (int, any) {
		limit, since, perr := listParams(f)
		if perr != nil {
			return perr.status, perr
		}
		typ, types := f.get("type"), f.lists["types"]
		if typ != "" && len(types) > 0 {
			return http.StatusBadRequest, invalid("types", "You cannot pass both type and types.")
		}
		if len(types) > 20 {
			return http.StatusBadRequest, invalid("types", "Invalid types: at most 20.")
		}
		match := func(k string) bool {
			switch {
			case typ != "" && strings.HasSuffix(typ, ".*"):
				return strings.HasPrefix(k, strings.TrimSuffix(typ, "*"))
			case typ != "":
				return k == typ
			case len(types) > 0:
				return slices.Contains(types, k)
			}
			return true
		}
		var items []struct {
			acct string
			b    bankChange
		}
		if acct := r.Header.Get("Stripe-Account"); acct != "" {
			a := s.accounts[acct]
			if !accountID.MatchString(acct) || a == nil {
				return http.StatusForbidden, &apiError{
					status: http.StatusForbidden, Type: "invalid_request_error",
					Code: "account_invalid", Message: "The provided key does not have access to account '" + acct + "'.",
				}
			}
			changes := slices.Clone(a.bankChanges)
			if s.faults.BankChangedRecently {
				changes = append(changes, bankChange{
					event: "evt_SimBank" + strings.TrimPrefix(acct, "acct_"),
					kind:  "account.external_account.updated", at: c.now.Add(-24 * time.Hour),
				})
			}
			slices.SortStableFunc(changes, func(x, y bankChange) int { return y.at.Compare(x.at) })
			for _, b := range changes {
				if match(b.kind) && b.at.Unix() >= since && c.now.Sub(b.at) <= eventRetention {
					items = append(items, struct {
						acct string
						b    bankChange
					}{acct, b})
				}
			}
		}
		page, more, perr := pageAfter(items, f.get("starting_after"), limit, func(e struct {
			acct string
			b    bankChange
		},
		) string {
			return e.b.event
		})
		if perr != nil {
			return perr.status, perr
		}
		data := make([]any, len(page))
		for i, e := range page {
			data[i] = renderEvent(e.acct, e.b, c)
		}
		return http.StatusOK, list("/v1/events", data, more)
	})
}

// getBalance reads the platform's balance, one entry per currency it holds.
func (s *Server) getBalance(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, nil, func(c call, _ *form) (int, any) {
		var avail []any
		for _, cur := range []string{"usd", "eur", "gbp"} {
			avail = append(avail, map[string]any{"amount": s.available(cur, c.now), "currency": cur})
		}
		return http.StatusOK, map[string]any{"object": "balance", "available": avail, "pending": []any{}, "livemode": c.live}
	})
}

// listParams reads limit (1–100, default 10) and created[gte] (unix
// seconds, default none).
func listParams(f *form) (limit int, since int64, perr *apiError) {
	limit, since = 10, -1<<62
	if v := f.get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			return 0, 0, invalid("limit", "Invalid limit: must be an integer from 1 to 100.")
		}
		limit = n
	}
	if v := f.get("created[gte]"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return 0, 0, invalid("created[gte]", "Invalid timestamp: "+v)
		}
		since = n
	}
	return limit, since, nil
}

// pageAfter returns up to limit items after the one whose id is after (from
// the start when after is empty), and whether more follow.
func pageAfter[T any](items []T, after string, limit int, id func(T) string) ([]T, bool, *apiError) {
	if after != "" {
		i := slices.IndexFunc(items, func(t T) bool { return id(t) == after })
		if i < 0 {
			return nil, false, invalid("starting_after", "Invalid starting_after: "+after)
		}
		items = items[i+1:]
	}
	if len(items) > limit {
		return items[:limit], true, nil
	}
	return items, false, nil
}

func list(url string, data []any, more bool) map[string]any {
	return map[string]any{"object": "list", "data": data, "has_more": more, "url": url}
}

// listIntents lists payment intents newest first, of one customer, created
// at or after created[gte], continuing after starting_after (the payment
// intent verifier's lookup after a lost answer).
func (s *Server) listIntents(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"customer", "created[gte]", "limit", "starting_after"}, func(c call, f *form) (int, any) {
		limit, since, perr := listParams(f)
		if perr != nil {
			return perr.status, perr
		}
		var items []*paymentIntent
		for _, id := range slices.Backward(s.order) {
			if p := s.intents[id]; p != nil && (f.get("customer") == "" || p.customer == f.get("customer")) && p.created.Unix() >= since {
				items = append(items, p)
			}
		}
		page, more, perr := pageAfter(items, f.get("starting_after"), limit, func(p *paymentIntent) string { return p.id })
		if perr != nil {
			return perr.status, perr
		}
		data := make([]any, len(page))
		for i, p := range page {
			data[i] = s.renderIntent(p, c, nil)
		}
		return http.StatusOK, list("/v1/payment_intents", data, more)
	})
}

// listTransfers lists transfers newest first, to one destination or of one
// transfer group, created at or after created[gte], continuing after
// starting_after (the transfer verifier's lookup after a lost answer).
func (s *Server) listTransfers(w http.ResponseWriter, r *http.Request) {
	s.get(w, r, []string{"destination", "transfer_group", "created[gte]", "limit", "starting_after"}, func(c call, f *form) (int, any) {
		limit, since, perr := listParams(f)
		if perr != nil {
			return perr.status, perr
		}
		var items []*transfer
		for _, id := range slices.Backward(s.order) {
			if t := s.transfers[id]; t != nil && (f.get("destination") == "" || t.destination == f.get("destination")) &&
				(f.get("transfer_group") == "" || t.group == f.get("transfer_group")) && t.created.Unix() >= since {
				items = append(items, t)
			}
		}
		page, more, perr := pageAfter(items, f.get("starting_after"), limit, func(t *transfer) string { return t.id })
		if perr != nil {
			return perr.status, perr
		}
		data := make([]any, len(page))
		for i, t := range page {
			data[i] = s.renderTransfer(t, c)
		}
		return http.StatusOK, list("/v1/transfers", data, more)
	})
}
