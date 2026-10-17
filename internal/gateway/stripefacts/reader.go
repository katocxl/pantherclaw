// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package stripefacts reads the stripe.* facts the pc.stripe package names
// (G0 M14 D12, D51) from Stripe, with the connection's own test key, before
// the gateway asks for a decision; the gateway reports them as the
// connection's fact provider (HR-160). A fact it cannot read, or whose
// answer is not what it expects, is left unread: the decision sees it
// missing and never a guessed value. An answer reporting livemode true is
// never a fact (HR-303, D54): it is reported to the caller, which
// quarantines the connection.
package stripefacts

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Fact names this reader provides.
const (
	// Refundable is what is left to refund on a payment (a PaymentIntent
	// or a charge): members remaining (money: value and currency, as
	// ActionIR writes money), payment (the charge id) and livemode.
	Refundable = "stripe.payment.refundable"
	// PayoutDetailsChanged is whether a connected account's external
	// (bank) account was added, changed or removed within BankWindow:
	// members changed (bool), last_changed (unix seconds, 0 when none)
	// and account.
	PayoutDetailsChanged = "stripe.account.payout_details_changed"
)

// APIVersion is the Stripe API version every read pins (the pc.stripe
// package's Stripe-Version).
const APIVersion = "2026-09-30.endive"

// BankWindow is how far back a bank-account change counts (D12).
const BankWindow = 7 * 24 * time.Hour

// ErrLivemode reports a Stripe answer with livemode true.
var ErrLivemode = errors.New("stripe answered in live mode")

// Getter reads one Stripe API path (with its query) with the connection's
// key placed and Stripe-Version pinned; account, when set, is sent as
// Stripe-Account (acting as that connected account).
type Getter func(ctx context.Context, path, account string) (egress.Response, error)

// Fact is one fact read, as its value's members.
type Fact struct {
	Name  string
	Value map[string]any
}

var (
	paymentID = regexp.MustCompile(`^(pi|ch)_[A-Za-z0-9]{8,64}$`)
	accountID = regexp.MustCompile(`^acct_[A-Za-z0-9]{8,64}$`)
)

// ReadAll reads the named facts about the action's target id, and says
// why each it could not read was not. live reports that some answer was
// in live mode (every fact it touched is then unread).
func ReadAll(ctx context.Context, get Getter, target string, names []string, now time.Time) (read []Fact, unread map[string]string, live bool) {
	unread = map[string]string{}
	for _, name := range names {
		var v map[string]any
		var err error
		switch name {
		case Refundable:
			v, err = refundable(ctx, get, target)
		case PayoutDetailsChanged:
			v, err = payoutDetailsChanged(ctx, get, target, now)
		default:
			err = fmt.Errorf("unknown fact %s", name)
		}
		switch {
		case errors.Is(err, ErrLivemode):
			live = true
			unread[name] = notRead(err)
		case err != nil:
			unread[name] = notRead(err)
		default:
			read = append(read, Fact{Name: name, Value: v})
		}
	}
	return read, unread, live
}

// UnreadFact is the value reported for a fact that could not be read: none
// of its members, which no binding or rule accepts, so an earlier
// observation still fresh never decides.
func UnreadFact(why string) map[string]any {
	return map[string]any{"unread": why}
}

// notRead is why a fact was not read: the error, without control
// characters and at most 160 bytes. Stripe's answers name objects and
// codes, never the key.
func notRead(err error) string {
	msg := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	if len(msg) > 160 {
		msg = msg[:160]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}
	return "not read: " + msg
}

// object reads path as one JSON object; a live-mode answer is ErrLivemode.
func object(ctx context.Context, get Getter, path, account string) (map[string]any, error) {
	return read(ctx, get, path, account, true)
}

// read reads path as one JSON object; an object (not a list, which Stripe
// writes without livemode) must say livemode false.
func read(ctx context.Context, get Getter, path, account string, isObject bool) (map[string]any, error) {
	res, err := get(ctx, path, account)
	switch {
	case err != nil:
		return nil, err
	case res.Status != http.StatusOK || res.Truncated:
		return nil, fmt.Errorf("GET %s answered %d", strings.SplitN(path, "?", 2)[0], res.Status)
	}
	var v map[string]any
	if err := json.Unmarshal(res.Body, &v); err != nil {
		return nil, fmt.Errorf("GET %s: not a JSON object", strings.SplitN(path, "?", 2)[0])
	}
	if live, ok := v["livemode"].(bool); isObject && (!ok || live) {
		if live {
			return nil, ErrLivemode
		}
		return nil, fmt.Errorf("GET %s: no livemode", strings.SplitN(path, "?", 2)[0])
	}
	return v, nil
}

// integer reads a non-negative JSON integer member.
func integer(m map[string]any, k string) (int64, bool) {
	f, ok := m[k].(float64)
	if !ok || f < 0 || f != float64(int64(f)) || f > 1e15 {
		return 0, false
	}
	return int64(f), true
}

// refundable reads the payment's charge: through the PaymentIntent with
// its latest charge expanded, or the charge itself. Only a succeeded,
// captured charge in a minor-unit currency is refundable; what is left is
// amount less amount_refunded (pending refunds included, as Stripe counts
// them).
func refundable(ctx context.Context, get Getter, target string) (map[string]any, error) {
	if !paymentID.MatchString(target) {
		return nil, errors.New("the target is not a payment")
	}
	var ch map[string]any
	if strings.HasPrefix(target, "pi_") {
		pi, err := object(ctx, get, "/v1/payment_intents/"+url.PathEscape(target)+"?expand%5B%5D=latest_charge", "")
		if err != nil {
			return nil, err
		}
		if pi["id"] != target || pi["status"] != "succeeded" {
			return nil, errors.New("the payment intent has not succeeded")
		}
		ch, _ = pi["latest_charge"].(map[string]any)
		if ch == nil {
			return nil, errors.New("the payment intent has no charge")
		}
		if live, ok := ch["livemode"].(bool); !ok || live {
			if live {
				return nil, ErrLivemode
			}
			return nil, errors.New("the charge has no livemode")
		}
		if ch["payment_intent"] != target {
			return nil, errors.New("the charge belongs to another payment intent")
		}
	} else {
		var err error
		if ch, err = object(ctx, get, "/v1/charges/"+url.PathEscape(target), ""); err != nil {
			return nil, err
		}
		if ch["id"] != target {
			return nil, errors.New("Stripe answered another charge")
		}
	}
	id, _ := ch["id"].(string)
	if !paymentID.MatchString(id) || !strings.HasPrefix(id, "ch_") {
		return nil, errors.New("the charge has no id")
	}
	if ch["status"] != "succeeded" || ch["captured"] != true {
		return nil, errors.New("the charge has not succeeded")
	}
	amount, ok1 := integer(ch, "amount")
	refunded, ok2 := integer(ch, "amount_refunded")
	code, _ := ch["currency"].(string)
	if !ok1 || !ok2 || refunded > amount {
		return nil, errors.New("the charge's amounts are not readable")
	}
	cur := money.Currency(strings.ToUpper(code))
	if strings.ToLower(code) != code || len(code) != 3 {
		return nil, errors.New("the charge's currency is not readable")
	}
	left, err := money.FromMinor(amount-refunded, cur)
	if err != nil {
		return nil, errors.New("the charge's currency is not exchanged in minor units")
	}
	return map[string]any{
		"remaining": map[string]any{"value": defs.FormatMoney(left), "currency": string(cur)},
		"payment":   id,
		"livemode":  false,
	}, nil
}

// payoutDetailsChanged lists the connected account's
// account.external_account.* events created within BankWindow, acting as
// the account (Stripe-Account), newest first. Any such event is a change:
// one page answers the question, and every event on it must be about this
// account's bank details, in test mode.
func payoutDetailsChanged(ctx context.Context, get Getter, target string, now time.Time) (map[string]any, error) {
	if !accountID.MatchString(target) {
		return nil, errors.New("the target is not a connected account")
	}
	since := now.Add(-BankWindow).Unix()
	q := url.Values{"type": {"account.external_account.*"}, "created[gte]": {strconv.FormatInt(since, 10)}, "limit": {"10"}}
	page, err := read(ctx, get, "/v1/events?"+q.Encode(), target, false)
	if err != nil {
		return nil, err
	}
	data, ok := page["data"].([]any)
	if _, ok2 := page["has_more"].(bool); page["object"] != "list" || !ok || !ok2 {
		return nil, errors.New("the events listing is not readable")
	}
	var last int64
	for _, d := range data {
		ev, _ := d.(map[string]any)
		typ, _ := ev["type"].(string)
		created, okc := integer(ev, "created")
		if live, okl := ev["livemode"].(bool); !okl || live {
			if live {
				return nil, ErrLivemode
			}
			return nil, errors.New("an event has no livemode")
		}
		if ev["account"] != target || !strings.HasPrefix(typ, "account.external_account.") || !okc || created < since {
			return nil, errors.New("an event is not a recent change of this account's bank details")
		}
		last = max(last, created)
	}
	return map[string]any{"changed": last > 0, "last_changed": last, "account": target}, nil
}
