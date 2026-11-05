// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ap2

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/payments/sdjwt"
)

// MerchantJWTMaxLife bounds a v0.1 merchant_authorization (D1122).
const MerchantJWTMaxLife = 15 * time.Minute

// cartMandate is an AP2 v0.1 CartMandate.
type cartMandate struct {
	Contents              jsontext.Value `json:"contents"`
	MerchantAuthorization string         `json:"merchant_authorization"`
}

// paymentMandate is an AP2 v0.1 PaymentMandate.
type paymentMandate struct {
	Contents          jsontext.Value `json:"payment_mandate_contents"`
	UserAuthorization string         `json:"user_authorization"`
}

// currencyAmount is a W3C PaymentCurrencyAmount; value is kept as its JSON
// number text so the minor units are exact.
type currencyAmount struct {
	Currency string         `json:"currency"`
	Value    jsontext.Value `json:"value"`
}

// paymentItem is a W3C PaymentItem (only its amount is read).
type paymentItem struct {
	Amount currencyAmount `json:"amount"`
}

// cartContents are the CartContents members read.
type cartContents struct {
	ID             string `json:"id"`
	CartExpiry     string `json:"cart_expiry"`
	MerchantName   string `json:"merchant_name"`
	PaymentRequest struct {
		Details struct {
			ID    string      `json:"id"`
			Total paymentItem `json:"total"`
		} `json:"details"`
	} `json:"payment_request"`
}

// paymentContents are the PaymentMandateContents members read.
type paymentContents struct {
	PaymentMandateID    string      `json:"payment_mandate_id"`
	PaymentDetailsID    string      `json:"payment_details_id"`
	PaymentDetailsTotal paymentItem `json:"payment_details_total"`
	MerchantAgent       string      `json:"merchant_agent"`
}

// v01 verifies an AP2 v0.1 envelope: the merchant's CartMandate and the
// user's PaymentMandate, whose KB-JWT transaction_data is [cart_hash,
// payment_hash]. An IntentMandate is never proof and is ignored.
func (v *verifier) v01(ctx context.Context, top map[string]jsontext.Value) (Verified, error) {
	for k := range top {
		if k != memberCart && k != memberPayment1 && k != memberIntent {
			return Verified{}, fmt.Errorf("unknown envelope member %q", k)
		}
	}
	var cm cartMandate
	if err := json.Unmarshal(top[memberCart], &cm, json.RejectUnknownMembers(true)); err != nil || len(cm.Contents) == 0 {
		return Verified{}, errors.New("CartMandate")
	}
	var pm paymentMandate
	if err := json.Unmarshal(top[memberPayment1], &pm, json.RejectUnknownMembers(true)); err != nil || len(pm.Contents) == 0 {
		return Verified{}, errors.New("PaymentMandate")
	}

	// The cart: merchant_authorization signs cart_hash.
	cartJCS, err := canonicalRaw(cm.Contents)
	if err != nil {
		return Verified{}, fmt.Errorf("CartContents: %w", err)
	}
	cartHash := hashB64(cartJCS)
	payload, _, err := v.bySignature(ctx, KindMerchant, cm.MerchantAuthorization, plainJWTTyp)
	if err != nil {
		return Verified{}, fmt.Errorf("merchant_authorization: %w", err)
	}
	var mc map[string]any
	if err := json.Unmarshal(payload, &mc); err != nil || mc == nil {
		return Verified{}, errors.New("merchant_authorization payload")
	}
	merchant, _ := mc["iss"].(string)
	if merchant == "" {
		return Verified{}, errors.New("merchant_authorization iss")
	}
	if h, _ := mc["cart_hash"].(string); h != cartHash {
		return Verified{}, errors.New("cart_hash is not the hash of CartContents")
	}
	iat, iok, err := sdjwt.NumericDate(mc, "iat")
	if err != nil {
		return Verified{}, err
	}
	exp, eok, err := sdjwt.NumericDate(mc, "exp")
	if err != nil {
		return Verified{}, err
	}
	if !iok || !eok || !exp.After(iat) || exp.Sub(iat) > MerchantJWTMaxLife || iat.After(v.now.Add(sdjwt.ClockSkew)) {
		return Verified{}, errors.New("merchant_authorization iat and exp (at most 15 minutes)")
	}
	if err := v.checkTimes(mc); err != nil {
		return Verified{}, fmt.Errorf("merchant_authorization: %w", err)
	}
	var cart cartContents
	if err := json.Unmarshal(cm.Contents, &cart); err != nil || cart.ID == "" {
		return Verified{}, errors.New("CartContents members")
	}
	cartExp, err := time.Parse(time.RFC3339, cart.CartExpiry)
	if err != nil {
		return Verified{}, errors.New("cart_expiry")
	}
	if !v.now.Before(cartExp) {
		return Verified{}, errors.New("cart expired")
	}
	v.expiry(cartExp)

	// The payment: an anchor-issued SD-JWT-VC with a KB-JWT over both hashes.
	payJCS, err := canonicalRaw(pm.Contents)
	if err != nil {
		return Verified{}, fmt.Errorf("PaymentMandateContents: %w", err)
	}
	payHash := hashB64(payJCS)
	p, claims, anchor, err := v.issued(ctx, pm.UserAuthorization)
	if err != nil {
		return Verified{}, fmt.Errorf("user_authorization: %w", err)
	}
	holder, err := sdjwt.HolderKey(claims)
	if err != nil {
		return Verified{}, fmt.Errorf("user_authorization: %w", err)
	}
	kb, err := p.VerifyKB(holder, v.anchors.Audiences(), v.now)
	if err != nil {
		return Verified{}, fmt.Errorf("user_authorization: %w", err)
	}
	v.expiry(kb.IssuedAt.Add(sdjwt.KBMaxAge))
	var td []string
	if raw, ok := kb.Extra["transaction_data"]; !ok || json.Unmarshal(raw, &td) != nil ||
		len(td) != 2 || td[0] != cartHash || td[1] != payHash {
		return Verified{}, errors.New("KB-JWT transaction_data is not [cart_hash, payment_hash]")
	}

	var pay paymentContents
	if err := json.Unmarshal(pm.Contents, &pay); err != nil || pay.PaymentMandateID == "" || pay.MerchantAgent == "" {
		return Verified{}, errors.New("PaymentMandateContents members")
	}
	if pay.PaymentDetailsID != cart.PaymentRequest.Details.ID {
		return Verified{}, errors.New("payment_details_id is not the cart's payment request")
	}
	payMinor, cur, err := minorUnits(pay.PaymentDetailsTotal.Amount)
	if err != nil {
		return Verified{}, fmt.Errorf("payment_details_total: %w", err)
	}
	cartMinor, cartCur, err := minorUnits(cart.PaymentRequest.Details.Total.Amount)
	if err != nil {
		return Verified{}, fmt.Errorf("cart total: %w", err)
	}
	if payMinor != cartMinor || cur != cartCur || payMinor <= 0 {
		return Verified{}, errors.New("payment total is not the cart total")
	}

	canon, err := canonicalJSON(map[string]any{
		"v": V01, memberCart: map[string]any{"contents": jsontext.Value(cartJCS), "merchant_authorization": cm.MerchantAuthorization},
		memberPayment1: map[string]any{"payment_mandate_contents": jsontext.Value(payJCS), "user_authorization": p.Canonical()},
	})
	if err != nil {
		return Verified{}, err
	}
	return Verified{
		Version: V01, Payee: pay.MerchantAgent, Merchant: merchant, AmountMinor: payMinor, Currency: cur,
		CartHash: cartHash, TransactionID: pay.PaymentMandateID, ExpiresAt: v.expires,
		MandateDigest: digestOf([]byte(canon)), IssuerAnchorID: anchor,
	}, nil
}

// decimalRE is a non-negative JSON number without an exponent.
var decimalRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})(\.[0-9]{1,8})?$`)

// minorUnits converts a W3C amount to ISO 4217 minor units exactly: a
// value with more fraction digits than the currency has, or an exponent,
// is refused.
func minorUnits(a currencyAmount) (int64, string, error) {
	if !currencyRE.MatchString(a.Currency) {
		return 0, "", errors.New("currency")
	}
	s := strings.TrimSpace(string(a.Value))
	if strings.HasPrefix(s, `"`) { // a decimal string is accepted as well
		if err := json.Unmarshal(a.Value, &s); err != nil {
			return 0, "", errors.New("value")
		}
	}
	if !decimalRE.MatchString(s) {
		return 0, "", errors.New("value is not a plain decimal")
	}
	whole, frac, _ := strings.Cut(s, ".")
	exp := minorExponent(a.Currency)
	frac = strings.TrimRight(frac, "0")
	if len(frac) > exp {
		return 0, "", errors.New("value has more decimals than the currency")
	}
	frac += strings.Repeat("0", exp-len(frac))
	var n int64
	for _, c := range whole + frac {
		if n > (math.MaxInt64-9)/10 {
			return 0, "", errors.New("value too large")
		}
		n = n*10 + int64(c-'0')
	}
	return n, a.Currency, nil
}

// minorExponent is the ISO 4217 minor unit of a currency: 2 unless listed.
func minorExponent(cur string) int {
	switch cur {
	case "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF":
		return 0
	case "BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND":
		return 3
	case "CLF", "UYW":
		return 4
	}
	return 2
}
