// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"strconv"
)

// TypeMandate is an agent payment mandate envelope as the agent holds it
// (G0 M39 D1122, D1124, D1124a): the JSON object text ap2.Verify takes, of
// at most MaxMandateBytes, whose members are compact SD-JWT presentations
// (AP2 v0.2 {"checkout_mandate", "payment_mandate"}, each one presentation
// or [open, closed]) or the AP2 v0.1 mandate objects. Only printable ASCII
// is accepted. It is gateway-bound like a float_array or a string_map: the
// server's Authority verifies it (D1124d) and the gateway sends it to the merchant from the
// payment operation's dispatch template, policies never see it, and
// approvals show its verified facts and "mandate (N bytes)", never its
// text. A definition declares it only as its payment block's mandate_param.
const TypeMandate ParamType = "mandate"

// MaxMandateBytes bounds a mandate param (D1124; ap2.MaxEnvelope).
const MaxMandateBytes = 32 << 10

// mandate checks a mandate value: printable ASCII, a JSON object, within
// MaxMandateBytes. Whether it verifies is the Authority's payment step (D1124d).
func (p ParamSpec) mandate(s string) error {
	if s == "" || len(s) > MaxMandateBytes {
		return fmt.Errorf("must be 1..%d bytes", MaxMandateBytes)
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("must be printable ASCII")
		}
	}
	if v := jsontext.Value(s); !v.IsValid() || v.Kind() != '{' {
		return fmt.Errorf("must be a mandate envelope (a JSON object)")
	}
	return nil
}

// MandateShown is how an approval shows a mandate: its size only (D1124a).
func MandateShown(s string) string { return "mandate (" + strconv.Itoa(len(s)) + " bytes)" }

// PaymentSpec marks an operation payment-class (G0 M39 D1124; HR-834,
// HR-835): it names the params that hold the amount, its currency, the
// merchant and the mandate. The gateway verifies the mandate and reports
// its facts; the pipeline refuses a missing, invalid or mismatched mandate
// and holds every payment for a person unless an ACTIVE merchant cap
// allows it.
type PaymentSpec struct {
	AmountParam   string `json:"amount_param"`
	CurrencyParam string `json:"currency_param"`
	MerchantParam string `json:"merchant_param"`
	MandateParam  string `json:"mandate_param"`
}

// IsPayment reports whether the operation is payment-class.
func (d *Definition) IsPayment() bool { return d.Payment != nil }

// validatePayment checks the payment block (D1124, D1124a): each named param
// exists with its type (amount money, currency enum or identifier,
// merchant identifier, mandate a mandate), the four are distinct, and a
// mandate param exists only as a payment's mandate_param. Only a write is
// payment-class.
func (d *Definition) validatePayment() error {
	op := d.Operation
	mandates := 0
	for _, p := range d.Params {
		if p.Type == TypeMandate {
			mandates++
		}
	}
	pay := d.Payment
	if pay == nil {
		if mandates > 0 {
			return invalid("%s: a mandate param is declared only as a payment block's mandate_param (G0 M39 D1124a)", op)
		}
		return nil
	}
	if d.Access != AccessWrite {
		return invalid("%s: only a write is payment-class (G0 M39 D1124)", op)
	}
	names := []string{pay.AmountParam, pay.CurrencyParam, pay.MerchantParam, pay.MandateParam}
	for i, n := range names {
		if n == "" || slices.Contains(names[:i], n) {
			return invalid("%s: payment names four distinct params (amount, currency, merchant, mandate)", op)
		}
	}
	checks := []struct {
		role  string
		name  string
		types []ParamType
	}{
		{"amount_param", pay.AmountParam, []ParamType{TypeMoney}},
		{"currency_param", pay.CurrencyParam, []ParamType{TypeEnum, TypeIdentifier}},
		{"merchant_param", pay.MerchantParam, []ParamType{TypeIdentifier}},
		{"mandate_param", pay.MandateParam, []ParamType{TypeMandate}},
	}
	for _, c := range checks {
		p, ok := d.Params[c.name]
		if !ok {
			return invalid("%s: payment.%s names undeclared param %q", op, c.role, c.name)
		}
		if !slices.Contains(c.types, p.Type) {
			return invalid("%s: payment.%s %q must be %v, not %s (G0 M39 D1124a)", op, c.role, c.name, c.types, p.Type)
		}
		if c.role != "mandate_param" && !p.Material {
			return invalid("%s: payment.%s %q must be material", op, c.role, c.name)
		}
	}
	m := d.Params[pay.MandateParam]
	switch {
	case mandates != 1:
		return invalid("%s: a payment declares exactly one mandate param", op)
	case m.Material || m.Disclosure:
		return invalid("%s: the mandate param %q is gateway-bound: never material, never a disclosure param", op, pay.MandateParam)
	}
	return nil
}
