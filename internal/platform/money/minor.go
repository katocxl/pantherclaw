// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package money

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrMinorCurrency reports a currency whose amounts are not exchanged in
// minor units here (G0 M14 D8, CURRENCY_UNSUPPORTED).
var ErrMinorCurrency = errors.New("money: currency unsupported in minor units")

// minorExponents are the currencies an API may exchange as integer minor
// units, with their exponents (G0 M14 D8). The list is closed and shorter
// than minorUnits on purpose: it names only currencies whose minor unit
// targets such as Stripe agree on.
var minorExponents = map[Currency]int{
	"USD": 2, "EUR": 2, "GBP": 2, "CAD": 2, "AUD": 2, "NZD": 2, "CHF": 2,
	"SEK": 2, "NOK": 2, "DKK": 2, "SGD": 2, "HKD": 2, "JPY": 0, "KRW": 0,
}

// MinorExponent returns the minor-unit exponent of a currency exchanged in
// minor units, or ErrMinorCurrency.
func MinorExponent(c Currency) (int, error) {
	n, ok := minorExponents[c]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrMinorCurrency, string(c))
	}
	return n, nil
}

// minorRe is a non-negative integer of minor units without leading zeros.
var minorRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)

// FromMinor is the amount of units minor units of currency: 8550 USD is
// 85.50 USD, 100 JPY is 100 JPY.
func FromMinor(units int64, currency Currency) (Money, error) {
	n, err := MinorExponent(currency)
	if err != nil {
		return Money{}, err
	}
	if units < 0 {
		return Money{}, fmt.Errorf("%w: negative minor units", ErrInvalidDecimal)
	}
	s := fmt.Sprintf("%0*d", n+1, units)
	if n > 0 {
		s = s[:len(s)-n] + "." + s[len(s)-n:]
	}
	return ParseMoney(s, string(currency))
}

// ToMinor is m in integer minor units, as a decimal string ("8550" for
// 85.50 USD). An amount finer than the minor unit, a negative amount or a
// currency outside the minor-unit list is refused, never rounded.
func ToMinor(m Money) (string, error) {
	n, err := MinorExponent(m.Currency)
	if err != nil {
		return "", err
	}
	if m.Amount.Sign() < 0 {
		return "", fmt.Errorf("%w: negative amount", ErrInvalidDecimal)
	}
	s, err := m.Amount.StringFixed(n)
	if err != nil {
		return "", err
	}
	s = strings.TrimLeft(strings.Replace(s, ".", "", 1), "0")
	if s == "" {
		s = "0"
	}
	if !minorRe.MatchString(s) {
		return "", fmt.Errorf("%w: %s is out of range in minor units", ErrInvalidDecimal, m.Amount)
	}
	return s, nil
}
