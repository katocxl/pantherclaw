// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Value is one typed trigger parameter (D11, HR-276). Exactly the field of
// its type is meaningful; decimals are canonical decimal strings.
type Value struct {
	Type    ParamType `json:"type"`
	String  string    `json:"string,omitzero"`
	Int     int64     `json:"int,omitzero"`
	Decimal string    `json:"decimal,omitzero"`
	Bool    bool      `json:"bool,omitzero"`
}

// Text is the value as template text.
func (v Value) Text() string {
	switch v.Type {
	case ParamInt:
		return strconv.FormatInt(v.Int, 10)
	case ParamDecimal:
		return v.Decimal
	case ParamBool:
		return strconv.FormatBool(v.Bool)
	case ParamString, ParamEnum, ParamUUID:
	}
	return v.String
}

// Parameter bounds (D2).
const (
	DefaultParamMaxLen = 64
	MaxParamMaxLen     = 256
	MaxParamPattern    = 200
	MaxParamValues     = 50
)

// ErrParam reports a trigger value that does not fit its declaration; the
// trigger is refused (REFUSED_INVALID, HR-276).
var ErrParam = fmt.Errorf("%w: parameter", ErrInvalid)

func paramErr(name, format string, args ...any) error {
	return fmt.Errorf("%w %s: "+format, append([]any{ErrParam, name}, args...)...)
}

// MaxLenOrDefault is the declared length bound, 64 when unset.
func (p ParamSpec) MaxLenOrDefault() int {
	if p.MaxLen == 0 {
		return DefaultParamMaxLen
	}
	return p.MaxLen
}

// Convert turns a raw value (a JSON-decoded scalar: string, float64,
// bool; or text from a form) into a typed Value within the
// declaration's bounds. It never coerces across types except text to the
// declared type.
func (p ParamSpec) Convert(name string, raw any) (Value, error) {
	var s string
	switch r := raw.(type) {
	case string:
		s = r
	case float64:
		if p.Type != ParamInt && p.Type != ParamDecimal {
			return Value{}, paramErr(name, "a %s is expected", p.Type)
		}
		if r != math.Trunc(r) || math.Abs(r) > 1<<53 {
			return Value{}, paramErr(name, "numbers that are not whole are sent as strings")
		}
		s = strconv.FormatInt(int64(r), 10)
	case bool:
		if p.Type != ParamBool {
			return Value{}, paramErr(name, "a %s is expected", p.Type)
		}
		return Value{Type: ParamBool, Bool: r}, nil
	default:
		return Value{}, paramErr(name, "a %s is expected", p.Type)
	}
	if !utf8.ValidString(s) {
		return Value{}, paramErr(name, "not UTF-8")
	}
	switch p.Type {
	case ParamString:
		if utf8.RuneCountInString(s) > p.MaxLenOrDefault() {
			return Value{}, paramErr(name, "longer than %d characters", p.MaxLenOrDefault())
		}
		if p.Pattern != "" {
			re, err := regexp.Compile(`^(?:` + p.Pattern + `)$`)
			if err != nil || !re.MatchString(s) {
				return Value{}, paramErr(name, "does not match the declared pattern")
			}
		}
		return Value{Type: ParamString, String: s}, nil
	case ParamEnum:
		if !slices.Contains(p.Values, s) {
			return Value{}, paramErr(name, "not one of the declared values")
		}
		return Value{Type: ParamEnum, String: s}, nil
	case ParamUUID:
		u, err := ids.ParseUUID(s)
		if err != nil || u.IsZero() {
			return Value{}, paramErr(name, "not a UUID")
		}
		return Value{Type: ParamUUID, String: u.String()}, nil
	case ParamBool:
		b, err := strconv.ParseBool(s)
		if err != nil || (s != "true" && s != "false") {
			return Value{}, paramErr(name, "true or false is expected")
		}
		return Value{Type: ParamBool, Bool: b}, nil
	case ParamInt:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != s {
			return Value{}, paramErr(name, "a whole number is expected")
		}
		if err := p.inRange(name, money.MustParse(s)); err != nil {
			return Value{}, err
		}
		return Value{Type: ParamInt, Int: n}, nil
	case ParamDecimal:
		d, err := money.Parse(s)
		if err != nil {
			return Value{}, paramErr(name, "a decimal number is expected")
		}
		if err := p.inRange(name, d); err != nil {
			return Value{}, err
		}
		return Value{Type: ParamDecimal, Decimal: d.String()}, nil
	}
	return Value{}, paramErr(name, "unknown type %q", p.Type)
}

func (p ParamSpec) inRange(name string, d money.Decimal) error {
	if p.Min != "" {
		if m, err := money.Parse(p.Min); err != nil || d.Cmp(m) < 0 {
			return paramErr(name, "below the declared minimum")
		}
	}
	if p.Max != "" {
		if m, err := money.Parse(p.Max); err != nil || d.Cmp(m) > 0 {
			return paramErr(name, "above the declared maximum")
		}
	}
	return nil
}

// MaxParamsEnvelope bounds a trigger's stored parameters (the 4 KiB CHECK
// on their JSON, D87 L3).
const MaxParamsEnvelope = 4096

// ParamsEnvelopeBytes is the most a trigger's parameters can take as
// stored JSON: every parameter present at its longest, each character
// escaped as \uXXXX (D91 K3).
func ParamsEnvelopeBytes(ps map[string]ParamSpec) int {
	n := 2 // {}
	for name, p := range ps {
		// "name":{"type":"…","string":"…"},
		n += len(name) + 4 + len(`{"type":"","string":""}`) + len(p.Type) + 10
		switch p.Type {
		case ParamString:
			n += 6 * p.MaxLenOrDefault()
		case ParamEnum:
			longest := 0
			for _, v := range p.Values {
				longest = max(longest, len(v))
			}
			n += 6 * longest
		case ParamUUID:
			n += 36
		case ParamInt:
			n += 20
		case ParamDecimal:
			n += 80
		case ParamBool:
			n += 5
		}
	}
	return n
}
