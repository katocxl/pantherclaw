// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Value is one typed parameter value.
type Value struct {
	Type    ParamType
	Money   money.Money   // money
	Decimal money.Decimal // decimal
	Int     int64         // integer
	Str     string        // enum, identifier, text, command, path
	Bool    bool          // boolean
	List    []string      // identifier_list
	Filter  []Predicate   // query_filter
}

// Values are the typed parameters of one action, by name.
type Values map[string]Value

// DecodeParams strictly decodes ActionIR params into typed values. Unknown
// or missing required params, non-canonical numbers, unsupported currencies,
// out-of-range values and unsafe text are ambiguous (HR-101..103): the
// caller answers CANNOT_AUTHORIZE, never a default.
func (d *Definition) DecodeParams(raw jsontext.Value) (Values, error) {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, ambiguous("params must be an object")
	}
	out := make(Values, len(fields))
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		spec, ok := d.Params[name]
		if !ok {
			return nil, ambiguous("unknown param %q", name)
		}
		v, err := spec.decode(name, fields[name])
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	for _, name := range slices.Sorted(maps.Keys(d.Params)) {
		if _, ok := out[name]; !ok && d.Params[name].Required {
			return nil, ambiguous("missing required param %q", name)
		}
	}
	return out, nil
}

func (p ParamSpec) decode(name string, raw jsontext.Value) (Value, error) {
	v := Value{Type: p.Type}
	var err error
	switch p.Type {
	case TypeMoney:
		var m actionir.Amount
		if err = json.Unmarshal(raw, &m, json.RejectUnknownMembers(true)); err != nil {
			return v, ambiguous("%s: %v", name, err)
		}
		v.Money, err = p.money(m.Value, m.Currency)
	case TypeDecimal, TypeInteger:
		var s string
		if err = json.Unmarshal(raw, &s); err != nil {
			return v, ambiguous("%s must be a decimal string (HR-101)", name)
		}
		v.Decimal, v.Int, err = p.number(s)
	case TypeBoolean:
		err = json.Unmarshal(raw, &v.Bool)
	case TypeIdentifierList:
		if err = json.Unmarshal(raw, &v.List); err == nil {
			err = p.list(v.List)
		}
	case TypeQueryFilter:
		v.Filter, err = decodeFilter(raw)
	case TypeEnum, TypeIdentifier, TypeText, TypeCommand, TypeContent, TypePath:
		if err = json.Unmarshal(raw, &v.Str); err == nil {
			err = p.str(v.Str)
		}
	}
	if err != nil {
		return Value{}, ambiguous("%s: %v", name, err)
	}
	return v, nil
}

// money parses an amount that must be canonical: exactly the currency's
// minor-unit digits, positive, in an allowed currency and within bounds.
func (p ParamSpec) money(value, currency string) (money.Money, error) {
	m, err := money.ParseMoney(value, currency)
	if err != nil {
		return money.Money{}, err
	}
	if !slices.Contains(p.Currencies, currency) {
		return money.Money{}, fmt.Errorf("currency %s is not supported here", currency)
	}
	if m.Amount.Sign() <= 0 {
		return money.Money{}, fmt.Errorf("amount must be positive")
	}
	if FormatMoney(m) != value {
		return money.Money{}, fmt.Errorf("amount %q is not in canonical form %q", value, FormatMoney(m))
	}
	return m, p.bounds(m.Amount)
}

func (p ParamSpec) number(s string) (money.Decimal, int64, error) {
	d, err := p.parseNumber(s)
	if err != nil {
		return d, 0, err
	}
	if d.String() != s {
		return d, 0, fmt.Errorf("%q is not in canonical form %q", s, d.String())
	}
	var n int64
	if p.Type == TypeInteger {
		if n, err = strconv.ParseInt(s, 10, 64); err != nil {
			return d, 0, err
		}
	}
	return d, n, p.bounds(d)
}

func (p ParamSpec) bounds(d money.Decimal) error {
	if p.Min != "" && d.Cmp(money.MustParse(p.Min)) < 0 {
		return fmt.Errorf("%s is below the minimum %s", d, p.Min)
	}
	if p.Max != "" && d.Cmp(money.MustParse(p.Max)) > 0 {
		return fmt.Errorf("%s is above the maximum %s", d, p.Max)
	}
	return nil
}

func (p ParamSpec) str(s string) error {
	switch p.Type {
	case TypeEnum:
		if !slices.Contains(p.Values, s) {
			return fmt.Errorf("unsupported value")
		}
		return nil
	case TypeIdentifier:
		return p.identifier(s)
	case TypePath:
		if p.MaxLength > 0 && len(s) > p.MaxLength {
			return fmt.Errorf("longer than %d bytes", p.MaxLength)
		}
		if n, err := actionir.NormalizePath(s); err != nil || n != s {
			return fmt.Errorf("not a normalized absolute path (HR-187)")
		}
		return nil
	case TypeText, TypeCommand, TypeContent:
	case TypeMoney, TypeDecimal, TypeInteger, TypeIdentifierList, TypeBoolean, TypeQueryFilter:
		return fmt.Errorf("not a string type")
	}
	if limit := limitOr(p.MaxLength, maxParamText); len(s) > limit {
		return fmt.Errorf("longer than %d bytes", limit)
	}
	return checkText("text", s)
}

func (p ParamSpec) identifier(s string) error {
	if err := actionir.CheckIdentifier("identifier", s); err != nil {
		return err
	}
	if p.MaxLength > 0 && len(s) > p.MaxLength {
		return fmt.Errorf("longer than %d bytes", p.MaxLength)
	}
	if p.Pattern != "" && !matches(p.Pattern, s) {
		return fmt.Errorf("does not match the declared pattern")
	}
	return nil
}

func (p ParamSpec) list(items []string) error {
	if items == nil || len(items) > p.MaxItems {
		return fmt.Errorf("must be a list of at most %d identifiers", p.MaxItems)
	}
	for i, s := range items {
		if slices.Contains(items[:i], s) {
			return fmt.Errorf("duplicate item %q", s)
		}
		if err := p.identifier(s); err != nil {
			return err
		}
	}
	return nil
}

func limitOr(declared, limit int) int {
	if declared > 0 {
		return declared
	}
	return limit
}

// FormatMoney writes an amount with exactly the currency's minor-unit digits
// ("85.50" USD, "100" JPY): the one canonical form in ActionIR.
func FormatMoney(m money.Money) string {
	n, err := m.Currency.MinorUnits()
	if err != nil {
		return m.Amount.String()
	}
	s, err := m.Amount.StringFixed(n)
	if err != nil {
		return m.Amount.String()
	}
	return s
}

// wire returns the ActionIR JSON form of a value.
func (v Value) wire() any {
	switch v.Type {
	case TypeMoney:
		return actionir.Amount{Value: FormatMoney(v.Money), Currency: string(v.Money.Currency)}
	case TypeDecimal:
		return v.Decimal.String()
	case TypeInteger:
		return strconv.FormatInt(v.Int, 10)
	case TypeBoolean:
		return v.Bool
	case TypeIdentifierList:
		return v.List
	case TypeQueryFilter:
		return v.Filter
	case TypeEnum, TypeIdentifier, TypeText, TypeCommand, TypeContent, TypePath:
		return v.Str
	}
	return nil
}

// EncodeParams writes typed values as ActionIR params after checking them
// against the declared types, so that DecodeParams(EncodeParams(v)) == v.
func (d *Definition) EncodeParams(vals Values) (jsontext.Value, error) {
	obj := make(map[string]any, len(vals))
	for name, v := range vals {
		spec, ok := d.Params[name]
		if !ok || spec.Type != v.Type {
			return nil, ambiguous("param %q is not declared as %s", name, v.Type)
		}
		obj[name] = v.wire()
	}
	raw, err := json.Marshal(obj, json.Deterministic(true))
	if err != nil {
		return nil, ambiguous("params: %v", err)
	}
	if _, err := d.DecodeParams(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func ambiguous(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{actionir.ErrAmbiguous}, args...)...)
}

// DedupeKey computes the semantic dedupe key of an action (HR-007):
// "sha256:" + SHA-256 of the canonical JSON of the operation and the
// declared fields' canonical values. It is empty when the definition
// declares no key. A declared field without a value is ambiguous.
func (d *Definition) DedupeKey(target actionir.Target, vals Values) (string, error) {
	if len(d.Dedupe) == 0 {
		return "", nil
	}
	fields := make(map[string]any, len(d.Dedupe))
	for _, f := range d.Dedupe {
		var v any
		switch f {
		case "target.type":
			v = target.Type
		case "target.id":
			v = target.ID
		case "target.account":
			v = target.Account
		default:
			name, _ := strings.CutPrefix(f, "params.")
			pv, ok := vals[name]
			if !ok || d.Params[name].Type != pv.Type {
				return "", ambiguous("dedupe key field %s has no value", f)
			}
			v = pv.wire()
		}
		if v == "" {
			return "", ambiguous("dedupe key field %s has no value", f)
		}
		fields[f] = v
	}
	raw, err := json.Marshal(map[string]any{"operation": d.Operation, "fields": fields})
	if err != nil {
		return "", ambiguous("dedupe key: %v", err)
	}
	c := jsontext.Value(raw)
	if err := c.Canonicalize(); err != nil {
		return "", ambiguous("dedupe key: %v", err)
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
