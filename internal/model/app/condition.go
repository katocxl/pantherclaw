// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
)

const (
	// maxConditions bounds one rule's or path's conditions.
	maxConditions = 4
	// maxValue bounds a condition's value.
	maxValue = 256
	// maxParams bounds the names a schema offers.
	maxParams = 128
	// envField is the one policy field that is not a parameter.
	envField = "action.env"
	// paramPrefix leads a parameter's policy field.
	paramPrefix = "action.params."
	// noParam stands in a schema's enum when no parameter is offered: an empty
	// enum is not a schema. No parameter has this name.
	noParam = "none"
)

// Param is a parameter a policy condition may read. Params come only from the
// built-in packages' definitions (D316): a parameter of an organization's own
// tool is a record, and is never offered to a model (HR-542).
type Param struct {
	Name string
	Type defs.ParamType
	// Values are an enum's.
	Values []string
}

var paramName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// BuiltinParams lists the parameters of pkgs a condition can compare: a
// parameter whose type differs between definitions is left out, and so are
// free text, commands, content and paths.
func BuiltinParams(pkgs ...*defs.Package) []Param {
	byName := map[string]Param{}
	mixed := map[string]bool{}
	for _, p := range pkgs {
		for i := range p.Definitions {
			for name, spec := range p.Definitions[i].Params {
				if !canCompare(spec.Type) || !paramName.MatchString(name) {
					continue
				}
				prev, seen := byName[name]
				if seen && prev.Type != spec.Type {
					mixed[name] = true
				}
				prev.Name, prev.Type = name, spec.Type
				prev.Values = append(prev.Values, spec.Values...)
				byName[name] = prev
			}
		}
	}
	out := make([]Param, 0, len(byName))
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		if !mixed[name] && len(out) < maxParams {
			p := byName[name]
			slices.Sort(p.Values)
			p.Values = slices.Compact(p.Values)
			out = append(out, p)
		}
	}
	return out
}

func canCompare(t defs.ParamType) bool {
	return slices.Contains([]defs.ParamType{
		defs.TypeMoney, defs.TypeDecimal, defs.TypeInteger, defs.TypeBoolean, defs.TypeEnum, defs.TypeIdentifier,
	}, t)
}

// ordered reports whether a type has an order. CEL refuses one on strings.
func ordered(t defs.ParamType) bool {
	return t == defs.TypeMoney || t == defs.TypeDecimal || t == defs.TypeInteger
}

// Comparisons a condition may use, and their CEL.
var (
	equalityOps = map[string]string{"eq": "==", "ne": "!="}
	orderOps    = map[string]string{"gt": ">", "ge": ">=", "lt": "<", "le": "<="}
)

// opNames lists every comparison, for a schema.
func opNames(sets ...map[string]string) []string {
	var out []string
	for _, set := range sets {
		out = append(out, slices.Collect(maps.Keys(set))...)
	}
	slices.Sort(out)
	return out
}

// plainText reports whether s is one bounded line to compare with.
func plainText(s string) bool {
	return s != "" && len(s) <= maxValue && utf8.ValidString(s) &&
		!strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c == 0x7f })
}

// policyCondition is a condition of a policy rule. A rule's conditions all
// hold; none means it always applies. There is no expression to write: Go
// renders the CEL.
type policyCondition struct {
	Field    string `json:"field"`
	Op       string `json:"op"`
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

// policyFields are the fields a policy condition may read, by field name.
type policyFields map[string]Param

func fieldsOf(params []Param) policyFields {
	out := policyFields{envField: {Type: defs.TypeIdentifier}}
	for _, p := range params {
		out[paramPrefix+p.Name] = p
	}
	return out
}

// names lists the fields, sorted, for a schema.
func (f policyFields) names() []string { return slices.Sorted(maps.Keys(f)) }

// paramNames lists the parameters, sorted, for a schema.
func (f policyFields) paramNames() []string {
	var out []string
	for _, name := range f.names() {
		if p, ok := strings.CutPrefix(name, paramPrefix); ok {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{noParam}
	}
	return out
}

func (f policyFields) hasParam(name string) bool {
	_, ok := f[paramPrefix+name]
	return ok
}

// schema is one condition's.
func (f policyFields) schema() ports.Schema {
	return ports.Object(map[string]ports.Schema{
		"field":    ports.Enum(f.names()),
		"op":       ports.Enum(opNames(equalityOps, orderOps)),
		"value":    ports.Text("the value compared with, of the field's type"),
		"currency": ports.Text("the ISO currency of a money value, otherwise empty"),
	})
}

// literal is the condition's value as a CEL literal of the field's type. A
// value that is not of that type refuses the draft.
func (f Param) literal(value, currency string) (string, bool) {
	if !plainText(value) || (currency != "" && f.Type != defs.TypeMoney) {
		return "", false
	}
	switch f.Type {
	case defs.TypeMoney:
		if _, err := money.ParseMoney(value, currency); err != nil {
			return "", false
		}
		return "money(" + render.CELQuote(value) + ", " + render.CELQuote(currency) + ")", true
	case defs.TypeDecimal:
		if _, err := money.Parse(value); err != nil {
			return "", false
		}
		return "decimal(" + render.CELQuote(value) + ")", true
	case defs.TypeInteger:
		n, err := strconv.ParseInt(value, 10, 64)
		return strconv.FormatInt(n, 10), err == nil
	case defs.TypeBoolean:
		return value, value == "true" || value == "false"
	case defs.TypeEnum:
		return render.CELQuote(value), slices.Contains(f.Values, value)
	case defs.TypeIdentifier:
		return render.CELQuote(value), true
	case defs.TypeIdentifierList, defs.TypeText, defs.TypeCommand, defs.TypeContent, defs.TypePath, defs.TypeQueryFilter:
		return "", false
	}
	return "", false
}

// renderPolicy is a rule's `when`. A parameter may be absent, so each read has
// its guard; a value only ever reaches the expression as a literal.
func (f policyFields) renderPolicy(cs []policyCondition) (string, bool) {
	if len(cs) == 0 {
		return "true", true
	}
	if len(cs) > maxConditions {
		return "", false
	}
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		field, ok := f[c.Field]
		if !ok {
			return "", false
		}
		op, ok := equalityOps[c.Op]
		if !ok && ordered(field.Type) {
			op, ok = orderOps[c.Op]
		}
		if !ok {
			return "", false
		}
		lit, ok := field.literal(c.Value, c.Currency)
		if !ok {
			return "", false
		}
		if field.Name != "" {
			parts = append(parts, "has("+c.Field+")")
		}
		parts = append(parts, c.Field+" "+op+" "+lit)
	}
	return strings.Join(parts, " && "), true
}
