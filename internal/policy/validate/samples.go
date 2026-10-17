// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package validate

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Sample bounds (D8): generated actions per operation and per run.
const (
	MaxSamplesPerOperation = 256
	MaxSamples             = 4096
)

// Fixed ids of every sample: the run, its agent and the default
// environment. Literal UUIDs in conditions become sample agents and
// environments too.
var (
	sampleRun   = "00000000-0000-7000-8000-0000000000c1"
	sampleAgent = "00000000-0000-7000-8000-0000000000a1"
	sampleEnv   = "00000000-0000-7000-8000-0000000000e1"
	sampleIDs   = map[string]string{
		"org": "00000000-0000-7000-8000-000000000001", "action": "00000000-0000-7000-8000-0000000000d1",
		"instance": "00000000-0000-7000-8000-0000000000b1",
	}
)

// sample is one generated action with what it is evaluated with.
type sample struct {
	def    *defs.Definition
	action actionir.ActionIR
	in     papp.Input
}

// example is the sample's action as JSON, for a finding.
func (s sample) example() jsontext.Value {
	raw, err := json.Marshal(s.action, json.Deterministic(true))
	if err != nil {
		return nil
	}
	return raw
}

// literals are the values the conditions and constraints of some rules
// compare against.
type literals struct {
	money   []moneyLit
	ints    []int64
	decs    []string
	strs    []string
	envs    []string
	targets []string
	dests   []string
	values  map[string][]string // allowed_values per param
}

type moneyLit struct{ amount, currency string }

// collect gathers the literals of rules: comparison constants and money()
// literals in conditions, constraint limits and value sets, environments.
func collect(rules []pdomain.Rule) literals {
	l := literals{values: map[string][]string{}}
	env, err := cel.NewEnv()
	if err != nil {
		return l
	}
	for i := range rules {
		r := &rules[i]
		l.envs = append(l.envs, r.Environments...)
		if c := r.Constraint; c != nil {
			switch c.Kind { //nolint:exhaustive // verify has no value to sample
			case pdomain.AmountMax:
				if c.Currency != "" {
					l.money = append(l.money, moneyLit{c.Max, c.Currency})
				} else {
					l.decs = append(l.decs, c.Max)
				}
			case pdomain.CountMax:
				if n, err := strconv.ParseInt(c.Max, 10, 64); err == nil {
					l.ints = append(l.ints, n)
				}
			case pdomain.AllowedValues:
				l.values[c.Param] = append(l.values[c.Param], c.Values...)
			case pdomain.TargetSet:
				l.targets = append(l.targets, c.Values...)
			case pdomain.DestinationSet:
				l.dests = append(l.dests, c.Values...)
			}
		}
		a, iss := env.Parse(r.When)
		if iss.Err() != nil {
			continue
		}
		ast.PreOrderVisit(a.NativeRep().Expr(), ast.NewExprVisitor(func(e ast.Expr) {
			switch e.Kind() { //nolint:exhaustive // only constants and money() calls carry literals
			case ast.LiteralKind:
				switch v := e.AsLiteral().(type) {
				case types.Int:
					l.ints = append(l.ints, int64(v))
				case types.Uint:
					l.ints = append(l.ints, int64(v)) //nolint:gosec // a literal in a condition
				case types.Double:
					l.decs = append(l.decs, strconv.FormatFloat(float64(v), 'f', -1, 64))
				case types.String:
					l.strs = append(l.strs, string(v))
				}
			case ast.CallKind:
				call := e.AsCall()
				args := call.Args()
				if call.FunctionName() != "money" || len(args) != 2 || args[0].Kind() != ast.LiteralKind || args[1].Kind() != ast.LiteralKind {
					return
				}
				amt, ok1 := args[0].AsLiteral().(types.String)
				cur, ok2 := args[1].AsLiteral().(types.String)
				if ok1 && ok2 {
					l.money = append(l.money, moneyLit{string(amt), string(cur)})
				}
			}
		}))
	}
	return l
}

// around returns d−unit, d and d+unit, as decimal strings at d's scale (at
// least minScale digits).
func around(s string, minScale int) []string {
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil
	}
	scale := minScale
	if i := strings.IndexByte(s, '.'); i >= 0 && len(s)-i-1 > scale {
		scale = len(s) - i - 1
	}
	unit := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil))
	var out []string
	for _, x := range []*big.Rat{new(big.Rat).Sub(r, unit), r, new(big.Rat).Add(r, unit)} {
		out = append(out, x.FloatString(scale))
	}
	return out
}

// generator builds the samples of one run.
type generator struct {
	lit     literals
	catalog map[string]fdomain.Type
	now     time.Time
	budget  uint64
	total   int
}

// samples returns the samples of one operation: a base action, then the
// base with one dimension changed at a time, as many as fit the bounds.
// facts are the facts the rules on the operation may read.
func (g *generator) samples(d *defs.Definition, facts []string) []sample {
	base := g.baseValues(d)
	baseFacts := map[string]fdomain.Value{}
	for _, f := range facts {
		if v, ok := g.factValue(g.catalog[f], ""); ok {
			baseFacts[f] = v
		}
	}
	var out []sample
	seen := map[string]bool{}
	add := func(vals defs.Values, edit func(*sample)) {
		if len(out) >= MaxSamplesPerOperation || g.total >= MaxSamples {
			return
		}
		raw, err := d.EncodeParams(vals)
		if err != nil {
			return
		}
		if _, err := d.DecodeParams(raw); err != nil {
			return
		}
		s := sample{def: d, action: actionir.ActionIR{
			V: actionir.Version, Org: sampleIDs["org"], Env: sampleEnv, RunID: sampleRun, ActionID: sampleIDs["action"],
			AgentInstance: sampleIDs["instance"], Operation: d.Operation,
			Definition: actionir.Definition{Package: "policy-sample", Version: "0.0.0", Digest: d.Digest},
			Channel:    "sdk", Route: "sample", Target: actionir.Target{Type: d.Target.Type, ID: "sample-target"},
			Params: raw, Destinations: []actionir.Destination{},
		}, in: papp.Input{
			Budget: g.budget, Facts: maps.Clone(baseFacts), Now: g.now, Run: &papp.Run{ID: sampleRun, AgentID: sampleAgent},
		}}
		if edit != nil {
			edit(&s)
		}
		key := string(s.example()) + factsKey(s.in) + s.in.Run.AgentID + s.in.DestinationClass
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, s)
		g.total++
	}
	add(base, nil)
	for _, name := range slices.Sorted(maps.Keys(d.Params)) {
		for _, v := range g.paramVariants(name, d.Params[name]) {
			vals := maps.Clone(base)
			vals[name] = v
			add(vals, nil)
		}
	}
	for _, t := range append(slices.Clone(g.lit.targets), g.lit.strs...) {
		add(base, func(s *sample) { s.action.Target.ID = t })
	}
	for _, dst := range g.lit.dests {
		add(base, func(s *sample) { s.action.Destinations = []actionir.Destination{{Kind: "service", ID: dst}} })
	}
	for _, e := range g.lit.envs {
		add(base, func(s *sample) { s.action.Env = e })
	}
	for _, c := range []string{"public", "internal"} {
		add(base, func(s *sample) { s.in.DestinationClass = c })
	}
	for _, str := range g.lit.strs {
		if _, err := ids.ParseUUID(str); err == nil {
			add(base, func(s *sample) { s.in.Run = &papp.Run{ID: sampleRun, AgentID: str} })
		}
	}
	for _, f := range facts {
		for _, v := range g.factVariants(g.catalog[f]) {
			add(base, func(s *sample) { s.in.Facts[f] = v })
		}
	}
	return out
}

func factsKey(in papp.Input) string {
	var sb strings.Builder
	for _, k := range slices.Sorted(maps.Keys(in.Facts)) {
		sb.WriteString(k + "=" + in.Facts[k].String() + ";")
	}
	return sb.String()
}

// baseValues are a valid value for every required param.
func (g *generator) baseValues(d *defs.Definition) defs.Values {
	vals := defs.Values{}
	for name, p := range d.Params {
		if !p.Required {
			continue
		}
		if v, ok := g.defaultValue(name, p); ok {
			vals[name] = v
		}
	}
	return vals
}

func (g *generator) defaultValue(name string, p defs.ParamSpec) (defs.Value, bool) {
	switch p.Type { //nolint:exhaustive // the rest are strings
	case defs.TypeMoney:
		cur := "USD"
		if len(p.Currencies) > 0 {
			cur = p.Currencies[0]
		}
		m, err := money.ParseMoney("1", cur)
		return defs.Value{Type: p.Type, Money: m}, err == nil
	case defs.TypeDecimal:
		d, err := money.Parse(cmpOr(p.Min, "1"))
		return defs.Value{Type: p.Type, Decimal: d}, err == nil
	case defs.TypeInteger:
		n, err := strconv.ParseInt(cmpOr(p.Min, "1"), 10, 64)
		return defs.Value{Type: p.Type, Int: n}, err == nil
	case defs.TypeEnum:
		if len(p.Values) == 0 {
			return defs.Value{}, false
		}
		return defs.Value{Type: p.Type, Str: p.Values[0]}, true
	case defs.TypeBoolean:
		return defs.Value{Type: p.Type}, true
	case defs.TypeIdentifierList:
		return defs.Value{Type: p.Type, List: []string{cmpOr(first(g.lit.values[name]), "sample")}}, true
	case defs.TypeQueryFilter:
		return defs.Value{Type: p.Type, Filter: []defs.Predicate{}}, true
	}
	return defs.Value{Type: p.Type, Str: cmpOr(first(g.lit.values[name]), "sample")}, true
}

// paramVariants are the boundary and set values a param is sampled with.
func (g *generator) paramVariants(name string, p defs.ParamSpec) []defs.Value {
	var out []defs.Value
	switch p.Type { //nolint:exhaustive // the rest are strings
	case defs.TypeMoney:
		for _, m := range g.lit.money {
			if len(p.Currencies) > 0 && !slices.Contains(p.Currencies, m.currency) {
				continue
			}
			units, err := money.Currency(m.currency).MinorUnits()
			if err != nil {
				continue
			}
			for _, a := range around(m.amount, units) {
				if v, err := money.ParseMoney(a, m.currency); err == nil {
					out = append(out, defs.Value{Type: p.Type, Money: v})
				}
			}
		}
	case defs.TypeDecimal:
		for _, s := range g.lit.decs {
			for _, a := range around(s, 0) {
				if v, err := money.Parse(a); err == nil {
					out = append(out, defs.Value{Type: p.Type, Decimal: v})
				}
			}
		}
		for _, n := range g.lit.ints {
			for _, a := range []int64{n - 1, n, n + 1} {
				if v, err := money.FromInt(a); err == nil {
					out = append(out, defs.Value{Type: p.Type, Decimal: v})
				}
			}
		}
	case defs.TypeInteger:
		for _, n := range g.lit.ints {
			for _, a := range []int64{n - 1, n, n + 1} {
				out = append(out, defs.Value{Type: p.Type, Int: a})
			}
		}
	case defs.TypeEnum:
		for _, v := range p.Values {
			out = append(out, defs.Value{Type: p.Type, Str: v})
		}
	case defs.TypeBoolean:
		out = append(out, defs.Value{Type: p.Type, Bool: true}, defs.Value{Type: p.Type})
	case defs.TypeIdentifierList:
		for _, s := range append(slices.Clone(g.lit.values[name]), "outside-value") {
			out = append(out, defs.Value{Type: p.Type, List: []string{s}})
		}
	case defs.TypeQueryFilter:
		out = append(out, defs.Value{Type: p.Type, Filter: []defs.Predicate{}})
	default:
		for _, s := range append(append(slices.Clone(g.lit.values[name]), "outside-value"), g.lit.strs...) {
			out = append(out, defs.Value{Type: p.Type, Str: s})
		}
	}
	return out
}

// factValue is a fact's base value (lit empty) or the value of a literal.
func (g *generator) factValue(t fdomain.Type, lit string) (fdomain.Value, bool) {
	switch t { //nolint:exhaustive // objects are left missing
	case fdomain.TypeBoolean:
		return fdomain.Value{Type: t, Bool: true}, true
	case fdomain.TypeInteger:
		n, err := strconv.ParseInt(cmpOr(lit, "1"), 10, 64)
		return fdomain.Value{Type: t, Int: n}, err == nil
	case fdomain.TypeTimestamp:
		if lit == "" {
			return fdomain.Value{Type: t, Int: g.now.Add(-time.Hour).Unix()}, true
		}
		n, err := strconv.ParseInt(lit, 10, 64)
		return fdomain.Value{Type: t, Int: n}, err == nil
	case fdomain.TypeDecimal:
		d, err := money.Parse(cmpOr(lit, "1"))
		return fdomain.Value{Type: t, Decimal: d}, err == nil
	case fdomain.TypeIdentifier:
		return fdomain.Value{Type: t, Str: cmpOr(lit, "sample")}, true
	case fdomain.TypeMoney:
		m, err := money.ParseMoney("1", "USD")
		return fdomain.Value{Type: t, Money: m}, err == nil
	}
	return fdomain.Value{}, false
}

// factVariants are a fact's literal values.
func (g *generator) factVariants(t fdomain.Type) []fdomain.Value {
	var out []fdomain.Value
	switch t { //nolint:exhaustive // objects are left missing
	case fdomain.TypeBoolean:
		out = append(out, fdomain.Value{Type: t})
	case fdomain.TypeInteger, fdomain.TypeTimestamp:
		for _, n := range g.lit.ints {
			for _, a := range []int64{n - 1, n, n + 1} {
				out = append(out, fdomain.Value{Type: t, Int: a})
			}
		}
	case fdomain.TypeDecimal:
		for _, s := range g.lit.decs {
			for _, a := range around(s, 0) {
				if v, ok := g.factValue(t, a); ok {
					out = append(out, v)
				}
			}
		}
	case fdomain.TypeMoney:
		for _, m := range g.lit.money {
			units, err := money.Currency(m.currency).MinorUnits()
			if err != nil {
				continue
			}
			for _, a := range around(m.amount, units) {
				if v, err := money.ParseMoney(a, m.currency); err == nil {
					out = append(out, fdomain.Value{Type: t, Money: v})
				}
			}
		}
	case fdomain.TypeIdentifier:
		for _, s := range g.lit.strs {
			out = append(out, fdomain.Value{Type: t, Str: s})
		}
	}
	return out
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
