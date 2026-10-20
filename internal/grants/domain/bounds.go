// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds grants and guardrails (envelopes): the authority an
// agent's run may use (F038–F062, BUILD_GUIDE §8 M4). Bounds are a lattice,
// so "child ⊆ parent" is decided exactly when a grant is issued (HR-045),
// and every level is evaluated again at decision time (HR-046). Everything
// here is pure: no I/O, clock or randomness.
package domain

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// ErrInvalid reports a malformed grant, envelope or bounds document.
var ErrInvalid = errors.New("grants: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Bounds limit what a grant or envelope allows. Each field is one dimension
// of a lattice; a nil field means "no restriction at this level" (the other
// levels still apply), while a present but empty one allows nothing.
type Bounds struct {
	// Operations allowed: exact names or prefixes such as payments.*.
	Operations *Ops `json:"operations,omitzero"`
	// Access classes allowed: read, write (F074).
	Access *Match `json:"access,omitzero"`
	// Targets allowed per target type; a type that is not listed is refused.
	Targets *map[string]Match `json:"targets,omitzero"`
	// Accounts allowed for targets that have one.
	Accounts *Match `json:"accounts,omitzero"`
	// Destinations allowed; every destination of an action must match.
	Destinations *Match `json:"destinations,omitzero"`
	// Params bounds material parameters per exact operation. An operation
	// or parameter without an entry is not limited at this level.
	Params map[string]map[string]ParamBound `json:"params,omitzero"`
	// Weekly restricts the time of day and week (UTC).
	Weekly *Weekly `json:"weekly,omitzero"`
	// Scope limits the data a read's answer holds, per exact operation
	// (G0 M14 D11, scope.go).
	Scope map[string]ScopeBound `json:"scope,omitzero"`
}

// ParamBound limits one material parameter; exactly one field is set.
type ParamBound struct {
	// Range bounds integer and decimal parameters.
	Range *Range `json:"range,omitzero"`
	// Max bounds money parameters per currency.
	Max Amounts `json:"max,omitzero"`
	// Values bounds enum, identifier and identifier_list parameters (every
	// item of a list must match).
	Values *Match `json:"values,omitzero"`
}

func (pb ParamBound) kinds() int {
	n := 0
	if pb.Range != nil {
		n++
	}
	if pb.Max != nil {
		n++
	}
	if pb.Values != nil {
		n++
	}
	return n
}

// Validate checks the document's shape. Whether parameters exist and have
// the bounded types is checked against definitions by TypeCheck.
func (b Bounds) Validate() error {
	if b.Operations != nil {
		if err := b.Operations.validate("operations"); err != nil {
			return err
		}
	}
	if b.Access != nil {
		if err := b.Access.validate("access", false); err != nil {
			return err
		}
		for _, a := range b.Access.IDs {
			if a != string(defs.AccessRead) && a != string(defs.AccessWrite) {
				return invalid("access: %q is not read or write", a)
			}
		}
	}
	if b.Targets != nil {
		if len(*b.Targets) > maxEntries {
			return invalid("targets: at most %d target types", maxEntries)
		}
		for typ, m := range *b.Targets {
			if !kindPattern.MatchString(typ) {
				return invalid("targets: %q is not a target type", typ)
			}
			if err := m.validate("targets."+typ, true); err != nil {
				return err
			}
		}
	}
	for name, m := range map[string]*Match{"accounts": b.Accounts, "destinations": b.Destinations} {
		if m != nil {
			if err := m.validate(name, true); err != nil {
				return err
			}
		}
	}
	if len(b.Params) > maxEntries {
		return invalid("params: at most %d operations", maxEntries)
	}
	for op, ps := range b.Params {
		if !validOperation(op) {
			return invalid("params: %q is not an operation", op)
		}
		if len(ps) == 0 || len(ps) > maxEntries {
			return invalid("params.%s: list 1..%d parameters", op, maxEntries)
		}
		for name, pb := range ps {
			if err := pb.validate("params." + op + "." + name); err != nil {
				return err
			}
		}
	}
	if b.Weekly != nil {
		if err := b.Weekly.validate("weekly"); err != nil {
			return err
		}
	}
	return validateScope(b.Scope)
}

func (pb ParamBound) validate(name string) error {
	if pb.kinds() != 1 {
		return invalid("%s: set exactly one of range, max, values", name)
	}
	switch {
	case pb.Range != nil:
		return pb.Range.validate(name)
	case pb.Max != nil:
		return pb.Max.validate(name)
	default:
		return pb.Values.validate(name, true)
	}
}

// WithinError says why a bounds document is not inside another one.
type WithinError struct {
	Dimension string
	Detail    string
}

func (v *WithinError) Error() string { return v.Dimension + ": " + v.Detail }

// Within reports whether b allows nothing that p refuses (b ⊆ p), dimension
// by dimension. It is strict: a dimension that p restricts and b leaves
// open is not within. Call Inherit first to take the parent's dimensions
// for those b does not set.
func (b Bounds) Within(p Bounds) *WithinError {
	if p.Operations != nil {
		if b.Operations == nil {
			return &WithinError{"operations", "unrestricted, but limited to " + fmt.Sprint([]string(*p.Operations))}
		}
		if q, ok := b.Operations.Within(*p.Operations); !ok {
			return &WithinError{"operations", fmt.Sprintf("%q is not allowed; permitted: %v", q, []string(*p.Operations))}
		}
	}
	if v := matchWithin("access", b.Access, p.Access); v != nil {
		return v
	}
	if p.Targets != nil {
		if b.Targets == nil {
			return &WithinError{"targets", "unrestricted, but limited to listed target types"}
		}
		for _, typ := range slices.Sorted(maps.Keys(*b.Targets)) {
			pm, ok := (*p.Targets)[typ]
			if !ok {
				return &WithinError{"targets", fmt.Sprintf("target type %q is not allowed", typ)}
			}
			if q, ok := (*b.Targets)[typ].Within(pm); !ok {
				return &WithinError{"targets." + typ, fmt.Sprintf("%q is not allowed; permitted: %s", q, pm)}
			}
		}
	}
	if v := matchWithin("accounts", b.Accounts, p.Accounts); v != nil {
		return v
	}
	if v := matchWithin("destinations", b.Destinations, p.Destinations); v != nil {
		return v
	}
	for _, op := range slices.Sorted(maps.Keys(p.Params)) {
		for _, name := range slices.Sorted(maps.Keys(p.Params[op])) {
			dim := "params." + op + "." + name
			mine, ok := b.Params[op][name]
			if !ok {
				return &WithinError{dim, "unrestricted, but limited to " + p.Params[op][name].String()}
			}
			if !mine.Within(p.Params[op][name]) {
				return &WithinError{dim, mine.String() + " is wider than " + p.Params[op][name].String()}
			}
		}
	}
	if p.Weekly != nil {
		if b.Weekly == nil {
			return &WithinError{"weekly", "unrestricted, but limited to " + p.Weekly.String()}
		}
		if q, ok := b.Weekly.Within(*p.Weekly); !ok {
			return &WithinError{"weekly", fmt.Sprintf("%s is outside %s", q, p.Weekly)}
		}
	}
	return scopeWithin(b.Scope, p.Scope)
}

func matchWithin(dim string, b, p *Match) *WithinError {
	if p == nil {
		return nil
	}
	if b == nil {
		return &WithinError{dim, "unrestricted, but limited to " + p.String()}
	}
	if q, ok := b.Within(*p); !ok {
		return &WithinError{dim, fmt.Sprintf("%q is not allowed; permitted: %s", q, p)}
	}
	return nil
}

// Within reports whether pb ⊆ p. Bounds of different kinds never nest.
func (pb ParamBound) Within(p ParamBound) bool {
	switch {
	case pb.Range != nil && p.Range != nil:
		return pb.Range.Within(*p.Range)
	case pb.Max != nil && p.Max != nil:
		_, ok := pb.Max.Within(p.Max)
		return ok
	case pb.Values != nil && p.Values != nil:
		_, ok := pb.Values.Within(*p.Values)
		return ok
	}
	return false
}

// Intersect returns pb ∩ p. Bounds of different kinds cannot both hold for
// one parameter type, so their meet allows nothing.
func (pb ParamBound) Intersect(p ParamBound) ParamBound {
	switch {
	case pb.Range != nil && p.Range != nil:
		r := pb.Range.Intersect(*p.Range)
		return ParamBound{Range: &r}
	case pb.Max != nil && p.Max != nil:
		return ParamBound{Max: pb.Max.Intersect(p.Max)}
	case pb.Values != nil && p.Values != nil:
		m := pb.Values.Intersect(*p.Values)
		return ParamBound{Values: &m}
	}
	return ParamBound{Values: &Match{IDs: []string{}, Prefixes: []string{}}}
}

// String renders the bound for explanations.
func (pb ParamBound) String() string {
	switch {
	case pb.Range != nil:
		return pb.Range.String()
	case pb.Max != nil:
		return pb.Max.String()
	case pb.Values != nil:
		return "one of " + pb.Values.String()
	}
	return "nothing"
}

// Inherit returns b with every dimension b leaves open taken from p. A
// delegated grant stores its inherited bounds, so it reads as what the child
// may do and is strictly within its parent.
func (b Bounds) Inherit(p Bounds) Bounds {
	out := b.clone()
	if out.Operations == nil && p.Operations != nil {
		o := slices.Clone(*p.Operations)
		out.Operations = &o
	}
	if out.Access == nil {
		out.Access = cloneMatch(p.Access)
	}
	if out.Targets == nil && p.Targets != nil {
		t := maps.Clone(*p.Targets)
		out.Targets = &t
	}
	if out.Accounts == nil {
		out.Accounts = cloneMatch(p.Accounts)
	}
	if out.Destinations == nil {
		out.Destinations = cloneMatch(p.Destinations)
	}
	for op, ps := range p.Params {
		for name, pb := range ps {
			if _, ok := out.Params[op][name]; ok {
				continue
			}
			if out.Params == nil {
				out.Params = map[string]map[string]ParamBound{}
			}
			if out.Params[op] == nil {
				out.Params[op] = map[string]ParamBound{}
			}
			out.Params[op][name] = pb
		}
	}
	if out.Weekly == nil && p.Weekly != nil {
		w := slices.Clone(*p.Weekly)
		out.Weekly = &w
	}
	out.Scope = inheritScope(out.Scope, p.Scope)
	return out
}

func cloneMatch(m *Match) *Match {
	if m == nil {
		return nil
	}
	c := Match{IDs: slices.Clone(m.IDs), Prefixes: slices.Clone(m.Prefixes)}
	return &c
}

func (b Bounds) clone() Bounds {
	out := b
	if b.Operations != nil {
		o := slices.Clone(*b.Operations)
		out.Operations = &o
	}
	out.Access, out.Accounts, out.Destinations = cloneMatch(b.Access), cloneMatch(b.Accounts), cloneMatch(b.Destinations)
	if b.Targets != nil {
		t := maps.Clone(*b.Targets)
		out.Targets = &t
	}
	if b.Params != nil {
		out.Params = make(map[string]map[string]ParamBound, len(b.Params))
		for op, ps := range b.Params {
			out.Params[op] = maps.Clone(ps)
		}
	}
	if b.Weekly != nil {
		w := slices.Clone(*b.Weekly)
		out.Weekly = &w
	}
	out.Scope = cloneScope(b.Scope)
	return out
}

// Intersect returns the greatest bounds within both b and p (their meet).
// An action passes Intersect(b, p) exactly when it passes b and p.
func (b Bounds) Intersect(p Bounds) Bounds {
	var out Bounds
	switch {
	case b.Operations == nil:
		out.Operations = p.clone().Operations
	case p.Operations == nil:
		out.Operations = b.clone().Operations
	default:
		o := b.Operations.Intersect(*p.Operations)
		out.Operations = &o
	}
	out.Access = intersectMatch(b.Access, p.Access)
	switch {
	case b.Targets == nil:
		out.Targets = p.clone().Targets
	case p.Targets == nil:
		out.Targets = b.clone().Targets
	default:
		t := map[string]Match{}
		for typ, m := range *b.Targets {
			if pm, ok := (*p.Targets)[typ]; ok {
				t[typ] = m.Intersect(pm)
			}
		}
		out.Targets = &t
	}
	out.Accounts = intersectMatch(b.Accounts, p.Accounts)
	out.Destinations = intersectMatch(b.Destinations, p.Destinations)
	out.Params = b.clone().Params
	for op, ps := range p.Params {
		for name, pb := range ps {
			if out.Params == nil {
				out.Params = map[string]map[string]ParamBound{}
			}
			if out.Params[op] == nil {
				out.Params[op] = map[string]ParamBound{}
			}
			if mine, ok := out.Params[op][name]; ok {
				out.Params[op][name] = mine.Intersect(pb)
			} else {
				out.Params[op][name] = pb
			}
		}
	}
	switch {
	case b.Weekly == nil:
		out.Weekly = p.clone().Weekly
	case p.Weekly == nil:
		out.Weekly = b.clone().Weekly
	default:
		w := b.Weekly.Intersect(*p.Weekly)
		out.Weekly = &w
	}
	out.Scope = intersectScope(b.Scope, p.Scope)
	return out
}

func intersectMatch(a, b *Match) *Match {
	switch {
	case a == nil:
		return cloneMatch(b)
	case b == nil:
		return cloneMatch(a)
	}
	m := a.Intersect(*b)
	return &m
}

// Action is what bounds are checked against: the canonical action with its
// typed material parameters, and the decision time (database clock).
type Action struct {
	Operation  string
	Access     defs.Access
	TargetType string
	TargetID   string
	Account    string
	// AccountDeclared is set when the definition's target has an account
	// (required or optional); account bounds apply only then.
	AccountDeclared bool
	Destinations    []string
	Params          defs.Values
	Time            time.Time
}

// Outcome of checking one bounds document.
type Outcome int

// Outcomes. Unknown means the bound cannot be checked (an absent or
// differently typed parameter): CANNOT_AUTHORIZE, never a default (HR-103).
const (
	Allowed Outcome = iota
	Denied
	Unknown
)

// Finding is the result of a check, with the dimension that decided and an
// explanation naming the offending value and what is permitted (F079).
type Finding struct {
	Outcome   Outcome
	Dimension string
	Detail    string
	// Code, when set, is the reason code (budgets and counters).
	Code string
}

func allowed() Finding { return Finding{Outcome: Allowed} }

func denied(dim, format string, args ...any) Finding {
	return Finding{Outcome: Denied, Dimension: dim, Detail: fmt.Sprintf(format, args...)}
}

// CheckCoverage checks what the action touches: operation, access class,
// target and account (pipeline step 4).
func (b Bounds) CheckCoverage(a Action) Finding {
	if b.Operations != nil && !b.Operations.Matches(a.Operation) {
		return denied("operations", "%s is not granted; permitted: %v", a.Operation, []string(*b.Operations))
	}
	if b.Access != nil && !b.Access.Matches(string(a.Access)) {
		return denied("access", "%s access is not granted; permitted: %s", a.Access, b.Access)
	}
	if b.Targets != nil {
		m, ok := (*b.Targets)[a.TargetType]
		if !ok {
			return denied("targets", "target type %s is not granted", a.TargetType)
		}
		if !m.Matches(a.TargetID) {
			return denied("targets."+a.TargetType, "target %s is not granted; permitted: %s", a.TargetID, m)
		}
	}
	if b.Accounts != nil && a.AccountDeclared {
		if a.Account == "" {
			// The target may fall back to a default account, which cannot be
			// shown to be inside the bound (HR-103).
			return Finding{Outcome: Unknown, Dimension: "accounts", Detail: "the action names no account to check"}
		}
		if !b.Accounts.Matches(a.Account) {
			return denied("accounts", "account %s is not granted; permitted: %s", a.Account, b.Accounts)
		}
	}
	return allowed()
}

// CheckLimits checks how the action uses its coverage: parameters,
// destinations and time (pipeline step 7).
func (b Bounds) CheckLimits(a Action) Finding {
	ps := b.Params[a.Operation]
	for _, name := range slices.Sorted(maps.Keys(ps)) {
		if f := ps[name].check("params."+name, a.Params, name); f.Outcome != Allowed {
			return f
		}
	}
	if b.Destinations != nil {
		for _, d := range a.Destinations {
			if !b.Destinations.Matches(d) {
				return denied("destinations", "destination %s is not granted; permitted: %s", d, b.Destinations)
			}
		}
	}
	if b.Weekly != nil && !b.Weekly.Contains(MinuteOfWeek(a.Time)) {
		return denied("weekly", "%s is outside the permitted times: %s", a.Time.UTC().Format("Mon 15:04 UTC"), b.Weekly)
	}
	return allowed()
}

// Check runs CheckCoverage then CheckLimits.
func (b Bounds) Check(a Action) Finding {
	if f := b.CheckCoverage(a); f.Outcome != Allowed {
		return f
	}
	return b.CheckLimits(a)
}

func (pb ParamBound) check(dim string, vals defs.Values, name string) Finding {
	v, ok := vals[name]
	if !ok {
		return Finding{Outcome: Unknown, Dimension: dim, Detail: "the parameter is absent, so its bound cannot be checked"}
	}
	mismatch := Finding{Outcome: Unknown, Dimension: dim, Detail: fmt.Sprintf("a %s parameter cannot be checked against %s", v.Type, pb)}
	switch {
	case pb.Range != nil:
		var d money.Decimal
		switch v.Type { //nolint:exhaustive // only numeric types fit a range
		case defs.TypeInteger:
			n, err := money.FromInt(v.Int)
			if err != nil {
				return mismatch
			}
			d = n
		case defs.TypeDecimal:
			d = v.Decimal
		default:
			return mismatch
		}
		if !pb.Range.Contains(d) {
			return denied(dim, "%s exceeds the bound; permitted: %s", d, pb.Range)
		}
	case pb.Max != nil:
		if v.Type != defs.TypeMoney {
			return mismatch
		}
		if !pb.Max.Contains(v.Money) {
			return denied(dim, "%s exceeds the bound; permitted: %s", v.Money, pb.Max)
		}
	case pb.Values != nil:
		var items []string
		switch v.Type { //nolint:exhaustive // only identifier-like types fit an allowlist
		case defs.TypeEnum, defs.TypeIdentifier:
			items = []string{v.Str}
		case defs.TypeIdentifierList:
			items = v.List
		default:
			return mismatch
		}
		for _, it := range items {
			if !pb.Values.Matches(it) {
				return denied(dim, "%s is not allowed; permitted: %s", it, pb.Values)
			}
		}
	default:
		return mismatch
	}
	return allowed()
}
