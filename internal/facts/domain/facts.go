// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds trusted facts (HR-160, F085, F120–F126): what the
// system of record says about a target (a charge is refundable, a branch is
// protected, a backup was verified), who may say it, and for how long it
// counts as current. A fact is accepted only from the provider registered
// for its name; nothing a workload sends is ever a fact. Everything here is
// pure: the caller passes the database clock.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Errors.
var (
	// ErrInvalid reports a malformed provider, declaration or observation.
	ErrInvalid = errors.New("facts: invalid")
	// ErrUntrusted reports an observation its sender may not make: an
	// unregistered or disabled provider, or a fact it is not registered for.
	ErrUntrusted = errors.New("facts: untrusted source")
	// ErrStale reports an observation that is too old to record, or older
	// than the one already recorded.
	ErrStale = errors.New("facts: stale observation")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Type is the type of a fact's value. Times are integers (Unix seconds),
// so policies compare them with `now` without a separate time type.
type Type string

// Value types.
const (
	TypeBoolean    Type = "boolean"
	TypeInteger    Type = "integer"
	TypeDecimal    Type = "decimal"
	TypeMoney      Type = "money"
	TypeIdentifier Type = "identifier"
	TypeTimestamp  Type = "timestamp"
)

var types = []Type{TypeBoolean, TypeInteger, TypeDecimal, TypeMoney, TypeIdentifier, TypeTimestamp, TypeObject}

// Limits.
const (
	MaxFactsPerProvider = 64
	MaxLagCeiling       = 24 * time.Hour
	// MaxSkew is how far in the future an observation may claim to be (a
	// provider clock slightly ahead); it is recorded at the database time.
	MaxSkew       = 5 * time.Second
	maxValueBytes = 1024
)

var (
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$`)
	typePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,7}$`)
)

// ValidName reports whether s is a valid fact name, such as
// payments.charge.refundable.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// CELName is the name of a fact in policy conditions: dots become
// underscores, so payments.charge.refundable is
// facts.payments_charge_refundable.
func CELName(name string) string { return strings.ReplaceAll(name, ".", "_") }

// Declaration is one fact a provider may write.
type Declaration struct {
	Name string
	Type Type
	// SubjectType is the target type the fact is about (payments.charge).
	SubjectType string
	// MaxLag is how old an observation may be when it is recorded.
	MaxLag time.Duration
	// Kind is a value or a classification (G0 M16 D80); empty is a value.
	Kind Kind
}

// ProviderState is a provider's state.
type ProviderState string

// Provider states. A disabled provider's facts stop counting at once.
const (
	ProviderActive   ProviderState = "ACTIVE"
	ProviderDisabled ProviderState = "DISABLED"
)

// Provider is a registered source of facts. In M4 a provider pushes facts
// through the API, authenticated as its service account; pull providers
// (reads through a connection) arrive with connections in M6.
type Provider struct {
	ID               ids.UUID
	Org              ids.OrgID
	Name             string
	ServiceAccountID ids.UUID
	// GatewayID and ConnectionID bind a provider to the gateway that reads
	// a connection's system of record (G0 M8): a provider has exactly one
	// of a service account or a gateway and connection.
	GatewayID    ids.UUID
	ConnectionID ids.UUID
	// Builtin marks PantherClaw's own provider, pc.signals (G0 M16 D82): it
	// has neither a service account nor a gateway.
	Builtin bool
	State   ProviderState
	Facts   []Declaration
}

// Validate checks a provider. taken reports fact names (and their policy
// names) another active provider already declares: each name has one
// provider.
func (p Provider) Validate(taken func(name string) bool) error {
	switch {
	case p.ID.IsZero() || p.Org.IsZero() || !p.validSources():
		return invalid("provider: id, org and exactly one of a service account or a gateway and connection are required")
	case !typePattern.MatchString(p.Name):
		return invalid("provider: name %q must be a lowercase dotted name", p.Name)
	case len(p.Facts) == 0 || len(p.Facts) > MaxFactsPerProvider:
		return invalid("provider: declare 1..%d facts", MaxFactsPerProvider)
	case p.State != ProviderActive && p.State != ProviderDisabled:
		return invalid("provider: unknown state %q", p.State)
	}
	seen := map[string]bool{}
	for _, d := range p.Facts {
		switch {
		case !namePattern.MatchString(d.Name):
			return invalid("provider: fact name %q must be a dotted name such as payments.charge.refundable", d.Name)
		case seen[CELName(d.Name)]:
			return invalid("provider: fact %q is declared twice (names are compared with dots as underscores)", d.Name)
		case taken != nil && taken(d.Name):
			return invalid("provider: another provider already supplies %q", d.Name)
		case !slices.Contains(types, d.Type):
			return invalid("provider: fact %q has unknown type %q", d.Name, d.Type)
		case !typePattern.MatchString(d.SubjectType):
			return invalid("provider: fact %q needs a subject type", d.Name)
		case d.MaxLag < time.Second || d.MaxLag > MaxLagCeiling:
			return invalid("provider: fact %q needs a maximum lag of 1s..%s", d.Name, MaxLagCeiling)
		}
		if err := p.validDeclaration(d); err != nil {
			return err
		}
		seen[CELName(d.Name)] = true
	}
	return nil
}

// Declares returns the provider's declaration of a fact.
func (p Provider) Declares(name string) (Declaration, bool) {
	i := slices.IndexFunc(p.Facts, func(d Declaration) bool { return d.Name == name })
	if i < 0 {
		return Declaration{}, false
	}
	return p.Facts[i], true
}

// Value is a typed fact value.
type Value struct {
	Type    Type
	Bool    bool
	Int     int64 // integer, timestamp (Unix seconds)
	Decimal money.Decimal
	Money   money.Money
	Str     string // identifier
	// Object holds an object fact's members (strings, int64, bool, []any,
	// map[string]any).
	Object map[string]any
}

// valueJSON is the wire form: amounts and integers are strings (HR-101).
type valueJSON struct {
	Bool     *bool          `json:"bool,omitzero"`
	Int      string         `json:"int,omitzero"`
	Decimal  string         `json:"decimal,omitzero"`
	Amount   string         `json:"amount,omitzero"`
	Currency string         `json:"currency,omitzero"`
	ID       string         `json:"id,omitzero"`
	Time     string         `json:"time,omitzero"`
	Object   jsontext.Value `json:"object,omitzero"`
}

var intPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,17})$`)

// DecodeValue strictly decodes a value of type t.
func DecodeValue(t Type, raw jsontext.Value) (Value, error) {
	limit := maxValueBytes
	if t == TypeObject {
		limit = maxObjectBytes + 64
	}
	if len(raw) == 0 || len(raw) > limit {
		return Value{}, invalid("value: size %d outside 1..%d bytes", len(raw), limit)
	}
	var w valueJSON
	if err := json.Unmarshal(raw, &w, json.RejectUnknownMembers(true)); err != nil {
		return Value{}, invalid("value: %v", err)
	}
	v := Value{Type: t}
	only := func(set bool) error {
		n := 0
		for _, f := range []bool{w.Bool != nil, w.Int != "", w.Decimal != "", w.Amount != "" || w.Currency != "", w.ID != "", w.Time != "", len(w.Object) > 0} {
			if f {
				n++
			}
		}
		if !set || n != 1 {
			return invalid("value: a %s fact carries exactly its own field", t)
		}
		return nil
	}
	switch t {
	case TypeBoolean:
		if err := only(w.Bool != nil); err != nil {
			return Value{}, err
		}
		v.Bool = *w.Bool
	case TypeInteger:
		n, err := strconv.ParseInt(w.Int, 10, 64)
		if err := only(err == nil && intPattern.MatchString(w.Int)); err != nil {
			return Value{}, err
		}
		v.Int = n
	case TypeDecimal:
		d, err := money.Parse(w.Decimal)
		if err := only(err == nil); err != nil {
			return Value{}, err
		}
		v.Decimal = d
	case TypeMoney:
		m, err := money.ParseMoney(w.Amount, w.Currency)
		if err := only(err == nil); err != nil {
			return Value{}, err
		}
		v.Money = m
	case TypeIdentifier:
		if err := only(actionir.CheckIdentifier("id", w.ID) == nil); err != nil {
			return Value{}, err
		}
		v.Str = w.ID
	case TypeTimestamp:
		ts, err := time.Parse(time.RFC3339, w.Time)
		if err := only(err == nil); err != nil {
			return Value{}, err
		}
		v.Int = ts.Unix()
	case TypeObject:
		if err := only(len(w.Object) > 0); err != nil {
			return Value{}, err
		}
		obj, err := decodeObject(w.Object)
		if err != nil {
			return Value{}, err
		}
		v.Object = obj
	default:
		return Value{}, invalid("value: unknown type %q", t)
	}
	return v, nil
}

// String renders the value for explanations and digests.
func (v Value) String() string {
	switch v.Type {
	case TypeBoolean:
		return fmt.Sprint(v.Bool)
	case TypeInteger:
		return fmt.Sprint(v.Int)
	case TypeTimestamp:
		return time.Unix(v.Int, 0).UTC().Format(time.RFC3339)
	case TypeDecimal:
		return v.Decimal.String()
	case TypeMoney:
		return v.Money.String()
	case TypeIdentifier:
		return v.Str
	case TypeObject:
		b, _ := json.Marshal(v.Object, json.Deterministic(true))
		return string(b)
	}
	return ""
}

// Fact is one recorded observation.
type Fact struct {
	Name        string
	SubjectType string
	SubjectID   string
	Value       Value
	ObservedAt  time.Time
	RecordedAt  time.Time
	ProviderID  ids.UUID
	// Source and Method are its provenance (G0 M16 D80), when sent.
	Source, Method string
}

// Observation is what a provider sends.
type Observation struct {
	Name        string
	SubjectType string
	SubjectID   string
	Value       jsontext.Value
	ObservedAt  time.Time
	// Source and Method are its provenance (G0 M16 D80): both or neither,
	// and both for a classification (HR-435).
	Source, Method string
}

// Accept turns an observation into a fact (HR-160). The provider must be
// active and registered for the fact; the subject must have the declared
// type; the value must decode to the declared type; the observation may be
// neither in the future (beyond MaxSkew, and it is recorded at now) nor
// older than the declared lag; and it may not be older than the fact
// already recorded (prev, nil if none).
func Accept(p Provider, o Observation, now time.Time, prev *Fact) (Fact, error) {
	if p.State != ProviderActive {
		return Fact{}, fmt.Errorf("%w: provider %s is disabled", ErrUntrusted, p.Name)
	}
	d, ok := p.Declares(o.Name)
	if !ok {
		return Fact{}, fmt.Errorf("%w: provider %s is not registered for %q", ErrUntrusted, p.Name, o.Name)
	}
	if o.SubjectType != d.SubjectType {
		return Fact{}, invalid("%s is about %s, not %s", o.Name, d.SubjectType, o.SubjectType)
	}
	if err := actionir.CheckIdentifier("subject", o.SubjectID); err != nil {
		return Fact{}, invalid("subject id: %v", err)
	}
	if err := checkProvenance(d, o); err != nil {
		return Fact{}, err
	}
	v, err := DecodeValue(d.Type, o.Value)
	if err != nil {
		return Fact{}, err
	}
	if err := checkClass(d, v); err != nil {
		return Fact{}, err
	}
	observed := o.ObservedAt.UTC()
	switch {
	case observed.After(now.Add(MaxSkew)):
		return Fact{}, invalid("%s: observed at %s, after the database time %s", o.Name, observed.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	case observed.After(now):
		observed = now.UTC()
	case now.Sub(observed) > d.MaxLag:
		return Fact{}, fmt.Errorf("%w: %s was observed %s ago; at most %s is accepted", ErrStale, o.Name, now.Sub(observed).Round(time.Second), d.MaxLag)
	}
	if prev != nil && observed.Before(prev.ObservedAt) {
		return Fact{}, fmt.Errorf("%w: a newer observation of %s is already recorded", ErrStale, o.Name)
	}
	return Fact{
		Name: o.Name, SubjectType: o.SubjectType, SubjectID: o.SubjectID, Value: v, ObservedAt: observed, RecordedAt: now.UTC(), ProviderID: p.ID,
		Source: o.Source, Method: o.Method,
	}, nil
}

// Requirement is a fact an action needs, with its maximum age and who asks
// for it (a definition prerequisite or a policy rule).
type Requirement struct {
	Name   string
	MaxAge time.Duration
	Source string
}

// Merge combines requirements: one per fact, with the strictest age.
func Merge(rs []Requirement) []Requirement {
	by := map[string]Requirement{}
	for _, r := range rs {
		if cur, ok := by[r.Name]; ok {
			r.MaxAge = min(r.MaxAge, cur.MaxAge)
			r.Source = cur.Source + ", " + r.Source
		}
		by[r.Name] = r
	}
	out := make([]Requirement, 0, len(by))
	for _, n := range slices.Sorted(maps.Keys(by)) {
		out = append(out, by[n])
	}
	return out
}

// Status is how one requirement stands.
type Status int

// Statuses: a missing or stale fact makes the decision CANNOT_AUTHORIZE.
const (
	Present Status = iota
	Missing
	Stale
)

// Check is the result for one requirement.
type Check struct {
	Requirement Requirement
	Status      Status
	Fact        *Fact
	Age         time.Duration
	// Unread is why a fact its provider could not read is missing.
	Unread string
}

// Reason codes.
const (
	ReasonFactMissing = "FACT_MISSING"
	ReasonFactStale   = "FACT_STALE"
)

// Evaluate checks each requirement against the facts recorded about the
// action's target (by name), at now (pipeline step 6). Facts of disabled
// providers must already be left out by the caller.
func Evaluate(rs []Requirement, recorded map[string]Fact, now time.Time) []Check {
	var out []Check
	for _, r := range Merge(rs) {
		f, ok := recorded[r.Name]
		if !ok {
			out = append(out, Check{Requirement: r, Status: Missing})
			continue
		}
		if why, unread := f.Value.Unread(); unread {
			out = append(out, Check{Requirement: r, Status: Missing, Unread: why})
			continue
		}
		age := now.Sub(f.ObservedAt)
		c := Check{Requirement: r, Status: Present, Fact: &f, Age: age}
		if age > r.MaxAge {
			c.Status = Stale
		}
		out = append(out, c)
	}
	return out
}

// Digest is the SHA-256 of the canonical list of facts a decision used:
// name, subject, value, observation time and provider (F080).
func Digest(used []Fact) string {
	type row struct {
		Name     string `json:"name"`
		Subject  string `json:"subject"`
		Value    string `json:"value"`
		Observed int64  `json:"observed"`
		Provider string `json:"provider"`
	}
	rows := make([]row, 0, len(used))
	for _, f := range used {
		rows = append(rows, row{f.Name, f.SubjectType + ":" + f.SubjectID, string(f.Value.Type) + ":" + f.Value.String(), f.ObservedAt.Unix(), f.ProviderID.String()})
	}
	slices.SortFunc(rows, func(a, b row) int { return strings.Compare(a.Name+"\x00"+a.Subject, b.Name+"\x00"+b.Subject) })
	b, _ := json.Marshal(rows, json.Deterministic(true))
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EncodeValue writes a value in its wire form (DecodeValue reads it back).
func EncodeValue(v Value) ([]byte, error) {
	var w valueJSON
	switch v.Type {
	case TypeBoolean:
		b := v.Bool
		w.Bool = &b
	case TypeInteger:
		w.Int = strconv.FormatInt(v.Int, 10)
	case TypeDecimal:
		w.Decimal = v.Decimal.String()
	case TypeMoney:
		w.Amount, w.Currency = v.Money.Amount.String(), string(v.Money.Currency)
	case TypeIdentifier:
		w.ID = v.Str
	case TypeTimestamp:
		w.Time = time.Unix(v.Int, 0).UTC().Format(time.RFC3339)
	case TypeObject:
		b, err := json.Marshal(v.Object, json.Deterministic(true))
		if err != nil {
			return nil, invalid("value: %v", err)
		}
		w.Object = b
	default:
		return nil, invalid("value: unknown type %q", v.Type)
	}
	return json.Marshal(w, json.Deterministic(true))
}

// ScopedDeclaration is an active declaration with its source scope: Connection
// is zero for an org-scoped (service account) provider and the connection of
// a gateway provider (G0 M12 D43).
type ScopedDeclaration struct {
	Name        string
	Type        Type
	SubjectType string
	Connection  ids.UUID
}

// CheckScope checks the provider's declarations against the active ones: a
// fact name has one provider per source scope. A service account's provider
// (org scope) may not supply a name any provider supplies; a gateway's
// (connection scope) may not supply a name an org-scoped provider supplies
// or one its own connection already supplies, and may supply a name other
// connections supply only with the same type and subject type.
func (p Provider) CheckScope(active []ScopedDeclaration) error {
	for _, d := range p.Facts {
		for _, a := range active {
			if CELName(a.Name) != CELName(d.Name) {
				continue
			}
			switch {
			case p.ConnectionID.IsZero():
				return invalid("provider: another provider already supplies %q", d.Name)
			case a.Connection.IsZero():
				return invalid("provider: %q is supplied by an org-scoped provider, so no connection can also supply it", d.Name)
			case a.Connection == p.ConnectionID:
				return invalid("provider: this connection already supplies %q", d.Name)
			case a.Type != d.Type || a.SubjectType != d.SubjectType:
				return invalid("provider: another connection supplies %q as %s about %s", d.Name, a.Type, a.SubjectType)
			}
		}
	}
	return nil
}
