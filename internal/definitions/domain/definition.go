// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the reviewed meaning of agent operations: tool
// packages, action definitions, mappings and consequence rules (F372–F405,
// BUILD_GUIDE §8 M4). A definition says what an operation does, which
// target it touches, which parameters are material and how they are typed,
// what can be constrained, how retries and verification work, and how tool
// calls map onto it. Everything here is pure: no I/O, clock or randomness.
package domain

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// ErrInvalid reports a package or definition that breaks a format or
// review rule. Such a package is never imported.
var ErrInvalid = errors.New("definitions: invalid definition")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Access is the read/write class of an operation.
type Access string

// Access classes.
const (
	AccessRead  Access = "read"
	AccessWrite Access = "write"
)

// Reversibility states whether the direct effect can be undone (F379).
type Reversibility string

// Reversibility classes.
const (
	Reversible    Reversibility = "reversible"
	Compensatable Reversibility = "compensatable"
	Irreversible  Reversibility = "irreversible"
)

// Presence says whether an optional part of the target must be present.
type Presence string

// Presence values.
const (
	PresenceRequired Presence = "required"
	PresenceOptional Presence = "optional"
	PresenceNone     Presence = "none"
)

// Definition is the reviewed meaning of one operation (F374–F383).
type Definition struct {
	Operation     string               `json:"operation"`
	Summary       string               `json:"summary"`
	Access        Access               `json:"access"`
	Target        TargetSpec           `json:"target"`
	Params        map[string]ParamSpec `json:"params"`
	Effects       []Effect             `json:"effects"`
	SideEffects   []Effect             `json:"side_effects,omitzero"`
	Reversibility Reversibility        `json:"reversibility"`
	Constraints   []ConstraintSpec     `json:"constraints,omitzero"`
	Prerequisites []Prerequisite       `json:"prerequisites,omitzero"`
	Retry         RetrySpec            `json:"retry"`
	Verifier      *VerifierSpec        `json:"verifier,omitzero"`
	Approval      *ApprovalTemplate    `json:"approval,omitzero"`
	Dedupe        []string             `json:"dedupe_key,omitzero"`
	Assurance     Assurance            `json:"assurance"`
	Mappings      []Mapping            `json:"mappings"`
	// Dispatch is the outbound request template (G0 M6, HR-075).
	Dispatch *Dispatch `json:"dispatch,omitzero"`
	// Test marks the harmless read a connection test runs (G0 M8, C2): a
	// read with an HTTP GET dispatch template and no required params; at
	// most one per package.
	Test bool `json:"test,omitzero"`

	// Digest is "sha256:<hex>" of the canonical JSON of this definition,
	// mappings included. It is what ActionIR pins (definition.digest) and
	// approvals bind. The manifest decoder sets it.
	Digest string `json:"-"`
}

// TargetSpec is the stable identity of the object an operation affects
// (F377). Patterns are anchored RE2 expressions (no backtracking).
type TargetSpec struct {
	Type           string   `json:"type"`
	IDPattern      string   `json:"id_pattern"`
	Account        Presence `json:"account"`
	AccountPattern string   `json:"account_pattern,omitzero"`
}

// Effect is a direct or side effect (F379).
type Effect struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// ConstraintKind is a constraint a tool can reliably enforce (F100).
type ConstraintKind string

// Constraint kinds.
const (
	ConstraintAmountMax      ConstraintKind = "amount_max"
	ConstraintCountMax       ConstraintKind = "count_max"
	ConstraintAllowedValues  ConstraintKind = "allowed_values"
	ConstraintTargetSet      ConstraintKind = "target_set"
	ConstraintDestinationSet ConstraintKind = "destination_set"
)

// ConstraintSpec declares support for one constraint. Clamp declares that
// lowering the value to the limit is a safe transformation (F104); it is
// allowed only for count_max, because a material business change such as a
// smaller refund needs a new request (F105).
type ConstraintSpec struct {
	Kind  ConstraintKind `json:"kind"`
	Param string         `json:"param,omitzero"`
	Clamp bool           `json:"clamp,omitzero"`
}

// Prerequisite names a trusted fact that must be present and fresh (F381).
type Prerequisite struct {
	Fact          string `json:"fact"`
	MaxAgeSeconds int    `json:"max_age_seconds"`
	// Binds requires a member of the (object) fact to equal a material
	// param of the action; a mismatch is CANNOT_AUTHORIZE with its reason
	// (G0 M8, HR-205: a merge is bound to its pull request's head,
	// github.pull.head.sha == params.sha, else HEAD_MOVED).
	Binds *FactBinding `json:"binds,omitzero"`
}

// FactBinding binds a member of a fact to a param.
type FactBinding struct {
	Member string `json:"member"`
	Param  string `json:"param"`
	Reason string `json:"reason"`
}

// OnUnknown is what happens after an ambiguous outcome (F382).
type OnUnknown string

// Ambiguous-outcome handling.
const (
	OnUnknownReconcile OnUnknown = "reconcile"
	OnUnknownFail      OnUnknown = "fail"
)

// RetrySpec states retry safety (F382).
type RetrySpec struct {
	Safe              bool      `json:"safe"`
	OnUnknown         OnUnknown `json:"on_unknown"`
	TargetIdempotency bool      `json:"target_idempotency,omitzero"`
}

// ApprovalTemplate is the per-operation approval text (HR-034). Title
// placeholders and fields name canonical fields only: operation,
// target.type, target.id, target.account or params.<material param>.
type ApprovalTemplate struct {
	Title  string   `json:"title"`
	Fields []string `json:"fields"`
	// InvalidateOn names a prerequisite fact whose change supersedes every
	// unconsumed approval request for the same target (G0 M8, HR-205: a
	// pull request's new head, github.pull.head).
	InvalidateOn string `json:"invalidate_on,omitzero"`
	// IndependentOf names a prerequisite fact listing, by GitHub user id,
	// the people an independent approver must not be (G0 M8, HR-207: a
	// pull request's author, committers and pushers, github.pull.people,
	// with complete false when they cannot all be read).
	IndependentOf string `json:"independent_of,omitzero"`
}

// Basis is where the evidence for a definition comes from (F391).
type Basis string

// Assurance bases.
const (
	BasisDeclared   Basis = "declared"
	BasisDocumented Basis = "documented"
	BasisObserved   Basis = "observed"
)

// Assurance records who reviewed a definition and until when (F383).
type Assurance struct {
	Basis      Basis    `json:"basis"`
	ReviewedBy []string `json:"reviewed_by"`
	ValidUntil string   `json:"valid_until"`
}

// Expiry returns the end of the validity day (UTC, exclusive).
func (a Assurance) Expiry() (time.Time, error) {
	return parseDay("assurance.valid_until", a.ValidUntil)
}

// parseDay parses YYYY-MM-DD and returns the end of that UTC day.
func parseDay(name, s string) (time.Time, error) {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return time.Time{}, invalid("%s must be YYYY-MM-DD", name)
	}
	return d.AddDate(0, 0, 1), nil
}

// Stale reports whether the evidence has expired at now (F396). An
// unparsable date counts as stale.
func (a Assurance) Stale(now time.Time) bool {
	exp, err := a.Expiry()
	return err != nil || !now.Before(exp)
}

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	kindRe   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,7}$`)
	reviewRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$`)
	holderRe = regexp.MustCompile(`\{([^{}]*)\}`)
	// partRe is a named group of a target id pattern, which a template
	// references as target.id.<name>.
	partRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

const (
	maxText   = 1024
	maxItems  = 64
	maxSecond = 366 * 24 * 3600
)

// text checks a required piece of package prose.
func text(name, v string) error {
	if v == "" {
		return invalid("%s is required", name)
	}
	if len(v) > maxText {
		return invalid("%s longer than %d bytes", name, maxText)
	}
	return checkText(name, v)
}

// Validate checks a definition on its own. Package-level checks (unique
// operations, verifier references) are in Package.Validate.
func (d *Definition) Validate() error {
	op := d.Operation
	switch {
	case !actionir.ValidOperation(op):
		return invalid("operation %q", op)
	case d.Access != AccessRead && d.Access != AccessWrite:
		return invalid("%s: access must be read or write", op)
	case !slices.Contains([]Reversibility{Reversible, Compensatable, Irreversible}, d.Reversibility):
		return invalid("%s: reversibility must be reversible, compensatable or irreversible", op)
	case len(d.Effects) == 0 || len(d.Effects) > maxItems || len(d.SideEffects) > maxItems:
		return invalid("%s: 1..%d effects and at most %d side effects", op, maxItems, maxItems)
	case len(d.Params) > maxItems || len(d.Mappings) > maxItems:
		return invalid("%s: at most %d params and %d mappings", op, maxItems, maxItems)
	case len(d.Mappings) == 0 && d.Access != AccessRead && d.Dispatch != nil:
		// A read without mappings is internal: only a verifier, a target
		// log or a connection test may use it, never an agent. A write
		// without mappings is virtual: never dispatched, it only names a
		// consequence of this package (Package.Validate).
		return invalid("%s: a write needs 1..%d mappings, or no dispatch when it is a consequence", op, maxItems)
	case d.Test && (d.Access != AccessRead || d.Dispatch == nil || d.Dispatch.HTTP == nil || d.Dispatch.HTTP.Method != methods[0] ||
		slices.ContainsFunc(slices.Collect(maps.Values(d.Params)), func(p ParamSpec) bool { return p.Required })):
		return invalid("%s: a connection test is a read with an HTTP GET template and no required params", op)
	}
	if err := text(op+": summary", d.Summary); err != nil {
		return err
	}
	if err := d.Target.validate(op); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(d.Params)) {
		if !nameRe.MatchString(name) {
			return invalid("%s: param name %q", op, name)
		}
		if err := d.Params[name].validate(op + ": params." + name); err != nil {
			return err
		}
	}
	for _, e := range slices.Concat(d.Effects, d.SideEffects) {
		if !kindRe.MatchString(e.Kind) {
			return invalid("%s: effect kind %q", op, e.Kind)
		}
		if err := text(op+": effect description", e.Description); err != nil {
			return err
		}
	}
	for _, c := range d.Constraints {
		if err := d.validateConstraint(c); err != nil {
			return err
		}
	}
	for _, p := range d.Prerequisites {
		if !kindRe.MatchString(p.Fact) || p.MaxAgeSeconds <= 0 || p.MaxAgeSeconds > maxSecond {
			return invalid("%s: prerequisite %q needs a fact name and 1..%d max_age_seconds", op, p.Fact, maxSecond)
		}
		if err := d.validateBinding(p); err != nil {
			return err
		}
	}
	if err := d.validateRetry(); err != nil {
		return err
	}
	if err := d.validateVerifier(); err != nil {
		return err
	}
	if err := d.validateApproval(); err != nil {
		return err
	}
	if err := d.validateDedupe(); err != nil {
		return err
	}
	if err := d.validateAssurance(); err != nil {
		return err
	}
	for i := range d.Mappings {
		if err := d.validateMapping(i); err != nil {
			return err
		}
	}
	return d.validateDispatch()
}

func (t TargetSpec) validate(op string) error {
	if err := actionir.CheckIdentifier(op+": target.type", t.Type); err != nil || !kindRe.MatchString(t.Type) {
		return invalid("%s: target.type %q", op, t.Type)
	}
	if err := anchored(op+": target.id_pattern", t.IDPattern); err != nil {
		return err
	}
	groups := regexp.MustCompile(t.IDPattern).SubexpNames()
	for i, g := range groups {
		if g != "" && (!partRe.MatchString(g) || slices.Contains(groups[:i], g)) {
			return invalid("%s: target.id_pattern group %q must be a distinct lowercase name", op, g)
		}
	}
	switch t.Account {
	case PresenceRequired, PresenceOptional:
		return anchored(op+": target.account_pattern", t.AccountPattern)
	case PresenceNone:
		if t.AccountPattern != "" {
			return invalid("%s: target.account_pattern without an account", op)
		}
		return nil
	default:
		return invalid("%s: target.account must be required, optional or none", op)
	}
}

// anchored compiles an RE2 pattern that must match whole values.
func anchored(name, p string) error {
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") || len(p) > 256 {
		return invalid("%s must be an anchored pattern (^…$) of at most 256 bytes", name)
	}
	if _, err := regexp.Compile(p); err != nil {
		return invalid("%s: %v", name, err)
	}
	return nil
}

func (d *Definition) validateConstraint(c ConstraintSpec) error {
	op := d.Operation
	var want []ParamType
	switch c.Kind {
	case ConstraintAmountMax:
		want = []ParamType{TypeMoney, TypeDecimal}
	case ConstraintCountMax:
		want = []ParamType{TypeInteger}
	case ConstraintAllowedValues:
		want = []ParamType{TypeEnum, TypeIdentifier, TypeIdentifierList}
	case ConstraintTargetSet, ConstraintDestinationSet:
		if c.Param != "" || c.Clamp {
			return invalid("%s: %s constraint takes no param and cannot clamp", op, c.Kind)
		}
		return nil
	default:
		return invalid("%s: unknown constraint kind %q", op, c.Kind)
	}
	p, ok := d.Params[c.Param]
	if !ok || !slices.Contains(want, p.Type) {
		return invalid("%s: %s constraint needs a param of type %v", op, c.Kind, want)
	}
	if c.Clamp && c.Kind != ConstraintCountMax {
		return invalid("%s: only count_max may clamp (F105)", op)
	}
	return nil
}

func (d *Definition) validateRetry() error {
	r := d.Retry
	if r.OnUnknown != OnUnknownReconcile && r.OnUnknown != OnUnknownFail {
		return invalid("%s: retry.on_unknown must be reconcile or fail", d.Operation)
	}
	if d.Reversibility == Irreversible && (r.Safe || r.OnUnknown != OnUnknownReconcile) {
		return invalid("%s: an irreversible operation is never safe to retry and reconciles unknown outcomes", d.Operation)
	}
	return nil
}

// canonicalField reports whether f names a canonical material field: one an
// approval may show and a dedupe key may use.
func (d *Definition) canonicalField(f string) bool {
	switch f {
	case "operation", "target.type", "target.id":
		return true
	case "target.account":
		return d.Target.Account != PresenceNone
	}
	name, ok := strings.CutPrefix(f, "params.")
	p, declared := d.Params[name]
	return ok && declared && p.Material
}

// prerequisiteField reports whether f is facts.<name> of a prerequisite
// fact: an approval may show its value (a readable name beside a stable id,
// G0 M5 part 2 decision 9), but a dedupe key may not use it.
func (d *Definition) prerequisiteField(f string) bool {
	name, ok := strings.CutPrefix(f, "facts.")
	return ok && slices.ContainsFunc(d.Prerequisites, func(p Prerequisite) bool { return p.Fact == name })
}

func (d *Definition) validateApproval() error {
	a := d.Approval
	if a == nil {
		if d.Access == AccessWrite {
			return invalid("%s: write operations need an approval template", d.Operation)
		}
		return nil
	}
	if err := text(d.Operation+": approval.title", a.Title); err != nil {
		return err
	}
	if len(a.Fields) == 0 || len(a.Fields) > maxItems {
		return invalid("%s: approval needs 1..%d fields", d.Operation, maxItems)
	}
	if a.InvalidateOn != "" && !d.prerequisiteField("facts."+a.InvalidateOn) {
		return invalid("%s: approval.invalidate_on names %q, which is not a prerequisite fact", d.Operation, a.InvalidateOn)
	}
	if a.InvalidateOn != "" && !slices.ContainsFunc(d.Prerequisites, func(p Prerequisite) bool { return p.Fact == a.InvalidateOn && p.Binds != nil }) {
		// An approval binds only the members prerequisites declare (HR-030
		// option B), so only a bound member's change can supersede it.
		return invalid("%s: approval.invalidate_on names %q, whose prerequisite binds no member", d.Operation, a.InvalidateOn)
	}
	if a.IndependentOf != "" && !d.prerequisiteField("facts."+a.IndependentOf) {
		return invalid("%s: approval.independent_of names %q, which is not a prerequisite fact", d.Operation, a.IndependentOf)
	}
	refs := a.Fields
	for _, m := range holderRe.FindAllStringSubmatch(a.Title, -1) {
		refs = append(refs, m[1])
	}
	for _, f := range refs {
		if !d.canonicalField(f) && !d.prerequisiteField(f) {
			return invalid("%s: approval may show only canonical material fields and prerequisite facts, not %q (HR-034)", d.Operation, f)
		}
		if name, ok := strings.CutPrefix(f, "params."); ok && d.Params[name].Type == TypeContent {
			// Content is agent-written (a commit message, a pull request's
			// title or body): it is shown only in the untrusted block.
			return invalid("%s: approval may not show content parameter %q among the canonical fields; it is shown untrusted (HR-034)", d.Operation, f)
		}
	}
	return nil
}

func (d *Definition) validateAssurance() error {
	a := d.Assurance
	if !slices.Contains([]Basis{BasisDeclared, BasisDocumented, BasisObserved}, a.Basis) {
		return invalid("%s: assurance.basis must be declared, documented or observed", d.Operation)
	}
	if len(a.ReviewedBy) == 0 || len(a.ReviewedBy) > maxItems {
		return invalid("%s: assurance.reviewed_by needs 1..%d reviewers", d.Operation, maxItems)
	}
	for _, r := range a.ReviewedBy {
		if !reviewRe.MatchString(r) {
			return invalid("%s: reviewer %q", d.Operation, r)
		}
	}
	_, err := a.Expiry()
	return err
}

// Supports reports whether the definition declares support for constraint
// kind on param (F100). A constraint it does not declare is unsupported.
func (d *Definition) Supports(kind ConstraintKind, param string) (ConstraintSpec, bool) {
	i := slices.IndexFunc(d.Constraints, func(c ConstraintSpec) bool { return c.Kind == kind && c.Param == param })
	if i < 0 {
		return ConstraintSpec{}, false
	}
	return d.Constraints[i], true
}

// validateDedupe checks the semantic dedupe key: the canonical fields that
// identify one logical business action across channels (F099). Irreversible
// operations must declare one (HR-007). The key is computed from canonical
// values, so reformatting an amount cannot produce a different key.
func (d *Definition) validateDedupe() error {
	if d.Reversibility == Irreversible && len(d.Dedupe) == 0 {
		return invalid("%s: an irreversible operation must declare a dedupe key (HR-007)", d.Operation)
	}
	if len(d.Dedupe) > maxItems {
		return invalid("%s: dedupe_key has at most %d fields", d.Operation, maxItems)
	}
	for i, f := range d.Dedupe {
		if f == "operation" || !d.canonicalField(f) || slices.Contains(d.Dedupe[:i], f) {
			return invalid("%s: dedupe_key field %q must be a distinct target field or material param", d.Operation, f)
		}
	}
	return nil
}

// reasonRe is a reason code a definition names.
var reasonRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

// validateBinding checks a prerequisite's binding: a member name, a
// material identifier, enum or integer param, and a reason code.
func (d *Definition) validateBinding(p Prerequisite) error {
	b := p.Binds
	if b == nil {
		return nil
	}
	param, ok := d.Params[b.Param]
	switch {
	case !nameRe.MatchString(b.Member) || !reasonRe.MatchString(b.Reason):
		return invalid("%s: prerequisite %s binds a member name with a reason code", d.Operation, p.Fact)
	case !ok || !param.Material || !slices.Contains([]ParamType{TypeIdentifier, TypeEnum, TypeInteger}, param.Type):
		return invalid("%s: prerequisite %s binds %q, which is not a material identifier, enum or integer param", d.Operation, p.Fact, b.Param)
	}
	return nil
}
