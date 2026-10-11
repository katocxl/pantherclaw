// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds structured policy rules and their deterministic,
// fail-closed composition (ADR-0004, F092, F179). A rule is a readable
// sentence backed by validated fields; its condition is a CEL expression
// compiled elsewhere (internal/policy/app). Rules only ever restrict: no
// rule kind can produce ALLOW, which only a grant can give (part 2).
package domain

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrInvalid reports a rule or bundle that breaks a format rule; such a
// bundle is never published.
var ErrInvalid = errors.New("policy: invalid rule")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Kind is what a matching rule does.
type Kind string

// Rule kinds.
const (
	Forbid          Kind = "FORBID"
	RequireApproval Kind = "REQUIRE_APPROVAL"
	RequireStepUp   Kind = "REQUIRE_STEP_UP"
	Constrain       Kind = "CONSTRAIN"
	Annotate        Kind = "ANNOTATE"
)

// Rule is one structured policy rule.
type Rule struct {
	ID      string `json:"id"`
	Kind    Kind   `json:"kind"`
	Summary string `json:"summary"`
	// Operations scopes the rule: exact operations or prefixes ending in
	// ".*" (payments.*). Environments optionally narrows it to env ids.
	Operations   []string `json:"operations"`
	Environments []string `json:"environments,omitzero"`
	// When is the CEL condition over `action`.
	When string `json:"when"`
	// Reason is the stable reason code reported when the rule decides.
	Reason     string               `json:"reason"`
	Approval   *ApprovalRequirement `json:"approval,omitzero"`
	StepUp     *StepUpRequirement   `json:"step_up,omitzero"`
	Constraint *Constraint          `json:"constraint,omitzero"`
	Labels     map[string]string    `json:"labels,omitzero"`
	// Facts are the trusted facts the condition reads (as
	// facts.<name with dots as underscores>). They become required for every
	// action in the rule's scope; a rule whose facts are missing or stale is
	// not evaluated (HR-160, F120).
	Facts []FactRef `json:"facts,omitzero"`
}

// FactRef names a fact a rule reads and how old it may be.
type FactRef struct {
	Name          string `json:"name"`
	MaxAgeSeconds int    `json:"max_age_seconds"`
}

const (
	maxRuleFacts  = 8
	maxFactAgeSec = 86400
)

// ApprovalRequirement says who must approve (enforced in M5). Role is a
// default role holding approval.respond (G0 M5 part 2 decision 2);
// DeadlineSeconds, when set, is the hold's deadline (decision 6: 300 to
// 604800 seconds; the shortest of a hold's requirements wins).
type ApprovalRequirement struct {
	Role            string `json:"role"`
	Count           int    `json:"count"`
	Independent     bool   `json:"independent,omitzero"`
	DeadlineSeconds int    `json:"deadline_seconds,omitzero"`
}

// StepUpRequirement says who must re-authenticate (enforced in M5): the
// launcher or the principal, by WebAuthn (decision 4).
type StepUpRequirement struct {
	Subject         string `json:"subject"`
	Method          string `json:"method"`
	DeadlineSeconds int    `json:"deadline_seconds,omitzero"`
}

// Hold deadline bounds a requirement may set (G0 M5 part 2 decision 6).
const (
	MinDeadlineSeconds = 300
	MaxDeadlineSeconds = 7 * 24 * 3600
)

// ValidDeadline reports whether a requirement's deadline is unset or in
// bounds.
func ValidDeadline(s int) bool { return s == 0 || (s >= MinDeadlineSeconds && s <= MaxDeadlineSeconds) }

// ApprovalRole reports whether an approval may name role: a default role
// that holds approval.respond (decision 2; today only "approver"). Stored
// policies and grants that name another role are not refused when read;
// the decision pipeline answers REQUIREMENT_INVALID for them.
func ApprovalRole(role string) bool {
	r, ok := tdomain.LookupRole(tdomain.RoleName(role))
	return ok && r.Has(tdomain.PermApprovalRespond)
}

// ConstraintKind matches the definitions' declared constraint kinds (F100),
// and Verify.
type ConstraintKind string

// Constraint kinds.
const (
	AmountMax      ConstraintKind = "amount_max"
	CountMax       ConstraintKind = "count_max"
	AllowedValues  ConstraintKind = "allowed_values"
	TargetSet      ConstraintKind = "target_set"
	DestinationSet ConstraintKind = "destination_set"
	// Verify raises the verification level the action's effect needs
	// (verify(level), G0 M7 design decision 2, F497). It is no limit on the
	// action: the Authority applies it, after dispatch, and step 8 refuses
	// the action (CANNOT_AUTHORIZE, VERIFIER_UNSUPPORTED) when the
	// definition's verifier cannot reach the level or the connection cannot
	// make its read.
	Verify ConstraintKind = "verify"
)

// Constraint is the limit a CONSTRAIN rule applies. Max is a decimal string
// (with Currency for money params); Values lists allowed values, target ids
// or destination ids; Level is the level a verify constraint requires.
type Constraint struct {
	Kind     ConstraintKind `json:"kind"`
	Param    string         `json:"param,omitzero"`
	Max      string         `json:"max,omitzero"`
	Currency string         `json:"currency,omitzero"`
	Values   []string       `json:"values,omitzero"`
	Level    defs.Level     `json:"level,omitzero"`
}

// VerifyLevel reports whether a verify constraint may require level: a
// level above the target's own acceptance (follow_up, domain_effect or
// downstream), which is what every effect reaches anyway.
func VerifyLevel(l defs.Level) bool { return l.Rank() > defs.LevelAcceptance.Rank() }

// Bundle is a published set of rules for an org (versioned, immutable).
type Bundle struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

var (
	idRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	reasonRe  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	roleRe    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	labelRe   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	prefixRe  = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,6}\.\*$`)
	maxRules  = 512
	maxWhen   = 4 << 10
	maxValues = 256
)

// Validate checks a bundle: unique rule ids and well-formed rules.
// CheckApprovalRoles refuses a new bundle whose approval rules name a role
// that is not a default role holding approval.respond (G0 M5 part 2
// decision 2). It is not part of Validate, so a stored bundle still
// compiles and its holds are answered REQUIREMENT_INVALID.
func (b *Bundle) CheckApprovalRoles() error {
	for _, r := range b.Rules {
		if r.Approval != nil && !ApprovalRole(r.Approval.Role) {
			return invalid("%s: approval role %q is not a default role that holds approval.respond", r.ID, r.Approval.Role)
		}
	}
	return nil
}

func (b *Bundle) Validate() error {
	if !idRe.MatchString(b.ID) || b.Version < 1 {
		return invalid("bundle needs an id and a positive version")
	}
	if len(b.Rules) == 0 || len(b.Rules) > maxRules {
		return invalid("a bundle has 1..%d rules", maxRules)
	}
	seen := map[string]bool{}
	for i := range b.Rules {
		r := &b.Rules[i]
		if err := r.Validate(); err != nil {
			return err
		}
		if seen[r.ID] {
			return invalid("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
	}
	return nil
}

// Validate checks one rule. Each kind carries exactly its own fields.
func (r *Rule) Validate() error {
	id := r.ID
	switch {
	case !idRe.MatchString(id):
		return invalid("rule id %q", id)
	case !reasonRe.MatchString(r.Reason):
		return invalid("%s: reason code %q must be UPPER_SNAKE", id, r.Reason)
	case r.Summary == "" || len(r.Summary) > 512 || strings.ContainsFunc(r.Summary, func(c rune) bool { return c < 0x20 || c == 0x7f }):
		return invalid("%s: summary must be one readable line", id)
	case r.When == "" || len(r.When) > maxWhen:
		return invalid("%s: condition must be 1..%d bytes", id, maxWhen)
	case len(r.Operations) == 0 || len(r.Operations) > maxValues || len(r.Environments) > maxValues:
		return invalid("%s: 1..%d operations and at most %d environments", id, maxValues, maxValues)
	}
	for _, op := range r.Operations {
		if !actionir.ValidOperation(op) && !prefixRe.MatchString(op) {
			return invalid("%s: operation %q must be exact or a prefix like payments.*", id, op)
		}
	}
	for _, env := range r.Environments {
		if err := actionir.CheckIdentifier(id+": environment", env); err != nil {
			return invalid("%s: environment %q", id, env)
		}
	}
	if len(r.Facts) > maxRuleFacts {
		return invalid("%s: a rule reads at most %d facts", id, maxRuleFacts)
	}
	seenFacts := map[string]bool{}
	for _, f := range r.Facts {
		if !fdomain.ValidName(f.Name) || seenFacts[f.Name] || f.MaxAgeSeconds < 1 || f.MaxAgeSeconds > maxFactAgeSec {
			return invalid("%s: fact %q needs a unique dotted name and a max_age_seconds of 1..%d", id, f.Name, maxFactAgeSec)
		}
		seenFacts[f.Name] = true
	}
	want := map[Kind][4]bool{ // approval, step-up, constraint, labels
		Forbid: {}, RequireApproval: {true, false, false, false}, RequireStepUp: {false, true, false, false},
		Constrain: {false, false, true, false}, Annotate: {false, false, false, true},
	}
	w, ok := want[r.Kind]
	if !ok {
		return invalid("%s: unknown kind %q", id, r.Kind)
	}
	if have := [4]bool{r.Approval != nil, r.StepUp != nil, r.Constraint != nil, len(r.Labels) > 0}; have != w {
		return invalid("%s: a %s rule carries exactly its own requirement fields", id, r.Kind)
	}
	switch r.Kind { //nolint:exhaustive // FORBID carries nothing extra
	case RequireApproval:
		if a := r.Approval; !roleRe.MatchString(a.Role) || a.Count < 1 || a.Count > 2 || !ValidDeadline(a.DeadlineSeconds) {
			return invalid("%s: approval needs a role, a count of 1 or 2 and a deadline of 300..604800 seconds if any", id)
		}
	case RequireStepUp:
		if s := r.StepUp; !slices.Contains([]string{"launcher", "principal"}, s.Subject) || s.Method != "webauthn" ||
			!ValidDeadline(s.DeadlineSeconds) {
			return invalid("%s: step-up needs subject launcher|principal, method webauthn and a deadline of 300..604800 seconds if any", id)
		}
	case Constrain:
		return r.Constraint.validate(id)
	case Annotate:
		for _, k := range slices.Sorted(maps.Keys(r.Labels)) {
			if !labelRe.MatchString(k) || len(r.Labels[k]) > 256 {
				return invalid("%s: label %q", id, k)
			}
		}
	}
	return nil
}

func (c *Constraint) validate(id string) error {
	if c.Level != "" && c.Kind != Verify {
		return invalid("%s: only verify takes a level", id)
	}
	switch c.Kind {
	case Verify:
		if c.Param != "" || c.Max != "" || c.Currency != "" || len(c.Values) > 0 || !VerifyLevel(c.Level) {
			return invalid("%s: verify needs a level of follow_up, domain_effect or downstream, and nothing else", id)
		}
		return nil
	case AmountMax, CountMax:
		if c.Param == "" || c.Max == "" || len(c.Values) > 0 {
			return invalid("%s: %s needs a param and a max", id, c.Kind)
		}
	case AllowedValues:
		if c.Param == "" || c.Max != "" || c.Currency != "" || len(c.Values) == 0 {
			return invalid("%s: allowed_values needs a param and values", id)
		}
	case TargetSet, DestinationSet:
		if c.Param != "" || c.Max != "" || c.Currency != "" || len(c.Values) == 0 {
			return invalid("%s: %s needs values and no param", id, c.Kind)
		}
	default:
		return invalid("%s: unknown constraint kind %q", id, c.Kind)
	}
	if len(c.Values) > maxValues {
		return invalid("%s: at most %d values", id, maxValues)
	}
	for _, v := range c.Values {
		if err := actionir.CheckIdentifier(id+": value", v); err != nil {
			return invalid("%s: value %q", id, v)
		}
	}
	return nil
}

// Applies reports whether the rule's scope covers an operation in an env.
func (r *Rule) Applies(operation, env string) bool {
	if len(r.Environments) > 0 && !slices.Contains(r.Environments, env) {
		return false
	}
	return r.CoversOperation(operation)
}

// CoversOperation reports whether the rule's operations cover an operation,
// whatever the environment.
func (r *Rule) CoversOperation(operation string) bool {
	return slices.ContainsFunc(r.Operations, func(op string) bool {
		prefix, isPrefix := strings.CutSuffix(op, "*")
		return op == operation || (isPrefix && strings.HasPrefix(operation, prefix))
	})
}
