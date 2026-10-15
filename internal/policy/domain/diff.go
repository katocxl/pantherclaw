// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"
)

// Direction says whether a change can only make decisions stricter.
type Direction string

// Directions. UNKNOWN is a change whose effect cannot be proven either way;
// it is treated like LOOSER (M11.1 D3, F1).
const (
	Tighter Direction = "TIGHTER"
	Looser  Direction = "LOOSER"
	Unknown Direction = "UNKNOWN"
	Neutral Direction = "NEUTRAL"
)

// Change kinds.
const (
	ChangeAdded   = "ADDED"
	ChangeRemoved = "REMOVED"
	ChangeChanged = "CHANGED"
)

// Change is one classified difference between two bundles. RuleID is empty
// for a scenario test change (Field "test").
type Change struct {
	RuleID    string    `json:"rule_id,omitzero"`
	Kind      string    `json:"kind"`
	Field     string    `json:"field,omitzero"`
	Before    string    `json:"before,omitzero"`
	After     string    `json:"after,omitzero"`
	Direction Direction `json:"direction"`
	Sentence  string    `json:"sentence"`
}

// Diff is every change from one bundle to the next and their combined
// direction.
type Diff struct {
	Changes   []Change  `json:"changes"`
	Direction Direction `json:"direction"`
}

// Loosens reports whether publishing the next bundle in place of the base
// needs the loosening confirmations (M11.1 F1): it is not provably tighter.
func (d Diff) Loosens() bool { return d.Direction == Looser || d.Direction == Unknown }

// Compare classifies every change from base to next (M11.1 D3, F198).
// Rules are matched by id. A nil base is no policy, so every rule of next
// is ADDED; a nil next is a bundle without rules.
func Compare(base, next *Bundle) Diff {
	if base == nil {
		base = &Bundle{}
	}
	if next == nil {
		next = &Bundle{}
	}
	var changes []Change
	byID := map[string]*Rule{}
	for i := range base.Rules {
		byID[base.Rules[i].ID] = &base.Rules[i]
	}
	inNext := map[string]bool{}
	for i := range next.Rules {
		r := &next.Rules[i]
		inNext[r.ID] = true
		if b, ok := byID[r.ID]; ok {
			changes = append(changes, compareRule(b, r)...)
			continue
		}
		d := Tighter
		if r.Kind == Annotate {
			d = Neutral
		}
		changes = append(changes, change(r.ID, ChangeAdded, "", "", r.Summary, d))
	}
	for i := range base.Rules {
		r := &base.Rules[i]
		if inNext[r.ID] {
			continue
		}
		d := Looser
		if r.Kind == Annotate && !r.IsEmergency() {
			d = Neutral
		}
		changes = append(changes, change(r.ID, ChangeRemoved, "", r.Summary, "", d))
	}
	changes = append(changes, compareTests(base.Tests, next.Tests)...)
	return Diff{Changes: changes, Direction: combine(changes)}
}

func combine(changes []Change) Direction {
	has := map[Direction]bool{}
	for _, c := range changes {
		has[c.Direction] = true
	}
	switch {
	case has[Looser]:
		return Looser
	case has[Unknown]:
		return Unknown
	case has[Tighter]:
		return Tighter
	default:
		return Neutral
	}
}

func change(rule, kind, field, before, after string, d Direction) Change {
	c := Change{RuleID: rule, Kind: kind, Field: field, Before: before, After: after, Direction: d}
	c.Sentence = sentence(c)
	return c
}

var fieldNames = map[string]string{
	"kind": "kind", "summary": "summary", "reason": "reason code", "operations": "operations",
	"environments": "environments", "when": "condition", "facts": "facts", "exceptable": "exceptable",
	"labels": "labels", "labels.emergency": "emergency label",
	"approval.role": "approval role", "approval.count": "approvals required", "approval.independent": "independent approvers",
	"approval.window": "change window", "approval.deadline_seconds": "approval deadline",
	"step_up.subject": "step-up subject", "step_up.method": "step-up method", "step_up.deadline_seconds": "step-up deadline",
	"constraint": "constraint", "constraint.max": "constraint limit", "constraint.values": "constraint values",
	"constraint.level": "verification level",
}

func sentence(c Change) string {
	dir := strings.ToLower(string(c.Direction))
	switch {
	case c.Field == "test":
		return fmt.Sprintf("Test %s %s (%s)", cmp.Or(c.After, c.Before), strings.ToLower(c.Kind), dir)
	case c.Kind == ChangeAdded:
		return fmt.Sprintf("Rule %s added: %s (%s)", c.RuleID, c.After, dir)
	case c.Kind == ChangeRemoved:
		return fmt.Sprintf("Rule %s removed: %s (%s)", c.RuleID, c.Before, dir)
	}
	name := cmp.Or(fieldNames[c.Field], c.Field)
	return fmt.Sprintf("Rule %s: %s %s → %s (%s)", c.RuleID, name, cmp.Or(c.Before, "none"), cmp.Or(c.After, "none"), dir)
}

// compareRule lists the field changes between two rules with the same id.
func compareRule(a, b *Rule) []Change {
	var out []Change
	add := func(field, before, after string, d Direction) {
		out = append(out, change(a.ID, ChangeChanged, field, before, after, d))
	}
	if a.Kind != b.Kind {
		add("kind", string(a.Kind), string(b.Kind), kindDirection(a.Kind, b.Kind))
	}
	if a.Summary != b.Summary {
		add("summary", a.Summary, b.Summary, Neutral)
	}
	if a.Reason != b.Reason {
		add("reason", a.Reason, b.Reason, Neutral)
	}
	if !slices.Equal(a.Operations, b.Operations) {
		add("operations", strings.Join(a.Operations, ", "), strings.Join(b.Operations, ", "),
			scope(coversOps(b.Operations, a.Operations), coversOps(a.Operations, b.Operations)))
	}
	if !slices.Equal(a.Environments, b.Environments) {
		add("environments", envText(a.Environments), envText(b.Environments),
			scope(coversEnvs(b.Environments, a.Environments), coversEnvs(a.Environments, b.Environments)))
	}
	if a.When != b.When {
		add("when", a.When, b.When, Unknown)
	}
	out = append(out, compareFacts(a, b)...)
	if a.Exceptable != b.Exceptable {
		d := Looser
		if !b.Exceptable {
			d = Tighter
		}
		add("exceptable", strconv.FormatBool(a.Exceptable), strconv.FormatBool(b.Exceptable), d)
	}
	before := maps.Clone(a.Labels)
	if a.IsEmergency() && !b.IsEmergency() {
		add("labels.emergency", a.Labels[EmergencyLabel], b.Labels[EmergencyLabel], Looser)
		delete(before, EmergencyLabel)
	}
	if !maps.Equal(before, b.Labels) {
		add("labels", labelText(before), labelText(b.Labels), Neutral)
	}
	if a.Kind == b.Kind {
		switch a.Kind { //nolint:exhaustive // FORBID and ANNOTATE carry no requirement
		case RequireApproval:
			out = append(out, compareApproval(a.ID, a.Approval, b.Approval)...)
		case RequireStepUp:
			out = append(out, compareStepUp(a.ID, a.StepUp, b.StepUp)...)
		case Constrain:
			out = append(out, compareConstraint(a.ID, a.Constraint, b.Constraint)...)
		}
	}
	if a.Kind == Annotate && b.Kind == Annotate {
		// An annotation decides nothing; only losing the emergency label
		// matters (D4).
		for i := range out {
			if out[i].Field != "labels.emergency" && out[i].Direction != Neutral {
				out[i].Direction = Neutral
				out[i].Sentence = sentence(out[i])
			}
		}
	}
	return out
}

// kindRank orders the deciding kinds: FORBID > REQUIRE_APPROVAL,
// REQUIRE_STEP_UP > CONSTRAIN.
var kindRank = map[Kind]int{Forbid: 3, RequireApproval: 2, RequireStepUp: 2, Constrain: 1}

func kindDirection(a, b Kind) Direction {
	ra, okA := kindRank[a]
	rb, okB := kindRank[b]
	switch {
	case !okA || !okB || ra == rb:
		return Unknown
	case rb > ra:
		return Tighter
	default:
		return Looser
	}
}

// scope classifies a scope change: wider (next covers base) is TIGHTER,
// narrower LOOSER, the same coverage NEUTRAL, else UNKNOWN.
func scope(nextCoversBase, baseCoversNext bool) Direction {
	switch {
	case nextCoversBase && baseCoversNext:
		return Neutral
	case nextCoversBase:
		return Tighter
	case baseCoversNext:
		return Looser
	default:
		return Unknown
	}
}

// coversOps reports whether every operation pattern of b is covered by one
// of a: equal, or under a prefix pattern of a (payments.* covers
// payments.refund.create and payments.refund.*).
func coversOps(a, b []string) bool {
	return !slices.ContainsFunc(b, func(x string) bool {
		return !slices.ContainsFunc(a, func(p string) bool {
			prefix, isPrefix := strings.CutSuffix(p, "*")
			return p == x || (isPrefix && strings.HasPrefix(x, prefix))
		})
	})
}

// coversEnvs: an empty list is every environment, the widest scope.
func coversEnvs(a, b []string) bool {
	switch {
	case len(a) == 0:
		return true
	case len(b) == 0:
		return false
	}
	return !slices.ContainsFunc(b, func(x string) bool { return !slices.Contains(a, x) })
}

func envText(envs []string) string {
	if len(envs) == 0 {
		return "all environments"
	}
	return strings.Join(envs, ", ")
}

func labelText(l map[string]string) string {
	parts := make([]string, 0, len(l))
	for _, k := range slices.Sorted(maps.Keys(l)) {
		parts = append(parts, k+"="+l[k])
	}
	return strings.Join(parts, ", ")
}

func compareFacts(a, b *Rule) []Change {
	before := map[string]int{}
	for _, f := range a.Facts {
		before[f.Name] = f.MaxAgeSeconds
	}
	after := map[string]int{}
	for _, f := range b.Facts {
		after[f.Name] = f.MaxAgeSeconds
	}
	var out []Change
	text := func(name string, age int) string { return fmt.Sprintf("%s (max age %ds)", name, age) }
	for _, name := range slices.Sorted(maps.Keys(after)) {
		old, ok := before[name]
		switch {
		case !ok:
			out = append(out, change(a.ID, ChangeChanged, "facts", "", text(name, after[name]), Tighter))
		case after[name] < old:
			out = append(out, change(a.ID, ChangeChanged, "facts", text(name, old), text(name, after[name]), Tighter))
		case after[name] > old:
			out = append(out, change(a.ID, ChangeChanged, "facts", text(name, old), text(name, after[name]), Looser))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(before)) {
		if _, ok := after[name]; !ok {
			out = append(out, change(a.ID, ChangeChanged, "facts", text(name, before[name]), "", Looser))
		}
	}
	return out
}

// more classifies a requirement that is stricter when larger.
func more(a, b int) Direction {
	if b > a {
		return Tighter
	}
	return Looser
}

// boolOn classifies a requirement that is stricter when on.
func boolOn(b bool) Direction {
	if b {
		return Tighter
	}
	return Looser
}

// deadline: shorter is stricter. Unset means the tenant's configured hold
// deadline, which the bundle does not know, so a change to or from unset
// is UNKNOWN.
func deadline(a, b int) Direction {
	switch {
	case a == 0 || b == 0:
		return Unknown
	case b < a:
		return Tighter
	default:
		return Looser
	}
}

func secs(s int) string {
	if s == 0 {
		return "default"
	}
	return strconv.Itoa(s) + "s"
}

func compareApproval(id string, a, b *ApprovalRequirement) []Change {
	if a == nil || b == nil {
		return nil
	}
	var out []Change
	add := func(field, before, after string, d Direction) {
		out = append(out, change(id, ChangeChanged, field, before, after, d))
	}
	if a.Role != b.Role {
		add("approval.role", a.Role, b.Role, Unknown)
	}
	if a.Count != b.Count {
		add("approval.count", strconv.Itoa(a.Count), strconv.Itoa(b.Count), more(a.Count, b.Count))
	}
	if a.Independent != b.Independent {
		add("approval.independent", strconv.FormatBool(a.Independent), strconv.FormatBool(b.Independent), boolOn(b.Independent))
	}
	if a.Window != b.Window {
		add("approval.window", strconv.FormatBool(a.Window), strconv.FormatBool(b.Window), boolOn(b.Window))
	}
	if a.DeadlineSeconds != b.DeadlineSeconds {
		add("approval.deadline_seconds", secs(a.DeadlineSeconds), secs(b.DeadlineSeconds), deadline(a.DeadlineSeconds, b.DeadlineSeconds))
	}
	return out
}

func compareStepUp(id string, a, b *StepUpRequirement) []Change {
	if a == nil || b == nil {
		return nil
	}
	var out []Change
	add := func(field, before, after string, d Direction) {
		out = append(out, change(id, ChangeChanged, field, before, after, d))
	}
	if a.Subject != b.Subject {
		add("step_up.subject", a.Subject, b.Subject, Unknown)
	}
	if a.Method != b.Method {
		add("step_up.method", a.Method, b.Method, Unknown)
	}
	if a.DeadlineSeconds != b.DeadlineSeconds {
		add("step_up.deadline_seconds", secs(a.DeadlineSeconds), secs(b.DeadlineSeconds), deadline(a.DeadlineSeconds, b.DeadlineSeconds))
	}
	return out
}

func constraintText(c *Constraint) string {
	s := string(c.Kind)
	if c.Param != "" {
		s += " " + c.Param
	}
	if c.Currency != "" {
		s += " (" + c.Currency + ")"
	}
	return s
}

func maxText(c *Constraint) string { return strings.TrimSpace(c.Max + " " + c.Currency) }

func compareConstraint(id string, a, b *Constraint) []Change {
	if a == nil || b == nil {
		return nil
	}
	one := func(field, before, after string, d Direction) []Change {
		return []Change{change(id, ChangeChanged, field, before, after, d)}
	}
	if a.Kind != b.Kind || a.Param != b.Param || a.Currency != b.Currency {
		return one("constraint", constraintText(a), constraintText(b), Unknown)
	}
	switch a.Kind {
	case AmountMax, CountMax:
		if a.Max == b.Max {
			return nil
		}
		x, okA := new(big.Rat).SetString(a.Max)
		y, okB := new(big.Rat).SetString(b.Max)
		d := Unknown
		if okA && okB {
			switch y.Cmp(x) {
			case -1:
				d = Tighter
			case 1:
				d = Looser
			default:
				d = Neutral
			}
		}
		return one("constraint.max", maxText(a), maxText(b), d)
	case AllowedValues, TargetSet, DestinationSet:
		if slices.Equal(a.Values, b.Values) {
			return nil
		}
		sub := !slices.ContainsFunc(b.Values, func(v string) bool { return !slices.Contains(a.Values, v) })
		sup := !slices.ContainsFunc(a.Values, func(v string) bool { return !slices.Contains(b.Values, v) })
		// Fewer allowed values is stricter.
		return one("constraint.values", strings.Join(a.Values, ", "), strings.Join(b.Values, ", "), scope(sub, sup))
	case Verify:
		if a.Level == b.Level {
			return nil
		}
		d := Unknown
		switch ra, rb := a.Level.Rank(), b.Level.Rank(); {
		case rb > ra:
			d = Tighter
		case rb < ra:
			d = Looser
		}
		return one("constraint.level", string(a.Level), string(b.Level), d)
	}
	return nil
}

func compareTests(a, b []TestCase) []Change {
	byID := map[string]TestCase{}
	for _, t := range a {
		byID[t.ID] = t
	}
	var out []Change
	inNext := map[string]bool{}
	for _, t := range b {
		inNext[t.ID] = true
		old, ok := byID[t.ID]
		switch {
		case !ok:
			out = append(out, change("", ChangeAdded, "test", "", t.ID, Neutral))
		case jcsDigest(old) != jcsDigest(t):
			out = append(out, change("", ChangeChanged, "test", t.ID, t.ID, Neutral))
		}
	}
	for _, t := range a {
		if !inNext[t.ID] {
			out = append(out, change("", ChangeRemoved, "test", t.ID, "", Neutral))
		}
	}
	return out
}
