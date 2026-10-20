// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package validate checks a policy bundle against the org's active
// definitions and fact catalog before it can be tested and published
// (M11.1 D8, F196, F197, HR-238). ERROR findings block publication;
// WARNING and INFO findings are shown. Some findings come from generated
// sample actions (boundary values around every literal and limit the rules
// use): they are labeled sample_based, because samples can miss an action
// that shows a problem (ADR-0004, R-25). OutcomeDiff shows, over the same
// samples, which decisions a new version would change.
//
// Everything here is read-only and engine-only: no decision pipeline, no
// writes (HR-232).
package validate

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Definitions returns the definitions of the org's active packages
// (app.ActiveDefinitions).
type Definitions interface {
	ActiveDefinitions(ctx context.Context, org ids.OrgID) ([]*defs.Definition, error)
}

// Catalog returns the org's declared fact names and types (app.FactCatalog).
type Catalog interface {
	Catalog(ctx context.Context, org ids.OrgID) (map[string]fdomain.Type, error)
}

// Subjects returns the subject type each fact is declared about
// (app.FactSubjects).
type Subjects interface {
	FactSubjects(ctx context.Context, org ids.OrgID) (map[string]string, error)
}

// Approvers counts the active persons who hold a role at the org path, for
// APPROVER_NONE.
type Approvers interface {
	Approvers(ctx context.Context, org ids.OrgID, role string) (int, error)
}

// Sources reports which facts an active provider or connection supplies,
// for FACT_NO_SOURCE.
type Sources interface {
	SuppliedFacts(ctx context.Context, org ids.OrgID) (map[string]bool, error)
}

// Finding codes (D8).
const (
	CodeCompileError          = "COMPILE_ERROR"
	CodeOperationUnknown      = "OPERATION_UNKNOWN"
	CodeConstraintUnsupported = "CONSTRAINT_UNSUPPORTED"
	CodeVerifyUnreachable     = "VERIFY_UNREACHABLE"
	CodeFactUnknown           = "FACT_UNKNOWN"
	CodeConflict              = "CONFLICT"
	CodeShadowed              = "SHADOWED"
	CodeApproverNone          = "APPROVER_NONE"
	CodeFactNoSource          = "FACT_NO_SOURCE"
	CodeRedundant             = "REDUNDANT"
)

// Validator implements the publish gate's Validator port
// (internal/policy/app).
type Validator struct {
	defs     Definitions
	facts    Catalog
	subjects Subjects
	limits   celenv.Limits
	// Approvers and Sources, when set, add APPROVER_NONE and
	// FACT_NO_SOURCE; without them those checks are not made.
	Approvers Approvers
	Sources   Sources
	// Budget is the tenant's CEL cost budget each sample evaluation runs
	// under (HR-043, D26); New sets the default, the caller the tenant's.
	Budget uint64
	now    func() time.Time
}

// New returns a validator. subjects may be nil.
func New(definitions Definitions, facts Catalog, subjects Subjects, limits celenv.Limits) *Validator {
	return &Validator{defs: definitions, facts: facts, subjects: subjects, limits: limits, Budget: papp.DefaultBudget, now: time.Now}
}

// inputs are what one validation reads.
type inputs struct {
	defs     []*defs.Definition
	catalog  map[string]fdomain.Type
	subjects map[string]string
}

func (v *Validator) read(ctx context.Context, org ids.OrgID) (inputs, error) {
	var in inputs
	var err error
	if in.defs, err = v.defs.ActiveDefinitions(ctx, org); err != nil {
		return in, fmt.Errorf("validate: definitions: %w", err)
	}
	if in.catalog, err = v.facts.Catalog(ctx, org); err != nil {
		return in, fmt.Errorf("validate: fact catalog: %w", err)
	}
	if v.subjects != nil {
		if in.subjects, err = v.subjects.FactSubjects(ctx, org); err != nil {
			return in, fmt.Errorf("validate: fact subjects: %w", err)
		}
	}
	return in, nil
}

// Validate checks b for org. An error means a read failed; a bundle with
// problems is a result with findings, and Passed is false when any is an
// ERROR.
func (v *Validator) Validate(ctx context.Context, org ids.OrgID, b *pdomain.Bundle) (pdomain.ValidationResult, error) {
	var res pdomain.ValidationResult
	in, err := v.read(ctx, org)
	if err != nil {
		return res, err
	}
	res.DefinitionsDigest, res.CatalogDigest = pdomain.DefinitionsDigest(in.defs), pdomain.CatalogDigest(in.catalog)
	add := func(f pdomain.Finding) { res.Findings = append(res.Findings, f) }
	if err := b.Validate(); err != nil {
		add(pdomain.Finding{Code: CodeCompileError, Severity: pdomain.SeverityError, Detail: err.Error()})
		return res, nil //nolint:nilerr // an invalid bundle is a finding, not a failure to validate
	}
	for i := range b.Rules {
		for _, f := range static(&b.Rules[i], in) {
			add(f)
		}
	}
	engine := &papp.Engine{Limits: v.limits, Facts: in.catalog, Subjects: in.subjects}
	compiled := true
	for i := range b.Rules {
		r := b.Rules[i]
		if _, err := engine.Compile(&pdomain.Bundle{ID: b.ID, Version: b.Version, Rules: []pdomain.Rule{r}}, in.defs); err != nil {
			compiled = false
			add(pdomain.Finding{Code: CodeCompileError, Severity: pdomain.SeverityError, Rules: []string{r.ID}, Detail: err.Error()})
		}
	}
	for _, f := range redundant(b.Rules) {
		add(f)
	}
	if compiled {
		res.Findings = append(res.Findings, v.sampled(ctx, b, in, engine)...)
	}
	more, err := v.optional(ctx, org, b, in)
	if err != nil {
		return res, err
	}
	res.Findings = append(res.Findings, more...)
	res.Passed = !slices.ContainsFunc(res.Findings, func(f pdomain.Finding) bool { return f.Severity == pdomain.SeverityError })
	return res, nil
}

// matching are the active definitions a rule's operations cover.
func matching(r *pdomain.Rule, ds []*defs.Definition) []*defs.Definition {
	var out []*defs.Definition
	for _, d := range ds {
		if r.CoversOperation(d.Operation) {
			out = append(out, d)
		}
	}
	return out
}

// static finds what the rule says about the definitions and the catalog,
// without evaluating anything.
func static(r *pdomain.Rule, in inputs) []pdomain.Finding {
	var out []pdomain.Finding
	errf := func(code, format string, args ...any) {
		out = append(out, pdomain.Finding{Code: code, Severity: pdomain.SeverityError, Rules: []string{r.ID}, Detail: fmt.Sprintf(format, args...)})
	}
	for _, op := range r.Operations {
		probe := pdomain.Rule{Operations: []string{op}}
		if len(matching(&probe, in.defs)) == 0 {
			errf(CodeOperationUnknown, "rule %s: no active definition matches %s", r.ID, op)
		}
	}
	for _, f := range r.Facts {
		if _, ok := in.catalog[f.Name]; !ok {
			errf(CodeFactUnknown, "rule %s: no provider declares fact %s", r.ID, f.Name)
		}
	}
	if c := r.Constraint; r.Kind == pdomain.Constrain && c != nil {
		for _, d := range matching(r, in.defs) {
			if c.Kind == pdomain.Verify {
				if v := d.Verifier; v == nil || !v.Extended() || v.Reaches().Rank() < c.Level.Rank() {
					errf(CodeVerifyUnreachable, "rule %s: the verifier of %s cannot reach %s, so every action it matches would be CANNOT_AUTHORIZE",
						r.ID, d.Operation, c.Level)
				}
				continue
			}
			if c.Kind.ScopeKind() {
				// A data scope rule needs the definition to declare it can
				// enforce that kind (G0 M14 D11).
				need := map[pdomain.ConstraintKind]string{pdomain.RecordScope: "records", pdomain.DataClasses: "classes"}[c.Kind]
				if !slices.Contains(d.Scoping, need) {
					errf(CodeConstraintUnsupported, "rule %s: %s cannot limit the %s of its answer, so every action it matches would be CANNOT_AUTHORIZE",
						r.ID, d.Operation, need)
				}
				continue
			}
			if _, ok := d.Supports(defs.ConstraintKind(c.Kind), c.Param); !ok {
				errf(CodeConstraintUnsupported, "rule %s: %s does not declare %s on %q, so every action it matches would be CANNOT_AUTHORIZE",
					r.ID, d.Operation, c.Kind, c.Param)
			}
		}
	}
	return out
}

// redundant finds a CONSTRAIN rule that a stricter one with the same
// condition, scope and constraint makes useless (INFO).
func redundant(rules []pdomain.Rule) []pdomain.Finding {
	var out []pdomain.Finding
	for i := range rules {
		a := &rules[i]
		for j := range rules {
			b := &rules[j]
			if i == j || a.Kind != pdomain.Constrain || b.Kind != pdomain.Constrain || a.When != b.When ||
				!sameSet(a.Operations, b.Operations) || !sameSet(a.Environments, b.Environments) {
				continue
			}
			ca, cb := a.Constraint, b.Constraint
			if ca.Kind != cb.Kind || ca.Param != cb.Param || ca.Currency != cb.Currency || ca.Kind == pdomain.Verify {
				continue
			}
			// a is redundant when b is at least as strict, and strictly so or
			// earlier (so of two equal rules only the second is reported).
			d := pdomain.Compare(
				&pdomain.Bundle{Rules: []pdomain.Rule{{ID: "x", Kind: pdomain.Constrain, Constraint: cb}}},
				&pdomain.Bundle{Rules: []pdomain.Rule{{ID: "x", Kind: pdomain.Constrain, Constraint: ca}}},
			).Direction
			if d == pdomain.Looser || (d == pdomain.Neutral && j < i) {
				out = append(out, pdomain.Finding{
					Code: CodeRedundant, Severity: pdomain.SeverityInfo, Rules: []string{a.ID, b.ID},
					Detail: fmt.Sprintf("rule %s is a looser duplicate of rule %s and never limits anything %s does not", a.ID, b.ID, b.ID),
				})
				break
			}
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// matchBundle is b with every rule turned into a FORBID with the same
// scope, condition and facts: evaluated, its checklist shows exactly which
// conditions match an action.
func matchBundle(b *pdomain.Bundle) *pdomain.Bundle {
	m := &pdomain.Bundle{ID: b.ID, Version: b.Version}
	for _, r := range b.Rules {
		r.Kind, r.Approval, r.StepUp, r.Constraint, r.Labels = pdomain.Forbid, nil, nil, nil, nil
		m.Rules = append(m.Rules, r)
	}
	return m
}

// operations are the definitions in some rule's scope, each with the facts
// rules on it read and its prerequisites the catalog declares.
func operations(rules []pdomain.Rule, in inputs) ([]*defs.Definition, map[string][]string) {
	var ds []*defs.Definition
	facts := map[string][]string{}
	for _, d := range in.defs {
		set := map[string]bool{}
		covered := false
		for i := range rules {
			if rules[i].CoversOperation(d.Operation) {
				covered = true
				for _, f := range rules[i].Facts {
					set[f.Name] = true
				}
			}
		}
		if !covered {
			continue
		}
		for _, p := range d.Prerequisites {
			if _, ok := in.catalog[p.Fact]; ok {
				set[p.Fact] = true
			}
		}
		ds = append(ds, d)
		facts[d.Digest] = slices.Sorted(maps.Keys(set))
	}
	return ds, facts
}

// sampled finds CONFLICT and SHADOWED on generated samples.
func (v *Validator) sampled(ctx context.Context, b *pdomain.Bundle, in inputs, engine *papp.Engine) []pdomain.Finding {
	mc, err := engine.Compile(matchBundle(b), in.defs)
	if err != nil {
		return nil // every rule compiled alone; nothing to sample if they do not together
	}
	ds, facts := operations(b.Rules, in)
	g := &generator{lit: collect(b.Rules), catalog: in.catalog, now: v.now(), budget: v.Budget}
	index := map[string]int{}
	for i, r := range b.Rules {
		index[r.ID] = i
	}
	// matchedOn[i] counts samples rule i matches; shadowedOn[i] those where
	// an earlier FORBID matches too.
	matchedOn, shadowedOn := make([]int, len(b.Rules)), make([]int, len(b.Rules))
	shadowers := make([]map[string]bool, len(b.Rules))
	conflicts := map[[2]int]*pdomain.Finding{}
	for _, d := range ds {
		for _, s := range g.samples(d, facts[d.Digest]) {
			out, err := mc.Evaluate(ctx, s.def, s.action, s.in)
			if err != nil {
				continue // the sample does not decode: not an action
			}
			var matched []int
			for _, it := range out.Checklist {
				if it.Status == pdomain.StatusFailed {
					matched = append(matched, index[it.Rule])
				}
			}
			slices.Sort(matched)
			for _, i := range matched {
				matchedOn[i]++
				for _, j := range matched {
					if j < i && b.Rules[j].Kind == pdomain.Forbid {
						shadowedOn[i]++
						if shadowers[i] == nil {
							shadowers[i] = map[string]bool{}
						}
						shadowers[i][b.Rules[j].ID] = true
						break
					}
				}
				for _, j := range matched {
					if j <= i || conflicts[[2]int{i, j}] != nil {
						continue
					}
					if why := conflict(&b.Rules[i], &b.Rules[j]); why != "" {
						conflicts[[2]int{i, j}] = &pdomain.Finding{
							Code: CodeConflict, Severity: pdomain.SeverityError, Rules: []string{b.Rules[i].ID, b.Rules[j].ID},
							Detail: why + "; the example action matches both, so no value could satisfy them", Example: s.example(), SampleBased: true,
						}
					}
				}
			}
		}
	}
	var found []pdomain.Finding
	for _, k := range slices.SortedFunc(maps.Keys(conflicts), func(a, b [2]int) int {
		if a[0] != b[0] {
			return a[0] - b[0]
		}
		return a[1] - b[1]
	}) {
		found = append(found, *conflicts[k])
	}
	for i, r := range b.Rules {
		if matchedOn[i] == 0 || shadowedOn[i] != matchedOn[i] {
			continue
		}
		by := slices.Sorted(maps.Keys(shadowers[i]))
		found = append(found, pdomain.Finding{
			Code: CodeShadowed, Severity: pdomain.SeverityWarning, Rules: append([]string{r.ID}, by...), SampleBased: true,
			Detail: fmt.Sprintf("rule %s never decides on any sample: wherever it matches, an earlier FORBID (%s) matches too", r.ID, strings.Join(by, ", ")),
		})
	}
	return found
}

// conflict says why two CONSTRAIN rules cannot both hold, or "".
func conflict(a, b *pdomain.Rule) string {
	if a.Kind != pdomain.Constrain || b.Kind != pdomain.Constrain {
		return ""
	}
	ca, cb := a.Constraint, b.Constraint
	if ca.Kind != cb.Kind {
		return ""
	}
	switch ca.Kind { //nolint:exhaustive // count_max and verify always have a common value
	case pdomain.AmountMax:
		if ca.Param == cb.Param && ca.Currency != cb.Currency {
			return fmt.Sprintf("rules %s and %s limit params.%s in %s and in %s", a.ID, b.ID, ca.Param, cmpOr(ca.Currency, "no currency"), cmpOr(cb.Currency, "no currency"))
		}
	case pdomain.AllowedValues, pdomain.TargetSet, pdomain.DestinationSet:
		if ca.Param != cb.Param || slices.ContainsFunc(ca.Values, func(x string) bool { return slices.Contains(cb.Values, x) }) {
			return ""
		}
		what := string(ca.Kind)
		if ca.Param != "" {
			what += " on params." + ca.Param
		}
		return fmt.Sprintf("rules %s and %s allow disjoint sets (%s)", a.ID, b.ID, what)
	}
	return ""
}

// optional runs the checks whose ports are set.
func (v *Validator) optional(ctx context.Context, org ids.OrgID, b *pdomain.Bundle, in inputs) ([]pdomain.Finding, error) {
	var out []pdomain.Finding
	if v.Approvers != nil {
		counted := map[string]int{}
		for _, r := range b.Rules {
			if r.Approval == nil {
				continue
			}
			n, ok := counted[r.Approval.Role]
			if !ok {
				var err error
				if n, err = v.Approvers.Approvers(ctx, org, r.Approval.Role); err != nil {
					return nil, fmt.Errorf("validate: approvers: %w", err)
				}
				counted[r.Approval.Role] = n
			}
			if n == 0 {
				out = append(out, pdomain.Finding{
					Code: CodeApproverNone, Severity: pdomain.SeverityWarning, Rules: []string{r.ID},
					Detail: fmt.Sprintf("rule %s: no person holds the %s role, so its holds would wait until their deadline", r.ID, r.Approval.Role),
				})
			}
		}
	}
	if v.Sources != nil {
		supplied, err := v.Sources.SuppliedFacts(ctx, org)
		if err != nil {
			return nil, fmt.Errorf("validate: fact sources: %w", err)
		}
		for _, r := range b.Rules {
			for _, f := range r.Facts {
				if _, declared := in.catalog[f.Name]; declared && !supplied[f.Name] {
					out = append(out, pdomain.Finding{
						Code: CodeFactNoSource, Severity: pdomain.SeverityWarning, Rules: []string{r.ID},
						Detail: fmt.Sprintf("rule %s: no active provider or connection supplies %s, so the actions it covers would be CANNOT_AUTHORIZE", r.ID, f.Name),
					})
				}
			}
		}
	}
	return out, nil
}
