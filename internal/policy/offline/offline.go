// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package offline checks a policy bundle from files, with no server and no
// network (G0 M23 D120, D121): the same validator, scenario runner and
// mutation gate the publish gate uses, the same rule diff, and the same
// automation simulator, over a file-based source of definitions and facts.
// pclaw ci check prints what Check returns.
//
// A check is read-only and bounded (HR-232, HR-238). Everything a policy,
// package or scenario file says is untrusted text: Markdown and Text
// render it so it can neither render markup nor mention a person (HR-565).
package offline

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	"github.com/katocxl/pantherclaw/internal/policy/validate"
)

// FailOn says which rule changes fail a check. A failed validation or
// scenario always does.
type FailOn string

// Fail-on modes. FailWiden fails on a change that is not provably tighter
// (UNKNOWN counts as looser, M11.1 D3), and on a sample newly allowed.
// FailAny fails on any rule change as well.
const (
	FailWiden FailOn = "widen"
	FailAny   FailOn = "any"
)

// Options name what one check reads.
type Options struct {
	// PolicyFile is the bundle under check (pclaw policy create's format).
	PolicyFile string
	// BaseFile, optional, is the bundle it replaces.
	BaseFile string
	// ScenariosDir, optional, holds scenario fixtures.
	ScenariosDir string
	// PackagesDir, optional, replaces the built-in packages.
	PackagesDir string
	FailOn      FailOn
}

// NotCheckedOffline lists the checks that need the org's own records.
var NotCheckedOffline = []string{
	validate.CodeApproverNone + ": who holds an approval role is a server record",
	validate.CodeFactNoSource + ": which provider supplies a fact is a server record",
}

// OutcomeLimit is what a sample cannot prove (ADR-0004, R-25). Every report
// carries it.
const OutcomeLimit = "an empty sample proves nothing: samples can miss an action the versions decide differently, " +
	"and they show the policy engine alone, not grants, budgets, facts or holds"

// Report is one check's result. Its strings come from the checked files:
// they are untrusted (Markdown and Text render them safely; a JSON reader
// must do the same).
type Report struct {
	Policy     string      `json:"policy"`
	Passed     bool        `json:"passed"`
	FailOn     FailOn      `json:"fail_on"`
	Failures   []string    `json:"failures,omitzero"`
	Validation Validation  `json:"validation"`
	Scenarios  Scenarios   `json:"scenarios"`
	Changes    *RuleChange `json:"rule_changes,omitzero"`
	Outcomes   *Outcomes   `json:"outcome_samples,omitzero"`
}

// Validation is the validator's result.
type Validation struct {
	Passed     bool              `json:"passed"`
	Findings   []pdomain.Finding `json:"findings,omitzero"`
	NotChecked []string          `json:"not_checked"`
}

// Scenarios are the scenario tests, the mutation gate and any automation
// scenarios.
type Scenarios struct {
	Passed       bool                   `json:"passed"`
	Error        string                 `json:"error,omitzero"`
	Cases        []pdomain.CaseResult   `json:"cases,omitzero"`
	Mutants      int                    `json:"mutants"`
	Surviving    []pdomain.MutantResult `json:"surviving,omitzero"`
	Uncompilable []pdomain.MutantResult `json:"uncompilable,omitzero"`
	Automations  []Automation           `json:"automations,omitzero"`
}

// Automation is one automation scenario file's run.
type Automation struct {
	File    string                 `json:"file"`
	Passed  bool                   `json:"passed"`
	Cases   []assurance.CaseResult `json:"cases,omitzero"`
	Missing []string               `json:"missing_kinds,omitzero"`
}

// RuleChange is the rule diff from the base, by direction. Scenario test
// changes are not in it: they change no decision.
type RuleChange struct {
	Direction pdomain.Direction `json:"direction"`
	Looser    []pdomain.Change  `json:"looser,omitzero"`
	Unknown   []pdomain.Change  `json:"unknown,omitzero"`
	Tighter   []pdomain.Change  `json:"tighter,omitzero"`
	Neutral   []pdomain.Change  `json:"neutral,omitzero"`
}

func (c *RuleChange) count() int {
	return len(c.Looser) + len(c.Unknown) + len(c.Tighter) + len(c.Neutral)
}

// Outcomes are the sampled decisions that differ from the base's.
type Outcomes struct {
	Sampled int                      `json:"sampled"`
	Changes []validate.OutcomeChange `json:"changes,omitzero"`
	Limit   string                   `json:"limit"`
	// Error says why no sample ran (a version that does not compile).
	Error string `json:"error,omitzero"`
}

// checkOrg is the org of every check: a fixture needs one, and nothing
// reads it back.
var checkOrg = ids.MustParse[ids.Org]("00000000-0000-7000-8000-000000000001")

// Check runs one check. A nil report with an error is a check that could
// not run (ErrInput: exit 2); a policy that fails is a report with Passed
// false.
func Check(ctx context.Context, o Options) (*Report, error) {
	failOn := cmp.Or(o.FailOn, FailWiden)
	if failOn != FailWiden && failOn != FailAny {
		return nil, inputf("--fail-on %q is not widen or any", o.FailOn)
	}
	w, err := loadWorld(o.PackagesDir)
	if err != nil {
		return nil, err
	}
	fix, err := loadScenarios(o.ScenariosDir)
	if err != nil {
		return nil, err
	}
	raw, err := readBounded(o.PolicyFile)
	if err != nil {
		return nil, err
	}
	var base *pdomain.Bundle
	if o.BaseFile != "" {
		if base, err = decodeBase(o.BaseFile); err != nil {
			return nil, err
		}
	}
	r := &Report{FailOn: failOn, Validation: Validation{NotChecked: NotCheckedOffline}}
	next, err := papp.DecodeBundle(raw)
	if err != nil {
		r.Validation.Findings = []pdomain.Finding{{Code: validate.CodeCompileError, Severity: pdomain.SeverityError, Detail: err.Error()}}
		r.Scenarios.Error = scenario.ErrBundleInvalid
		r.finish()
		return r, nil
	}
	r.Policy = next.ID
	if base != nil {
		r.Changes = byDirection(pdomain.Compare(base, next))
	}
	checked := *next
	checked.Tests = slices.Concat(next.Tests, fix.tests)
	for _, cases := range [][]pdomain.TestCase{checked.Tests, testsOf(base)} {
		if err := w.inferFacts(cases); err != nil {
			return nil, err
		}
	}
	if err := r.check(ctx, w, &checked); err != nil {
		return nil, err
	}
	if err := r.automations(ctx, w, fix.automations); err != nil {
		return nil, err
	}
	if base != nil {
		r.sample(ctx, w, base, next)
	}
	r.finish()
	return r, nil
}

func testsOf(b *pdomain.Bundle) []pdomain.TestCase {
	if b == nil {
		return nil
	}
	return b.Tests
}

// decodeBase decodes the bundle in effect. It already passed a gate once:
// like a stored bundle, it is not held to rules added since. A base that
// does not decode leaves nothing to compare with, so the check cannot run.
func decodeBase(path string) (*pdomain.Bundle, error) {
	raw, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		return nil, inputf("--base %s: %v", path, err)
	}
	if b.Version == 0 {
		b.Version = 1
	}
	return &b, nil
}

func byDirection(d pdomain.Diff) *RuleChange {
	c := &RuleChange{}
	for _, ch := range d.Changes {
		if ch.Field == "test" {
			continue
		}
		switch ch.Direction {
		case pdomain.Looser:
			c.Looser = append(c.Looser, ch)
		case pdomain.Unknown:
			c.Unknown = append(c.Unknown, ch)
		case pdomain.Tighter:
			c.Tighter = append(c.Tighter, ch)
		case pdomain.Neutral:
			c.Neutral = append(c.Neutral, ch)
		}
	}
	switch {
	case len(c.Looser) > 0:
		c.Direction = pdomain.Looser
	case len(c.Unknown) > 0:
		c.Direction = pdomain.Unknown
	case len(c.Tighter) > 0:
		c.Direction = pdomain.Tighter
	default:
		c.Direction = pdomain.Neutral
	}
	return c
}

// check runs the validator and the scenario runner, as the publish gate
// does.
func (r *Report) check(ctx context.Context, w *world, b *pdomain.Bundle) error {
	v := validate.New(w, w, w, celenv.DefaultLimits)
	res, err := v.Validate(ctx, checkOrg, b)
	if err != nil {
		return err
	}
	r.Validation.Passed, r.Validation.Findings = res.Passed, res.Findings
	t, err := scenario.New(w, w, celenv.DefaultLimits, papp.DefaultBudget).Run(ctx, checkOrg, b)
	if err != nil {
		return err
	}
	r.Scenarios = Scenarios{
		Passed: t.Passed, Error: t.Error, Cases: t.Cases, Mutants: t.Mutants, Surviving: t.Surviving, Uncompilable: t.Uncompilable,
	}
	return nil
}

// automations runs each automation scenario file through engine.Simulate
// (assurance.Run), in memory.
func (r *Report) automations(ctx context.Context, w *world, fixtures []automationFixture) error {
	ops := map[string]defs.Reversibility{}
	for _, d := range w.defs {
		ops[d.Operation] = d.Reversibility
	}
	start := time.Now()
	for _, f := range fixtures {
		irreversible := assurance.Irreversible(f.def, ops, false)
		res, err := assurance.Run(ctx, f.def, checkOrg, ids.NewV7(), ids.NewV7(), f.cases, irreversible, start)
		if err != nil {
			return fmt.Errorf("offline: %s: %w", f.name, err)
		}
		r.Scenarios.Automations = append(r.Scenarios.Automations, Automation{File: f.name, Passed: res.Passed(), Cases: res.Cases, Missing: res.Missing})
	}
	return nil
}

// sample compares the versions on generated actions. A version that does
// not compile leaves no sample: the report says why.
func (r *Report) sample(ctx context.Context, w *world, base, next *pdomain.Bundle) {
	v := validate.New(w, w, w, celenv.DefaultLimits)
	r.Outcomes = &Outcomes{Limit: OutcomeLimit}
	changes, n, err := v.OutcomeSample(ctx, checkOrg, base, next)
	if err != nil {
		r.Outcomes.Error = err.Error()
		return
	}
	r.Outcomes.Sampled, r.Outcomes.Changes = n, changes
}

// Failure reasons.
const (
	FailureValidation = "validation failed"
	FailureScenarios  = "scenarios failed"
	FailureWidened    = "the policy widens what the base allows"
	FailureChanged    = "the policy changes rules and --fail-on any is set"
)

func (r *Report) finish() {
	if !r.Validation.Passed {
		r.Failures = append(r.Failures, FailureValidation)
	}
	automations := !slices.ContainsFunc(r.Scenarios.Automations, func(a Automation) bool { return !a.Passed })
	if !r.Scenarios.Passed || !automations {
		r.Failures = append(r.Failures, FailureScenarios)
	}
	if c := r.Changes; c != nil {
		widened := c.Direction == pdomain.Looser || c.Direction == pdomain.Unknown
		if r.Outcomes != nil && slices.ContainsFunc(r.Outcomes.Changes, func(o validate.OutcomeChange) bool { return o.Category == replay.NewlyAllowed }) {
			widened = true
		}
		if widened {
			r.Failures = append(r.Failures, FailureWidened)
		}
		if r.FailOn == FailAny && c.count() > 0 && !widened {
			r.Failures = append(r.Failures, FailureChanged)
		}
	}
	r.Passed = len(r.Failures) == 0
}

// outcomeCounts are the samples that changed, by category, in order.
func outcomeCounts(o *Outcomes) string {
	counts := map[replay.Category]int{}
	for _, c := range o.Changes {
		counts[c.Category]++
	}
	parts := make([]string, 0, len(counts))
	for _, k := range slices.Sorted(maps.Keys(counts)) {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
	}
	return strings.Join(parts, ", ")
}
