// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package scenario runs a policy bundle's scenario tests and its mutation
// gate (M11.1 D7, F193–F195, HR-044). Each case is decided by the real
// decision pipeline (steps 1–8) over an in-memory fixture, so a test shows
// what the Authority would decide, not what the policy engine alone says.
// A bundle passes only when every case passes, every comparison mutant of
// every condition is killed by a case, and removing any deciding rule is
// noticed by a case.
//
// The runner is read-only (HR-232): it reads the org's active definitions
// and fact catalog through its two ports and nothing else; it never
// finalizes, reserves or records anything. Runs are bounded (HR-238).
//
// The package sits beside internal/policy/app rather than inside it:
// the pipeline imports policy/app, so policy/app must never import this.
package scenario

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
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

// Catalog returns the org's declared fact names and types
// (app.FactCatalog).
type Catalog interface {
	Catalog(ctx context.Context, org ids.OrgID) (map[string]fdomain.Type, error)
}

// Bounds of one run (HR-238).
const (
	MaxCases = pdomain.MaxTests
	// MaxEvaluations counts every pipeline evaluation of a run, mutants
	// included; an approved case takes two.
	MaxEvaluations = 20_000
)

// ErrBundleInvalid is the TestResult error of a bundle that does not
// validate or compile: there is nothing to test.
const ErrBundleInvalid = "BUNDLE_INVALID"

// RemoveRule is the mutation of a removal mutant.
const RemoveRule = "remove rule"

// Runner runs scenario tests. It implements the publish gate's TestRunner
// port (internal/policy/app).
type Runner struct {
	defs   Definitions
	facts  Catalog
	limits celenv.Limits
	budget uint64
	now    func() time.Time
}

// New returns a runner that compiles with limits and evaluates each case
// with the tenant's CEL cost budget per evaluation (HR-043).
func New(definitions Definitions, facts Catalog, limits celenv.Limits, budget uint64) *Runner {
	return &Runner{defs: definitions, facts: facts, limits: limits, budget: budget, now: time.Now}
}

// prepared is a case with its fixture, or why it could not be built.
type prepared struct {
	tc     *pdomain.TestCase
	f      *fixture
	failed string
}

// outcome is what an evaluation decided.
type outcome struct {
	decision, reason, rule string
}

func (o outcome) String() string {
	s := o.decision + " " + o.reason
	if o.rule != "" {
		s += " (rule " + o.rule + ")"
	}
	return s
}

func (o outcome) matches(e pdomain.TestExpect) bool {
	return o.decision == e.Decision && o.reason == e.Reason && (e.Rule == "" || o.rule == e.Rule)
}

// run is one Run's evaluation count.
type run struct {
	evaluations int
}

func (r *run) exceeded() bool { return r.evaluations > MaxEvaluations }

// Run runs the bundle's tests and mutation gate for org. An error means a
// read failed; a bundle that fails the gate is a result with Passed false.
func (r *Runner) Run(ctx context.Context, org ids.OrgID, b *pdomain.Bundle) (pdomain.TestResult, error) {
	var res pdomain.TestResult
	if len(b.Tests) > MaxCases {
		res.Error = pdomain.ErrTestsTooLarge
		return res, nil
	}
	ds, err := r.defs.ActiveDefinitions(ctx, org)
	if err != nil {
		return res, fmt.Errorf("scenario: definitions: %w", err)
	}
	catalog, err := r.facts.Catalog(ctx, org)
	if err != nil {
		return res, fmt.Errorf("scenario: fact catalog: %w", err)
	}
	res.DefinitionsDigest, res.CatalogDigest = pdomain.DefinitionsDigest(ds), pdomain.CatalogDigest(catalog)
	version := fmt.Sprintf("%s@%d", b.ID, b.Version)
	policy, err := r.compile(b, ds, catalog, version)
	if err != nil || policy == nil {
		res.Error = ErrBundleInvalid
		return res, nil //nolint:nilerr // an invalid bundle is a result, not a failure to run
	}
	now := r.now()
	reads := httpReads(ds)
	cases := make([]prepared, len(b.Tests))
	for i := range b.Tests {
		tc := &b.Tests[i]
		cases[i] = prepared{tc: tc}
		def, why := definitionFor(ds, tc.Action.Operation)
		if why != "" {
			cases[i].failed = why
			continue
		}
		f, err := build(org, now, def, catalog, reads, tc)
		if err != nil {
			cases[i].failed = err.Error()
			continue
		}
		cases[i].f = f
	}
	st := &run{}
	passed := true
	for _, c := range cases {
		cr := pdomain.CaseResult{ID: c.tc.ID, Detail: c.failed}
		if c.f != nil {
			o, err := st.evaluate(ctx, c, policy)
			if err != nil {
				return res, err
			}
			cr.Decision, cr.Reason, cr.Rule = o.decision, o.reason, o.rule
			cr.Passed = o.matches(c.tc.Expect)
			if !cr.Passed {
				cr.Detail = "decided " + o.String() + ", expected " + outcome{c.tc.Expect.Decision, c.tc.Expect.Reason, c.tc.Expect.Rule}.String()
			}
		}
		passed = passed && cr.Passed
		res.Cases = append(res.Cases, cr)
	}
	mutants, err := mutantsOf(b)
	if err != nil {
		res.Error = ErrBundleInvalid
		return res, nil //nolint:nilerr // a condition that cannot be parsed did not compile either
	}
	res.Mutants = len(mutants)
	for _, m := range mutants {
		mp, err := r.compile(m.bundle, ds, catalog, version)
		if err != nil {
			continue // a mutant that cannot compile can never be published: it is dead
		}
		killed := false
		for _, c := range cases {
			if c.f == nil {
				continue
			}
			o, err := st.evaluate(ctx, c, mp)
			if err != nil {
				return res, err
			}
			if !o.matches(c.tc.Expect) {
				killed = true
				break
			}
			if st.exceeded() {
				break
			}
		}
		if st.exceeded() {
			return tooLarge(res), nil
		}
		if !killed {
			res.Surviving = append(res.Surviving, pdomain.MutantResult{Rule: m.rule, Mutation: m.mutation})
		}
	}
	if st.exceeded() {
		return tooLarge(res), nil
	}
	res.Survivors = len(res.Surviving)
	res.Passed = passed && res.Survivors == 0
	return res, nil
}

func tooLarge(res pdomain.TestResult) pdomain.TestResult {
	res.Passed, res.Error = false, pdomain.ErrTestsTooLarge
	res.Survivors = len(res.Surviving)
	return res
}

// compile compiles a bundle (nil when it has no rules: no policy).
func (r *Runner) compile(b *pdomain.Bundle, ds []*defs.Definition, catalog map[string]fdomain.Type, version string) (*pipeline.Policy, error) {
	if len(b.Rules) == 0 {
		return nil, nil //nolint:nilnil // no rules is no policy
	}
	c, err := (&papp.Engine{Limits: r.limits, Facts: catalog}).Compile(b, ds)
	if err != nil {
		return nil, err
	}
	return &pipeline.Policy{Compiled: c, Version: version, Budget: r.budget}, nil
}

// evaluate decides one case under policy and counts the evaluations.
func (st *run) evaluate(ctx context.Context, c prepared, policy *pipeline.Policy) (outcome, error) {
	if st.exceeded() {
		return outcome{}, nil
	}
	ev, n, err := c.f.evaluate(ctx, policy, c.tc.Given)
	st.evaluations += n
	if err != nil {
		return outcome{}, fmt.Errorf("scenario: evaluate %s: %w", c.tc.ID, err)
	}
	it := ev.Decisive()
	o := outcome{decision: string(ev.Decision), reason: it.Code}
	if policy != nil {
		if rest, ok := strings.CutPrefix(it.Level, "policy "+policy.Version+" rule "); ok {
			o.rule, _, _ = strings.Cut(rest, " ")
		}
	}
	return o, nil
}

// definitionFor is the one active definition of an operation.
func definitionFor(ds []*defs.Definition, op string) (*defs.Definition, string) {
	var found []*defs.Definition
	for _, d := range ds {
		if d.Operation == op {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 0:
		return nil, "OPERATION_UNKNOWN: no active definition of " + op
	case 1:
		return found[0], ""
	}
	return nil, fmt.Sprintf("%d active definitions of %s: a case cannot tell which one decides", len(found), op)
}

// httpReads are the reads a gateway can make over HTTP for a verifier,
// from every active definition (pipeline.Connection.Reads).
func httpReads(ds []*defs.Definition) []string {
	pkg := &defs.Package{}
	for _, d := range ds {
		pkg.Definitions = append(pkg.Definitions, *d)
	}
	return pkg.HTTPReads()
}

// mutant is a bundle with one change the tests must notice.
type mutant struct {
	rule, mutation string
	bundle         *pdomain.Bundle
}

// mutantsOf lists every comparison mutant of every deciding rule's
// condition (HR-044) and every deciding rule's removal, in rule order.
// ANNOTATE rules decide nothing, so no case could notice a change to
// them.
func mutantsOf(b *pdomain.Bundle) ([]mutant, error) {
	var out []mutant
	with := func(edit func(rules []pdomain.Rule) []pdomain.Rule) *pdomain.Bundle {
		c := *b
		c.Rules = edit(slices.Clone(b.Rules))
		c.Tests = nil
		return &c
	}
	for i, rule := range b.Rules {
		if rule.Kind == pdomain.Annotate {
			continue
		}
		ms, err := papp.Mutants(rule.When)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			out = append(out, mutant{rule: rule.ID, mutation: m, bundle: with(func(rs []pdomain.Rule) []pdomain.Rule {
				rs[i].When = m
				return rs
			})})
		}
		out = append(out, mutant{rule: rule.ID, mutation: RemoveRule, bundle: with(func(rs []pdomain.Rule) []pdomain.Rule {
			return slices.Delete(rs, i, i+1)
		})})
	}
	return out, nil
}
