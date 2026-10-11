// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app compiles policy bundles and evaluates them against actions.
// Conditions are type-checked per action definition when a bundle is
// compiled, so a rule that compares a string, forgets a has() guard or names
// a field the operation does not have is refused before publication.
// Evaluation is fail-closed (HR-040) and bounded by a per-tenant cost budget
// (HR-043); the result is a policy verdict that the decision pipeline
// (part 2) combines with grants, budgets and facts.
package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	"cel.dev/cel-go/cel"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// BundleStore returns an org's published bundle. The tables arrive after
// M2 (migrations from 00020).
type BundleStore interface {
	Published(ctx context.Context, org ids.OrgID) (*domain.Bundle, error)
}

// DefaultBudget is the recommended per-evaluation cost budget (G0 M4,
// decision 8); a tenant's configured budget replaces it.
const DefaultBudget = 100_000

// Engine compiles and evaluates bundles.
type Engine struct {
	Limits celenv.Limits
	// Facts types the facts rules may read: the org's provider
	// declarations, by fact name. A rule reading a fact no provider
	// declares is refused at compile time.
	Facts map[string]fdomain.Type
}

// Compiled is a bundle with its conditions compiled per definition digest.
type Compiled struct {
	Bundle *domain.Bundle
	limits celenv.Limits
	facts  map[string]fdomain.Type
	mu     sync.Mutex
	byDef  map[string]map[string]compiledRule // definition digest → rule id
}

type compiledRule struct {
	prog *celenv.Program
	err  error
	// needs lists the facts the rule reads plus the definition's
	// prerequisites that have a provider; all must be present to run it.
	needs []string
}

// Compile validates the bundle and type-checks every rule against every
// definition in its scope. Any failure refuses the whole bundle.
func (e *Engine) Compile(b *domain.Bundle, definitions []*defs.Definition) (*Compiled, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	c := &Compiled{Bundle: b, limits: e.Limits, facts: e.Facts, byDef: map[string]map[string]compiledRule{}}
	var errs []error
	for _, d := range definitions {
		for id, cr := range c.forDefinition(d) {
			if cr.err != nil {
				errs = append(errs, fmt.Errorf("rule %s on %s: %w", id, d.Operation, cr.err))
			}
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%w: %w", domain.ErrInvalid, errors.Join(errs...))
	}
	return c, nil
}

// forDefinition compiles (once) the rules that apply to a definition. A
// definition activated after the bundle was compiled is handled here too;
// a compile error then fails that rule closed at evaluation.
func (c *Compiled) forDefinition(d *defs.Definition) map[string]compiledRule {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rules, ok := c.byDef[d.Digest]; ok {
		return rules
	}
	rules := map[string]compiledRule{}
	for i := range c.Bundle.Rules {
		r := &c.Bundle.Rules[i]
		if !r.CoversOperation(d.Operation) {
			continue
		}
		needs, err := c.factsFor(d, r)
		if err != nil {
			rules[r.ID] = compiledRule{err: err}
			continue
		}
		schema := ActionSchema(d)
		maps.Copy(schema, FactsSchema(needs, c.facts))
		env, err := celenv.New(c.limits, schema, ActionVariable, FactsVariable, NowVariable)
		if err != nil {
			rules[r.ID] = compiledRule{err: err}
			continue
		}
		p, cerr := env.Compile(r.When, cel.BoolType)
		rules[r.ID] = compiledRule{prog: p, err: cerr, needs: needs}
	}
	c.byDef[d.Digest] = rules
	return rules
}

// evaluation order: prohibitions first, so they are found even when the
// budget runs out later; annotations last.
var kindOrder = []domain.Kind{domain.Forbid, domain.Constrain, domain.RequireApproval, domain.RequireStepUp, domain.Annotate}

// Evaluate runs the compiled bundle against one parsed action. The action's
// params are decoded with its definition first; ambiguous params are an
// error (CANNOT_AUTHORIZE upstream, HR-103). A rule whose facts are not all
// in the input is not evaluated: missing evidence is CANNOT_AUTHORIZE,
// never a denial (F096).
func (c *Compiled) Evaluate(ctx context.Context, d *defs.Definition, a actionir.ActionIR, in Input) (domain.Outcome, error) {
	budget := in.Budget
	if a.Operation != d.Operation || a.Definition.Digest != d.Digest {
		return domain.Outcome{}, fmt.Errorf("%w: action does not pin this definition", actionir.ErrAmbiguous)
	}
	vals, err := d.DecodeParams(a.Params)
	if err != nil {
		return domain.Outcome{}, err
	}
	action := ActionRecord(d, a, vals, in.DestinationClass)
	now := in.Now.Unix()
	compiled := c.forDefinition(d)
	rules := make([]*domain.Rule, 0, len(c.Bundle.Rules))
	for i := range c.Bundle.Rules {
		rules = append(rules, &c.Bundle.Rules[i])
	}
	slices.SortStableFunc(rules, func(x, y *domain.Rule) int {
		return slices.Index(kindOrder, x.Kind) - slices.Index(kindOrder, y.Kind)
	})
	var spent uint64
	results := make([]domain.Result, 0, len(rules))
	for _, r := range rules {
		res := domain.Result{Rule: r}
		cr, inScope := compiled[r.ID]
		switch {
		case !inScope || !r.Applies(a.Operation, a.Env):
			res.Effect = domain.OutOfScope
		case spent >= budget:
			res.Effect, res.Detail = domain.CostExceeded, "tenant cost budget exhausted before this rule"
		case cr.err != nil:
			res.Effect, res.Detail = domain.EvalError, cr.err.Error()
		case missingFact(cr.needs, in.Facts) != "":
			res.Effect, res.Detail = domain.FactsMissing, "fact "+missingFact(cr.needs, in.Facts)+" is missing or stale"
		default:
			vars := map[string]any{"action": action, "facts": FactsRecord(cr.needs, in.Facts), "now": now}
			matched, cost, err := cr.prog.EvalBool(ctx, vars)
			spent += cost
			switch {
			case errors.Is(err, celenv.ErrCost) || spent > budget:
				res.Effect, res.Detail = domain.CostExceeded, "cost budget exceeded"
			case err != nil:
				res.Effect, res.Detail = domain.EvalError, err.Error()
			case !matched:
				res.Effect = domain.NotMatched
			case r.Kind == domain.Constrain:
				res = constrain(d, a, vals, r)
			default:
				res.Effect = domain.Matched
			}
		}
		results = append(results, res)
	}
	return domain.Compose(results), nil
}

// constrain checks a matched CONSTRAIN rule against the action (F100,
// F104, F105). The definition must declare the constraint; a value over a
// limit is a violation unless the definition declares clamping safe, in
// which case the gateway must clamp it before execution.
func constrain(d *defs.Definition, a actionir.ActionIR, vals defs.Values, r *domain.Rule) domain.Result {
	c := r.Constraint
	res := domain.Result{Rule: r, Effect: domain.Matched}
	if c.Kind == domain.Verify {
		// Not a limit the definition declares: the Authority raises the
		// level the effect must be verified at, and step 8 refuses the
		// action when the verifier cannot reach it (G0 M7 design decision 2).
		res.Obligation = &domain.Obligation{Rule: r.ID, Kind: c.Kind, Level: c.Level, Timing: domain.TimingAfterDispatch}
		res.Detail = "the effect must be verified at " + string(c.Level) + " level"
		return res
	}
	spec, ok := d.Supports(defs.ConstraintKind(c.Kind), c.Param)
	if !ok {
		res.Effect, res.Detail = domain.Unsupported, fmt.Sprintf("%s does not support %s on %q", d.Operation, c.Kind, c.Param)
		return res
	}
	v, present := vals[c.Param]
	fail := func(effect domain.Effect, format string, args ...any) domain.Result {
		res.Effect, res.Detail = effect, fmt.Sprintf(format, args...)
		return res
	}
	switch c.Kind { //nolint:exhaustive // verify returned above
	case domain.AmountMax:
		if !present {
			return fail(domain.EvalError, "params.%s is absent; the limit cannot be checked", c.Param)
		}
		limit, err := money.Parse(c.Max)
		if err != nil {
			return fail(domain.EvalError, "max %q: %v", c.Max, err)
		}
		amount := v.Decimal
		if v.Type == defs.TypeMoney {
			if string(v.Money.Currency) != c.Currency {
				return fail(domain.EvalError, "params.%s is in %s; the limit is in %q", c.Param, v.Money.Currency, c.Currency)
			}
			amount = v.Money.Amount
		}
		if amount.Cmp(limit) > 0 {
			return fail(domain.Violated, "params.%s %s exceeds %s %s; permitted: at most %s %s", c.Param, amount, c.Max, c.Currency, c.Max, c.Currency)
		}
	case domain.CountMax:
		limit, err := strconv.ParseInt(c.Max, 10, 64)
		if err != nil {
			return fail(domain.EvalError, "max %q is not an integer", c.Max)
		}
		if present && v.Int <= limit {
			return res
		}
		if !spec.Clamp {
			return fail(domain.Violated, "params.%s must be at most %d", c.Param, limit)
		}
		res.Obligation = &domain.Obligation{Rule: r.ID, Kind: c.Kind, Param: c.Param, Max: c.Max, Clamp: true, Timing: domain.TimingBeforeExecution}
		res.Detail = fmt.Sprintf("params.%s clamped to %d before execution", c.Param, limit)
	case domain.AllowedValues:
		if !present {
			return fail(domain.EvalError, "params.%s is absent; the allowed values cannot be checked", c.Param)
		}
		got := v.List
		if v.Type != defs.TypeIdentifierList {
			got = []string{v.Str}
		}
		for _, s := range got {
			if !slices.Contains(c.Values, s) {
				return fail(domain.Violated, "params.%s %q is not allowed; permitted: %v", c.Param, s, c.Values)
			}
		}
	case domain.TargetSet:
		if !slices.Contains(c.Values, a.Target.ID) {
			return fail(domain.Violated, "target %q is outside the permitted set %v", a.Target.ID, c.Values)
		}
	case domain.DestinationSet:
		for _, dst := range a.Destinations {
			if !slices.Contains(c.Values, dst.ID) {
				return fail(domain.Violated, "destination %q is outside the permitted set %v", dst.ID, c.Values)
			}
		}
	}
	return res
}

// factsFor returns the facts a rule may read on a definition: the facts it
// declares, each of which a provider must declare, and the definition's
// prerequisites that a provider declares.
func (c *Compiled) factsFor(d *defs.Definition, r *domain.Rule) ([]string, error) {
	var needs []string
	for _, f := range r.Facts {
		if _, ok := c.facts[f.Name]; !ok {
			return nil, fmt.Errorf("no provider declares fact %q", f.Name)
		}
		needs = append(needs, f.Name)
	}
	for _, p := range d.Prerequisites {
		if _, ok := c.facts[p.Fact]; ok && !slices.Contains(needs, p.Fact) {
			needs = append(needs, p.Fact)
		}
	}
	slices.Sort(needs)
	return needs, nil
}

// Input is what one evaluation reads besides the action: the tenant's cost
// budget (HR-043), the present and fresh facts about the action's target by
// name (pipeline step 6), and the decision time from the database clock.
type Input struct {
	Budget uint64
	Facts  map[string]fdomain.Value
	Now    time.Time
	// DestinationClass is the class of the connection the action came
	// through, from the Authority's own records ("public" or "internal";
	// "" for an action without a connection, HR-079).
	DestinationClass string
}

func missingFact(needs []string, have map[string]fdomain.Value) string {
	for _, n := range needs {
		if _, ok := have[n]; !ok {
			return n
		}
	}
	return ""
}

// FactRequirements returns the facts the rules in scope of an operation and
// environment declare, with their maximum ages (pipeline step 6). The
// definition's prerequisites are added by the caller.
func (c *Compiled) FactRequirements(operation, env string) []fdomain.Requirement {
	var out []fdomain.Requirement
	for i := range c.Bundle.Rules {
		r := &c.Bundle.Rules[i]
		if !r.Applies(operation, env) {
			continue
		}
		for _, f := range r.Facts {
			out = append(out, fdomain.Requirement{Name: f.Name, MaxAge: time.Duration(f.MaxAgeSeconds) * time.Second, Source: "rule " + r.ID})
		}
	}
	return out
}
