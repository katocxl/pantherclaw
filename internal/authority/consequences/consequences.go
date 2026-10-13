// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package consequences evaluates the stored consequence rules of an
// action's operation (G0 M8 P1, F405, HR-206). A rule whose facts are all
// current predicts its consequence when its condition holds and rules it
// out otherwise; when a fact it needs is missing, stale or carries an
// unknown member, the consequence cannot be ruled out and is UNKNOWN. A
// rule that cannot be evaluated is an error, which the pipeline turns into
// CANNOT_AUTHORIZE (HR-040), never into "not triggered".
package consequences

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"cel.dev/cel-go/cel"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// State is what a rule says about its consequence.
type State string

// States of a consequence (00083's decision_consequences.state).
const (
	// Predicted: the rule's facts are current and its condition holds.
	Predicted State = "PREDICTED"
	// Unknown: a fact the rule needs is missing, stale or unknown, so the
	// consequence cannot be ruled out and is treated as predicted.
	Unknown State = "UNKNOWN"
	// NotTriggered: the rule's facts are current and its condition does
	// not hold.
	NotTriggered State = "NOT_TRIGGERED"
)

// Reason codes.
const (
	// ReasonUnknown: "Consequence unknown" (HR-206).
	ReasonUnknown = "CONSEQUENCE_UNKNOWN"
	// ReasonPredicted: a consequence is predicted, and is decided with the
	// action.
	ReasonPredicted = "CONSEQUENCE_PREDICTED"
	// ReasonEvaluation: a rule could not be evaluated (HR-040).
	ReasonEvaluation = "CONSEQUENCE_EVALUATION_ERROR"
)

// FactMaxAge is how old a fact a consequence rule needs may be, unless the
// definition or the policy asks for a younger one. The gateway reads the
// facts a rule names just before it asks for a decision (G0 M8 G4).
const FactMaxAge = 30 * time.Second

// Bounds on what a rule's environments expression may give.
const (
	maxEnvironments   = 32
	maxEnvironmentLen = 100
	maxReasonLen      = 200
)

// Rule is a consequence rule of the action's package version, with the
// definition of its consequence operation from the same version, or nil
// when that version does not define it.
type Rule struct {
	defs.ConsequenceRule
	Definition *defs.Definition
}

// Of returns the rules of package p for operation op, in order, each with
// the definition of its consequence operation in p.
func Of(p *defs.Package, op string) []Rule {
	var out []Rule
	for _, r := range p.Consequences {
		if r.Operation != op {
			continue
		}
		d, _ := p.Definition(r.Consequence.Operation)
		out = append(out, Rule{ConsequenceRule: r, Definition: d})
	}
	return out
}

// IDs are the rules' ids, in order.
func IDs(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

// Input is what the rules of one action are evaluated against.
type Input struct {
	// On is the definition of the action's operation, and TargetID the id
	// of its target.
	On       *defs.Definition
	TargetID string
	// Facts are the current facts about the action's target, by name.
	Facts map[string]fdomain.Fact
	// Ages are the maximum ages the definition and the policy ask for
	// some of those facts; a younger one than FactMaxAge applies.
	Ages map[string]time.Duration
	Now  time.Time
}

// Consequence is one rule's result.
type Consequence struct {
	Rule                           string
	Operation, Effect, Description string
	// Definition is the consequence operation's definition.
	Definition *defs.Definition
	// Target is the consequence's target; Environments are the ones it
	// reaches, when the rule predicts it and says so.
	Target       actionir.Target
	Environments []string
	State        State
	// Unknown says, for an UNKNOWN consequence, why each fact could not
	// be used.
	Unknown []string
	// Err is set when the rule could not be evaluated.
	Err error
	// Used are the facts the rule read, and FactsDigest their digest
	// (F080).
	Used        []fdomain.Fact
	FactsDigest string
}

// ErrRule reports a rule that cannot be evaluated: its consequence
// operation is not defined, its target cannot be formed, or a CEL
// expression fails (HR-040).
var ErrRule = errors.New("consequences: the rule cannot be evaluated")

// Evaluator evaluates rules, keeping the programs it compiled.
type Evaluator struct {
	limits celenv.Limits

	mu       sync.Mutex
	programs map[string]*celenv.Program
}

// maxPrograms bounds the compiled programs kept.
const maxPrograms = 512

// NewEvaluator returns an evaluator with the given CEL limits.
func NewEvaluator(limits celenv.Limits) *Evaluator {
	return &Evaluator{limits: limits, programs: map[string]*celenv.Program{}}
}

// Evaluate evaluates every rule, in order.
func (e *Evaluator) Evaluate(ctx context.Context, rules []Rule, in Input) []Consequence {
	out := make([]Consequence, 0, len(rules))
	for _, r := range rules {
		out = append(out, e.one(ctx, r, in))
	}
	return out
}

func (e *Evaluator) one(ctx context.Context, r Rule, in Input) Consequence {
	c := Consequence{
		Rule: r.ID, Operation: r.Consequence.Operation, Effect: r.Consequence.Effect, Description: r.Consequence.Description,
		Definition: r.Definition,
	}
	if r.Definition == nil {
		c.Err = fmt.Errorf("%w: %s is not defined in the package", ErrRule, r.Consequence.Operation)
		return c
	}
	id, ok := r.TargetID(in.On.Target, in.TargetID)
	if !ok || !r.Definition.Target.MatchID(id) {
		c.Err = fmt.Errorf("%w: its target is not a %s", ErrRule, r.Definition.Target.Type)
		return c
	}
	c.Target = actionir.Target{Type: r.Definition.Target.Type, ID: id}

	values := map[string]fdomain.Value{}
	types := map[string]fdomain.Type{}
	for _, name := range r.RequiresFacts {
		f, ok := in.Facts[name]
		if !ok {
			c.Unknown = append(c.Unknown, name+" is not known")
			continue
		}
		c.Used = append(c.Used, f)
		maxAge := FactMaxAge
		if a, ok := in.Ages[name]; ok && a < maxAge {
			maxAge = a
		}
		if age := in.Now.Sub(f.ObservedAt); age > maxAge {
			c.Unknown = append(c.Unknown, fmt.Sprintf("%s is %s old; at most %s is accepted", name, age.Round(time.Second), maxAge))
			continue
		}
		if f.Value.Type == fdomain.TypeObject {
			if why, ok := f.Value.Object[fdomain.UnknownMember]; ok {
				c.Unknown = append(c.Unknown, name+" is unknown: "+reason(why))
				continue
			}
		}
		values[name], types[name] = f.Value, f.Value.Type
	}
	c.FactsDigest = fdomain.Digest(c.Used)
	if len(c.Unknown) > 0 {
		c.State = Unknown
		return c
	}
	vars := map[string]any{
		papp.FactsVariable.Name: papp.FactsRecord(r.RequiresFacts, values),
		papp.NowVariable.Name:   in.Now.Unix(),
	}
	when, err := e.program(r.RequiresFacts, types, r.When, cel.BoolType)
	if err != nil {
		c.Err = fmt.Errorf("%w: when: %w", ErrRule, err)
		return c
	}
	hit, _, err := when.EvalBool(ctx, vars)
	switch {
	case err != nil:
		c.Err = fmt.Errorf("%w: when: %w", ErrRule, err)
		return c
	case !hit:
		c.State = NotTriggered
		return c
	}
	c.State = Predicted
	if r.Consequence.Environments != "" {
		if c.Environments, err = e.environments(ctx, r, types, vars); err != nil {
			c.Err = fmt.Errorf("%w: environments: %w", ErrRule, err)
		}
	}
	return c
}

// environments evaluates the rule's environments expression: a list of
// distinct, short, printable names.
func (e *Evaluator) environments(ctx context.Context, r Rule, types map[string]fdomain.Type, vars map[string]any) ([]string, error) {
	prg, err := e.program(r.RequiresFacts, types, r.Consequence.Environments, nil)
	if err != nil {
		return nil, err
	}
	v, _, err := prg.Eval(ctx, vars)
	if err != nil {
		return nil, err
	}
	native, err := v.ConvertToNative(reflect.TypeFor[[]string]())
	if err != nil {
		return nil, fmt.Errorf("not a list of strings: %w", err)
	}
	envs, _ := native.([]string)
	if len(envs) > maxEnvironments {
		return nil, fmt.Errorf("%d environments, at most %d", len(envs), maxEnvironments)
	}
	for _, env := range envs {
		if env == "" || len(env) > maxEnvironmentLen || strings.ContainsFunc(env, unicode.IsControl) {
			return nil, fmt.Errorf("environment %q", env)
		}
	}
	slices.Sort(envs)
	return slices.Compact(envs), nil
}

// program compiles src over the rule's facts with their types, or returns
// the program compiled earlier.
func (e *Evaluator) program(names []string, types map[string]fdomain.Type, src string, want *cel.Type) (*celenv.Program, error) {
	var key strings.Builder
	for _, n := range names {
		key.WriteString(n + ":" + string(types[n]) + ";")
	}
	if want != nil {
		key.WriteString(want.String())
	}
	key.WriteString("\x00" + src)
	e.mu.Lock()
	prg, ok := e.programs[key.String()]
	e.mu.Unlock()
	if ok {
		return prg, nil
	}
	env, err := celenv.New(e.limits, papp.FactsSchema(names, types), papp.FactsVariable, papp.NowVariable)
	if err != nil {
		return nil, err
	}
	if prg, err = env.Compile(src, want); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.programs) >= maxPrograms {
		e.programs = map[string]*celenv.Program{}
	}
	e.programs[key.String()] = prg
	return prg, nil
}

// reason is an unknown member's text as a short, printable reason: it
// comes from a fact provider.
func reason(v any) string {
	s, ok := v.(string)
	if !ok || s == "" {
		return "no reason given"
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	if len(s) > maxReasonLen {
		s = strings.ToValidUTF8(s[:maxReasonLen], "") + "…"
	}
	return s
}
