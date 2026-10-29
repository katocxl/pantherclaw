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
	// ReasonExpired: the rule's review has expired, so its consequence
	// cannot be ruled out (G0 M17 D110, HR-456).
	ReasonExpired = "CONSEQUENCE_RULE_EXPIRED"
	// ReasonFanout: the action's rules give more consequences than
	// MaxConsequences, so the rest cannot be ruled out (D109, HR-455).
	ReasonFanout = "CONSEQUENCE_FANOUT"
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
	// Source is where the rule comes from; empty is SourcePackage.
	Source Source
	// Customer is, for a customer rule (SourceCustomer), the stored version
	// it is, which a recording names (G0 M17 D106).
	Customer *CustomerRef
}

// Of returns the rules of package p that can apply to an action of
// operation op, in package order, each with the definition of its
// consequence operation in p: those for op, then, down a chain (G0 M17
// D109), those for the operation of a consequence they predict that apply
// that deep (MaxDepth). A package without such rules gives the rules for
// op alone, as before chains.
func Of(p *defs.Package, op string) []Rule {
	reached := map[string]bool{op: true}
	in := map[int]bool{}
	frontier := []string{op}
	for depth := 1; depth <= MaxDepth && len(frontier) > 0; depth++ {
		var next []string
		for i, r := range p.Consequences {
			if in[i] || !slices.Contains(frontier, r.Operation) || r.Depth() < depth {
				continue
			}
			in[i] = true
			if c := r.Consequence.Operation; !reached[c] {
				reached[c] = true
				next = append(next, c)
			}
		}
		frontier = next
	}
	var out []Rule
	for i, r := range p.Consequences {
		if !in[i] {
			continue
		}
		d, _ := p.Definition(r.Consequence.Operation)
		out = append(out, Rule{ConsequenceRule: r, Definition: d})
	}
	return out
}

// Direct are the rules for operation op itself: those whose facts are
// about the action's own target.
func Direct(rules []Rule, op string) []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Operation == op {
			out = append(out, r)
		}
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
	// More reads, for a predicted consequence that rules further down a
	// chain apply to, the current facts about its target (of definition
	// on) that those rules name, and the maximum ages the policy asks for
	// them (G0 M17 D109). Without it those rules have no facts, so their
	// consequences are UNKNOWN.
	More func(ctx context.Context, on *defs.Definition, targetID string, names []string) (map[string]fdomain.Fact, map[string]time.Duration, error)
	// Direct decides as pipeline version 4 did, for its replay (G0 M17
	// D133, D134): the rules for the action's operation only, no chain and no
	// expiry.
	Direct bool
}

// MaxConsequences is how many consequences one action's rules give at
// most (G0 M17 D109). A rule that would give one more is UNKNOWN,
// CONSEQUENCE_FANOUT, and nothing after it is derived.
const MaxConsequences = 16

// Source is where a consequence rule comes from (G0 M17 D106).
type Source string

// Sources (00208's decision_consequences.source).
const (
	// SourcePackage: a rule of the action's signed package version.
	SourcePackage Source = "package"
	// SourceCustomer: one of the org's reviewed customer rules.
	SourceCustomer Source = "customer"
)

// MaxDepth is how far down a chain a consequence may be (G0 M17 D109):
// depth 1 is a consequence of the action itself.
const MaxDepth = defs.MaxConsequenceDepth

// Consequence is one rule's result.
type Consequence struct {
	Rule                           string
	Operation, Effect, Description string
	// Source is where the rule comes from; empty is SourcePackage.
	Source Source
	// Depth is the consequence's place in its chain, 1 (or 0) for a
	// consequence of the action itself; Parent is, for a deeper one, the
	// position among the evaluation's consequences of the consequence it
	// follows from, which always comes before it (G0 M17 D109).
	Depth, Parent int
	// Definition is the consequence operation's definition.
	Definition *defs.Definition
	// Target is the consequence's target; Environments are the ones it
	// reaches, when the rule predicts it and says so.
	Target       actionir.Target
	Environments []string
	State        State
	// Unknown says, for an UNKNOWN consequence, why each fact could not
	// be used, or why the rule could not be, and where derivation stopped.
	Unknown []string
	// Reason is an UNKNOWN consequence's reason code: ReasonUnknown, or
	// ReasonExpired or ReasonFanout.
	Reason string
	// Err is set when the rule could not be evaluated.
	Err error
	// Used are the facts the rule read, and FactsDigest their digest
	// (F080).
	Used        []fdomain.Fact
	FactsDigest string
}

// Chain is the consequence's depth, its parent's position (ok false at
// depth 1) and its source, as stored (00208).
func (c *Consequence) Chain() (depth, parent int, ok bool, source Source) {
	depth, source = max(c.Depth, 1), c.Source
	if source == "" {
		source = SourcePackage
	}
	return depth, c.Parent, depth > 1, source
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

// hop is what the rules at one place in a chain are evaluated against: the
// action itself (depth 1, no parent) or a predicted consequence.
type hop struct {
	in            Input
	depth, parent int
	// err is set when the consequence's facts could not be read.
	err error
}

// Evaluate evaluates the rules for the action's operation, in order, and
// then, down each chain (G0 M17 D109, F411, F412), the rules for the
// operation of each consequence they predict that apply that deep, with
// the facts about that consequence's target. Each consequence comes after
// the one it follows from. A chain stops at a consequence that is not
// predicted: an UNKNOWN one that further rules apply to says derivation
// stopped there, and stays UNKNOWN (HR-206). A consequence whose operation
// and target were already reached is not derived from again, chains are at
// most MaxDepth deep, and past MaxConsequences the rest is UNKNOWN
// (HR-455).
func (e *Evaluator) Evaluate(ctx context.Context, rules []Rule, in Input) []Consequence {
	out := make([]Consequence, 0, len(rules))
	reached := map[[2]string]bool{{in.On.Operation, in.TargetID}: true}
	queue := []hop{{in: in, depth: 1, parent: -1}}
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		for _, r := range rules {
			if r.Operation != h.in.On.Operation || r.Depth() < h.depth || (in.Direct && h.depth > 1) {
				continue
			}
			if len(out) == MaxConsequences {
				return append(out, fanout(r, h))
			}
			c := e.one(ctx, r, h)
			at := len(out)
			if names := next(rules, c.Operation, h.depth+1); len(names) > 0 && c.Err == nil && !in.Direct {
				switch {
				case c.State == Unknown:
					c.Unknown = append(c.Unknown, fmt.Sprintf("derivation stopped at %s, depth %d: its consequences are not derived", c.Rule, h.depth))
				case c.State == Predicted && !reached[[2]string{c.Operation, c.Target.ID}]:
					reached[[2]string{c.Operation, c.Target.ID}] = true
					queue = append(queue, e.more(ctx, in, c, names, h.depth+1, at))
				}
			}
			out = append(out, c)
		}
	}
	return out
}

// next are the facts the rules for operation op that apply at depth need,
// or none when no rule applies there.
func next(rules []Rule, op string, depth int) []string {
	if depth > MaxDepth {
		return nil
	}
	var names []string
	for _, r := range rules {
		if r.Operation != op || r.Depth() < depth {
			continue
		}
		for _, n := range r.RequiresFacts {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	return names
}

// more is the hop of predicted consequence c, at position parent: its
// definition and target, with the facts about that target the rules there
// need.
func (e *Evaluator) more(ctx context.Context, in Input, c Consequence, names []string, depth, parent int) hop {
	h := hop{in: Input{On: c.Definition, TargetID: c.Target.ID, Now: in.Now}, depth: depth, parent: parent}
	if in.More != nil {
		h.in.Facts, h.in.Ages, h.err = in.More(ctx, c.Definition, c.Target.ID, names)
	}
	return h
}

// fanout is rule r's consequence at hop h when the action already has
// MaxConsequences: it cannot be ruled out, and nothing is derived after it.
func fanout(r Rule, h hop) Consequence {
	c := base(r, h)
	if r.Definition == nil {
		c.Err = fmt.Errorf("%w: %s is not defined", ErrRule, r.Consequence.Operation)
		return c
	}
	id, ok := r.TargetID(h.in.On.Target, h.in.TargetID)
	if !ok || !r.Definition.Target.MatchID(id) {
		c.Err = fmt.Errorf("%w: its target is not a %s", ErrRule, r.Definition.Target.Type)
		return c
	}
	c.Target = actionir.Target{Type: r.Definition.Target.Type, ID: id}
	c.State, c.Reason, c.FactsDigest = Unknown, ReasonFanout, fdomain.Digest(nil)
	c.Unknown = []string{fmt.Sprintf("more than %d consequences: derivation stopped at %s, depth %d", MaxConsequences, r.ID, h.depth)}
	return c
}

// base is rule r's consequence at hop h before it is evaluated.
func base(r Rule, h hop) Consequence {
	source := r.Source
	if source == "" {
		source = SourcePackage
	}
	return Consequence{
		Rule: r.ID, Operation: r.Consequence.Operation, Effect: r.Consequence.Effect, Description: r.Consequence.Description,
		Source: source, Depth: h.depth, Parent: h.parent, Definition: r.Definition,
	}
}

func (e *Evaluator) one(ctx context.Context, r Rule, h hop) Consequence {
	in := h.in
	c := base(r, h)
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
	if h.err != nil {
		c.Err = fmt.Errorf("%w: the facts about %s could not be read", ErrRule, in.TargetID) // never h.err: it may describe storage
		return c
	}
	// An expired rule cannot rule its consequence out (D110, HR-456).
	if !in.Direct && r.Expired(in.Now) {
		c.State, c.Reason, c.FactsDigest = Unknown, ReasonExpired, fdomain.Digest(nil)
		c.Unknown = []string{"the rule's review expired on " + r.ValidUntil}
		return c
	}

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
		if why, unread := f.Value.Unread(); unread {
			c.Unknown = append(c.Unknown, name+" could not be read: "+reason(why))
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
		c.State, c.Reason = Unknown, ReasonUnknown
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

// CustomerRef is the stored version of a customer rule: its version, the
// SHA-256 of its canonical JSON, and the pin of the definition of its
// consequence operation (zero when the org has no ACTIVE one, which the
// rule then cannot be evaluated without).
type CustomerRef struct {
	Version int
	Digest  [32]byte
	Pin     actionir.Definition
}
