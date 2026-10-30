// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"context"
	"errors"
	"slices"
	"sync"

	"cel.dev/cel-go/cel"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// guards evaluates steps' `when` guards (D2): CEL booleans over `trigger`
// (params, kind, occurred_at) and `steps` (steps.<id>.output.<key>),
// cost-limited and failing closed.
type guards struct {
	env *celenv.Env
	mu  sync.Mutex
	// compiled caches programs by source; definitions are immutable.
	compiled map[string]*celenv.Program
}

// GuardVariables are the variables a step guard may read.
var GuardVariables = autodomain.GuardVariables

func newGuards() (*guards, error) {
	env, err := celenv.New(celenv.DefaultLimits, nil, GuardVariables...)
	if err != nil {
		return nil, err
	}
	return &guards{env: env, compiled: map[string]*celenv.Program{}}, nil
}

// CompileGuard checks a guard expression (for validation and tests).
func CompileGuard(src string) error {
	g, err := newGuards()
	if err != nil {
		return err
	}
	_, err = g.program(src)
	return err
}

func (g *guards) program(src string) (*celenv.Program, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p, ok := g.compiled[src]; ok {
		return p, nil
	}
	p, err := g.env.Compile(src, cel.BoolType)
	if err != nil {
		return nil, err
	}
	g.compiled[src] = p
	return p, nil
}

func (g *guards) eval(ctx context.Context, src string, t autodomain.TriggerRef, outputs map[string]map[string]string) (bool, error) {
	p, err := g.program(src)
	if err != nil {
		return false, err
	}
	ok, _, err := p.EvalBool(ctx, guardVars(t, outputs))
	return ok, err
}

// ErrGuardUnevaluable is a guard reading what a replay does not have.
var ErrGuardUnevaluable = errors.New("guard reads what history does not keep")

// EvalGuard evaluates a guard outside an execution, for replays. History
// keeps no parameters and no step ran, so a guard reading `steps` or anything
// of `trigger` but its kind and time is never evaluated: on empty values it
// could answer, wrongly, instead of failing (D301).
func EvalGuard(ctx context.Context, src string, t autodomain.TriggerRef) (bool, error) {
	g, err := replayGuards()
	if err != nil {
		return false, err
	}
	p, err := g.program(src)
	if err != nil {
		return false, err
	}
	if !historyAnswers(p) {
		return false, ErrGuardUnevaluable
	}
	return g.eval(ctx, src, t, nil)
}

var replayGuards = sync.OnceValues(newGuards)

// historyAnswers reports whether a guard reads only the trigger's kind and
// time.
func historyAnswers(p *celenv.Program) bool {
	steps, ok := p.Fields("steps")
	if !ok || len(steps) > 0 {
		return false
	}
	fields, ok := p.Fields("trigger")
	return ok && !slices.ContainsFunc(fields, func(f string) bool { return f != "kind" && f != "occurred_at" })
}

// guardVars maps the trigger and outputs to CEL values: parameters keep
// their declared types.
func guardVars(t autodomain.TriggerRef, outputs map[string]map[string]string) map[string]any {
	params := make(map[string]any, len(t.Params))
	for k, v := range t.Params {
		switch v.Type {
		case autodomain.ParamInt:
			params[k] = v.Int
		case autodomain.ParamBool:
			params[k] = v.Bool
		case autodomain.ParamString, autodomain.ParamDecimal, autodomain.ParamEnum, autodomain.ParamUUID:
			params[k] = v.Text()
		default:
			params[k] = v.Text()
		}
	}
	steps := make(map[string]any, len(outputs))
	for id, out := range outputs {
		o := make(map[string]any, len(out))
		for k, v := range out {
			o[k] = v
		}
		steps[id] = map[string]any{"output": o}
	}
	return map[string]any{
		"trigger": map[string]any{"params": params, "kind": string(t.Kind), "occurred_at": t.OccurredAt},
		"steps":   steps,
	}
}
