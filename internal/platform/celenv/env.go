// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package celenv builds the CEL environments shared by tool package
// mappings, policies and (later) detections (ADR-0004). Every environment
// has:
//
//   - exact pc.Decimal and pc.Money types; ordering strings, bytes, doubles
//     or dyn values and any floating-point value are type errors (HR-041);
//   - struct types for known shapes, with a linter requiring has() guards on
//     optional fields (HR-042);
//   - parser size and recursion limits, a comprehension nesting limit, an
//     estimated-cost ceiling at compile time and a runtime cost limit per
//     evaluation (HR-043, T-023).
//
// Evaluation never swallows errors: an error, a non-boolean condition or a
// cost overrun is returned to the caller, which fails closed (HR-040).
package celenv

import (
	"context"
	"errors"
	"fmt"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/checker"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/interpreter"
)

// Limits bound compilation and evaluation. They are configuration, not
// constants: per-tenant budgets come from the caller (HR-043).
type Limits struct {
	// MaxExpressionBytes bounds the source of one expression.
	MaxExpressionBytes int `json:"max_expression_bytes"`
	// MaxCost bounds both the estimated and the actual cost of one
	// evaluation, in CEL cost units.
	MaxCost uint64 `json:"max_cost"`
	// MaxComprehensionNesting bounds nested macros such as exists/all.
	MaxComprehensionNesting int `json:"max_comprehension_nesting"`
	// EstimatedCollectionSize is the list, map and string size assumed when
	// estimating cost at compile time.
	EstimatedCollectionSize uint64 `json:"estimated_collection_size"`
}

// CeilingFactor bounds each configured limit at this many times its
// default, so configuration cannot lift the bound HR-043 relies on.
const CeilingFactor = 4

// Ceiling is the largest value configuration may give each limit.
var Ceiling = Limits{
	MaxExpressionBytes:      CeilingFactor * DefaultLimits.MaxExpressionBytes,
	MaxCost:                 CeilingFactor * DefaultLimits.MaxCost,
	MaxComprehensionNesting: CeilingFactor * DefaultLimits.MaxComprehensionNesting,
	EstimatedCollectionSize: CeilingFactor * DefaultLimits.EstimatedCollectionSize,
}

// Validate reports a limit that is not positive or is above its Ceiling.
// The server and gateway read Limits from their configuration (G0 M4
// decision 4).
func (l Limits) Validate() error {
	var errs []error
	checkInt := func(name string, v, ceiling int) {
		if v <= 0 || v > ceiling {
			errs = append(errs, fmt.Errorf("%s must be between 1 and %d (%d times the default)", name, ceiling, CeilingFactor))
		}
	}
	checkUint := func(name string, v, ceiling uint64) {
		if v == 0 || v > ceiling {
			errs = append(errs, fmt.Errorf("%s must be between 1 and %d (%d times the default)", name, ceiling, CeilingFactor))
		}
	}
	checkInt("max_expression_bytes", l.MaxExpressionBytes, Ceiling.MaxExpressionBytes)
	checkUint("max_cost", l.MaxCost, Ceiling.MaxCost)
	checkInt("max_comprehension_nesting", l.MaxComprehensionNesting, Ceiling.MaxComprehensionNesting)
	checkUint("estimated_collection_size", l.EstimatedCollectionSize, Ceiling.EstimatedCollectionSize)
	return errors.Join(errs...)
}

// DefaultLimits are the recommended defaults (G0 M4, decision 8).
var DefaultLimits = Limits{
	MaxExpressionBytes:      4 << 10,
	MaxCost:                 10_000,
	MaxComprehensionNesting: 2,
	EstimatedCollectionSize: 1024,
}

// Variable declares a top-level variable.
type Variable struct {
	Name string
	Type *types.Type
}

// Env is a configured CEL environment.
type Env struct {
	env    *cel.Env
	limits Limits
}

var (
	// ErrCompile reports an expression that does not parse, type-check,
	// pass the validators or fit the cost ceiling.
	ErrCompile = errors.New("celenv: expression rejected")
	// ErrEval reports an evaluation error, including a cost overrun.
	ErrEval = errors.New("celenv: evaluation failed")
	// ErrCost reports an evaluation that exceeded its cost limit or budget.
	ErrCost = errors.New("celenv: cost limit exceeded")
)

// New builds an environment with the given struct types and variables.
func New(limits Limits, schema Schema, vars ...Variable) (*Env, error) {
	if limits.MaxCost == 0 || limits.MaxExpressionBytes <= 0 || limits.MaxComprehensionNesting < 0 || limits.EstimatedCollectionSize == 0 {
		return nil, fmt.Errorf("celenv: limits must be positive")
	}
	opts := []cel.EnvOption{
		cel.CustomTypeProvider(&provider{Registry: newRegistry(), schema: schema}),
		cel.OptionalTypes(),
		cel.ParserExpressionSizeLimit(limits.MaxExpressionBytes),
		cel.ParserRecursionLimit(32),
		cel.CrossTypeNumericComparisons(false),
		cel.ASTValidators(
			cel.ValidateComprehensionNestingLimit(limits.MaxComprehensionNesting),
			noUnsafeNumbers{},
			hasGuards{schema: schema},
		),
	}
	opts = append(opts, moneyLibrary()...)
	opts = append(opts, pathLibrary()...)
	for _, v := range vars {
		opts = append(opts, cel.Variable(v.Name, v.Type))
	}
	e, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("celenv: %w", err)
	}
	return &Env{env: e, limits: limits}, nil
}

func newRegistry() *types.Registry {
	r, err := types.NewRegistry()
	if err != nil {
		panic(err) // an empty registry cannot fail
	}
	return r
}

// Program is a compiled, checked expression.
type Program struct {
	src      string
	prg      cel.Program
	out      *types.Type
	maxCost  uint64
	estimate uint64
	ast      *ast.AST
}

// Source returns the expression.
func (p *Program) Source() string { return p.src }

// OutputType returns the checked result type.
func (p *Program) OutputType() *types.Type { return p.out }

// EstimatedCost returns the worst-case cost estimated at compile time.
func (p *Program) EstimatedCost() uint64 { return p.estimate }

// Compile parses, type-checks and validates src. want, when non-nil, is the
// required result type (for example cel.BoolType for a condition). An
// expression whose estimated worst-case cost exceeds MaxCost is rejected
// here, before it can ever run (HR-043).
func (e *Env) Compile(src string, want *types.Type) (*Program, error) {
	if len(src) == 0 || len(src) > e.limits.MaxExpressionBytes {
		return nil, fmt.Errorf("%w: expression must be 1..%d bytes", ErrCompile, e.limits.MaxExpressionBytes)
	}
	a, iss := e.env.Compile(src)
	if iss.Err() != nil {
		return nil, fmt.Errorf("%w: %w", ErrCompile, iss.Err())
	}
	out := a.OutputType()
	if want != nil && !want.IsExactType(out) {
		return nil, fmt.Errorf("%w: result is %s, want %s", ErrCompile, out, want)
	}
	est, err := e.env.EstimateCost(a, estimator{size: e.limits.EstimatedCollectionSize})
	if err != nil {
		return nil, fmt.Errorf("%w: cost: %w", ErrCompile, err)
	}
	if est.Max > e.limits.MaxCost {
		return nil, fmt.Errorf("%w: estimated cost %d exceeds the limit %d (HR-043)", ErrCompile, est.Max, e.limits.MaxCost)
	}
	prg, err := e.env.Program(a,
		cel.CostLimit(e.limits.MaxCost),
		cel.EvalOptions(cel.OptTrackCost),
		cel.InterruptCheckFrequency(64),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCompile, err)
	}
	return &Program{src: src, prg: prg, out: out, maxCost: e.limits.MaxCost, estimate: est.Max, ast: a.NativeRep()}, nil
}

// Eval evaluates the program and returns its value and actual cost. Any
// error, including a canceled context or a cost overrun, is returned; the
// caller decides the fail-closed outcome. Error values are never treated as
// false.
func (p *Program) Eval(ctx context.Context, vars map[string]any) (ref.Val, uint64, error) {
	out, det, err := p.prg.ContextEval(ctx, vars)
	var cost uint64
	if det != nil && det.ActualCost() != nil {
		cost = *det.ActualCost()
	}
	if err != nil {
		if cost > p.maxCost || isCostErr(err) {
			return nil, cost, fmt.Errorf("%w: %w: %w", ErrEval, ErrCost, err)
		}
		return nil, cost, fmt.Errorf("%w: %w", ErrEval, err)
	}
	if types.IsError(out) || types.IsUnknown(out) {
		return nil, cost, fmt.Errorf("%w: result %v", ErrEval, out)
	}
	return out, cost, nil
}

// EvalBool evaluates a condition. Anything but a boolean is an error.
func (p *Program) EvalBool(ctx context.Context, vars map[string]any) (bool, uint64, error) {
	out, cost, err := p.Eval(ctx, vars)
	if err != nil {
		return false, cost, err
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, cost, fmt.Errorf("%w: condition returned %s, not bool", ErrEval, out.Type().TypeName())
	}
	return bool(b), cost, nil
}

func isCostErr(err error) bool {
	var c interpreter.EvalCancelledError
	return errors.As(err, &c) && (c.Cause == interpreter.CostLimitExceeded || c.Cause == interpreter.ContextCancelled)
}

// estimator bounds every list, map and string to the configured size, so the
// compile-time estimate is a real ceiling for inputs within the limits.
type estimator struct{ size uint64 }

func (e estimator) EstimateSize(checker.AstNode) *checker.SizeEstimate {
	return &checker.SizeEstimate{Min: 0, Max: e.size}
}

func (estimator) EstimateCallCost(string, string, *checker.AstNode, []checker.AstNode) *checker.CallEstimate {
	return nil
}
