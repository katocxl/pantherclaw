// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"fmt"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
)

// flips maps each comparison to the mutation that most often survives weak
// tests: the boundary shift (< ↔ <=, > ↔ >=) and equality negation. Each
// flip is its own inverse.
var flips = map[string]string{
	operators.Less: operators.LessEquals, operators.LessEquals: operators.Less,
	operators.Greater: operators.GreaterEquals, operators.GreaterEquals: operators.Greater,
	operators.Equals: operators.NotEquals, operators.NotEquals: operators.Equals,
}

// Mutants returns one mutant per comparison in a condition, each with that
// single comparison flipped (HR-044). A rule's scenario tests must fail on
// every mutant; a surviving mutant means a threshold or equality is not
// pinned by any test.
func Mutants(src string) ([]string, error) {
	c, err := parseComparisons(src)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(c.order))
	for _, id := range c.order {
		c.flip(id)
		m, err := cel.AstToString(c.ast)
		c.flip(id) // back
		if err != nil {
			return nil, fmt.Errorf("mutants: %w", err)
		}
		out = append(out, m)
	}
	return out, nil
}

// MutantCount is how many mutants Mutants returns for src, found with one
// parse, so a caller can refuse a condition with too many before any is
// built (M11.1 D26, HR-238).
func MutantCount(src string) (int, error) {
	c, err := parseComparisons(src)
	if err != nil {
		return 0, err
	}
	return len(c.order), nil
}

// comparisons is a parsed condition and its comparisons' node ids, each
// once, in pre-order.
type comparisons struct {
	ast   *cel.Ast
	order []int64
}

func parseComparisons(src string) (*comparisons, error) {
	// Macro call tracking keeps exists(...), all(...) and the like as
	// written when the condition is printed again.
	env, err := cel.NewEnv(cel.EnableMacroCallTracking())
	if err != nil {
		return nil, err
	}
	a, iss := env.Parse(src)
	if iss.Err() != nil {
		return nil, fmt.Errorf("mutants: %w", iss.Err())
	}
	c := &comparisons{ast: a}
	seen := map[int64]bool{}
	ast.PreOrderVisit(a.NativeRep().Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		if _, ok := flips[function(e)]; ok && !seen[e.ID()] {
			seen[e.ID()] = true
			c.order = append(c.order, e.ID())
		}
	}))
	return c, nil
}

// flip flips the comparison with node id. A comparison inside a macro is
// also kept in the macro call that printing uses, so the flip is applied
// to the expanded expression and to every macro call.
func (c *comparisons) flip(id int64) {
	fac := ast.NewExprFactory()
	visit := ast.NewExprVisitor(func(e ast.Expr) {
		if e.ID() == id {
			call := e.AsCall()
			e.SetKindCase(fac.NewCall(e.ID(), flips[call.FunctionName()], call.Args()...))
		}
	})
	native := c.ast.NativeRep()
	ast.PreOrderVisit(native.Expr(), visit)
	for _, call := range native.SourceInfo().MacroCalls() {
		ast.PreOrderVisit(call, visit)
	}
}

// function is the function name of a call, or "".
func function(e ast.Expr) string {
	if e.Kind() != ast.CallKind {
		return ""
	}
	return e.AsCall().FunctionName()
}
