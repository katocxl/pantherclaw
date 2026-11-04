// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"slices"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
)

// TriggerRules returns the rule ids an automation's event filter names (G0
// M28 D713): the string literals of each top-level conjunct of the form
// event.attrs["rule"] in [<literals>] or event.attrs["rule"] == "<literal>".
// It only parses where; it never evaluates it. Any other shape (||, !, a
// function, a non-literal list) names no ids, and an expression that does
// not parse names none. Sorted, each id once.
func TriggerRules(where string) []string {
	if where == "" {
		return nil
	}
	env, err := cel.NewEnv()
	if err != nil {
		return nil
	}
	a, iss := env.Parse(where)
	if iss.Err() != nil {
		return nil
	}
	var out []string
	for _, c := range conjuncts(a.NativeRep().Expr()) {
		out = append(out, ruleLiterals(c)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// conjuncts flattens the top-level && of e.
func conjuncts(e ast.Expr) []ast.Expr {
	if e.Kind() == ast.CallKind && e.AsCall().FunctionName() == operators.LogicalAnd {
		var out []ast.Expr
		for _, arg := range e.AsCall().Args() {
			out = append(out, conjuncts(arg)...)
		}
		return out
	}
	return []ast.Expr{e}
}

// ruleLiterals reads one conjunct of a recognized shape.
func ruleLiterals(e ast.Expr) []string {
	if e.Kind() != ast.CallKind {
		return nil
	}
	call := e.AsCall()
	args := call.Args()
	if len(args) != 2 || !isRuleAttr(args[0]) {
		return nil
	}
	switch call.FunctionName() {
	case operators.Equals:
		if s, ok := stringLiteral(args[1]); ok {
			return []string{s}
		}
	case operators.In:
		if args[1].Kind() != ast.ListKind {
			return nil
		}
		var out []string
		for _, el := range args[1].AsList().Elements() {
			s, ok := stringLiteral(el)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}

// isRuleAttr reports e is event.attrs["rule"].
func isRuleAttr(e ast.Expr) bool {
	if e.Kind() != ast.CallKind || e.AsCall().FunctionName() != operators.Index {
		return false
	}
	args := e.AsCall().Args()
	if len(args) != 2 {
		return false
	}
	if key, ok := stringLiteral(args[1]); !ok || key != "rule" {
		return false
	}
	sel := args[0]
	if sel.Kind() != ast.SelectKind || sel.AsSelect().FieldName() != "attrs" || sel.AsSelect().IsTestOnly() {
		return false
	}
	op := sel.AsSelect().Operand()
	return op.Kind() == ast.IdentKind && op.AsIdent() == "event"
}

func stringLiteral(e ast.Expr) (string, bool) {
	if e.Kind() != ast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().(types.String)
	return string(s), ok
}
