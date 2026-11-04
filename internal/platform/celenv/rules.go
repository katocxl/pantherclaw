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

// TriggerRules returns the rule ids an automation's event filter can fire on
// (G0 M28 D713, D720b L2). A test of the form event.attrs["rule"] in
// [<literals>] or event.attrs["rule"] == "<literal>" names its literals;
// across && the sets are intersected, a conjunct that does not touch the
// rule id being ignored; across || they are united. Anything else that
// touches the rule id (a negation, a function, a non-literal list, another
// way to reach it) cannot be analyzed, and an expression with such a part,
// or that does not parse, names no rule: it may under-claim, never
// over-claim. It only parses where; it never evaluates it. Sorted, each id
// once.
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
	r := analyze(a.NativeRep().Expr())
	if r.kind != constrained || len(r.ids) == 0 {
		return nil
	}
	slices.Sort(r.ids)
	return slices.Compact(r.ids)
}

type constraint int

const (
	// unconstrained: the expression does not touch the rule id.
	unconstrained constraint = iota
	// constrained: the rule id is one of ids.
	constrained
	// unknown: the expression touches the rule id in a way not analyzed.
	unknown
)

type result struct {
	kind constraint
	ids  []string
}

func analyze(e ast.Expr) result {
	if e.Kind() == ast.CallKind {
		switch e.AsCall().FunctionName() {
		case operators.LogicalAnd:
			out := result{kind: unconstrained}
			for _, arg := range e.AsCall().Args() {
				r := analyze(arg)
				switch r.kind {
				case unknown:
					return r
				case constrained:
					if out.kind == unconstrained {
						out = r
						continue
					}
					out.ids = slices.DeleteFunc(slices.Clone(out.ids), func(id string) bool { return !slices.Contains(r.ids, id) })
				case unconstrained:
				}
			}
			return out
		case operators.LogicalOr:
			out := result{kind: constrained}
			for _, arg := range e.AsCall().Args() {
				r := analyze(arg)
				if r.kind != constrained {
					// A branch that fires on any rule, or one not analyzed.
					return result{kind: unknown}
				}
				out.ids = append(out.ids, r.ids...)
			}
			return out
		}
	}
	if ids, ok := ruleLiterals(e); ok {
		return result{kind: constrained, ids: ids}
	}
	if touches(e) {
		return result{kind: unknown}
	}
	return result{kind: unconstrained}
}

// ruleLiterals reads a rule test of a recognized shape.
func ruleLiterals(e ast.Expr) ([]string, bool) {
	if e.Kind() != ast.CallKind {
		return nil, false
	}
	call := e.AsCall()
	args := call.Args()
	if len(args) != 2 || !isRuleAttr(args[0]) {
		return nil, false
	}
	switch call.FunctionName() {
	case operators.Equals:
		if s, ok := stringLiteral(args[1]); ok {
			return []string{s}, true
		}
	case operators.In:
		if args[1].Kind() != ast.ListKind {
			return nil, false
		}
		out := []string{}
		for _, el := range args[1].AsList().Elements() {
			s, ok := stringLiteral(el)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// touches reports whether e may read the rule id: event.attrs["rule"],
// event.attrs.rule, event.attrs under a key that is not a literal, or event
// or event.attrs used whole. It errs towards true.
func touches(e ast.Expr) bool {
	switch e.Kind() {
	case ast.IdentKind:
		return e.AsIdent() == "event"
	case ast.LiteralKind:
		return false
	case ast.SelectKind:
		s := e.AsSelect()
		if isEvent(s.Operand()) {
			// event.attrs whole is touched; event.<other field> is not.
			return s.FieldName() == "attrs"
		}
		if isEventAttrs(s.Operand()) {
			return s.FieldName() == "rule"
		}
		return touches(s.Operand())
	case ast.CallKind:
		c := e.AsCall()
		args := c.Args()
		if c.FunctionName() == operators.Index && len(args) == 2 && isEventAttrs(args[0]) {
			key, ok := stringLiteral(args[1])
			return !ok || key == "rule"
		}
		if c.IsMemberFunction() && touches(c.Target()) {
			return true
		}
		return slices.ContainsFunc(args, touches)
	case ast.ListKind:
		return slices.ContainsFunc(e.AsList().Elements(), touches)
	case ast.MapKind:
		for _, en := range e.AsMap().Entries() {
			m := en.AsMapEntry()
			if touches(m.Key()) || touches(m.Value()) {
				return true
			}
		}
		return false
	case ast.StructKind:
		for _, f := range e.AsStruct().Fields() {
			if touches(f.AsStructField().Value()) {
				return true
			}
		}
		return false
	case ast.ComprehensionKind:
		c := e.AsComprehension()
		return slices.ContainsFunc([]ast.Expr{c.IterRange(), c.AccuInit(), c.LoopCondition(), c.LoopStep(), c.Result()}, touches)
	case ast.UnspecifiedExprKind:
		// Not analyzed: it may read the rule id.
		return true
	}
	return true
}

func isEvent(e ast.Expr) bool { return e.Kind() == ast.IdentKind && e.AsIdent() == "event" }

// isEventAttrs reports e is event.attrs.
func isEventAttrs(e ast.Expr) bool {
	if e.Kind() != ast.SelectKind {
		return false
	}
	s := e.AsSelect()
	return s.FieldName() == "attrs" && !s.IsTestOnly() && isEvent(s.Operand())
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
	return isEventAttrs(args[0])
}

func stringLiteral(e ast.Expr) (string, bool) {
	if e.Kind() != ast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().(types.String)
	return string(s), ok
}
