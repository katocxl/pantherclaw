// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"

	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// CEL types for exact amounts (HR-041). Material amounts are never strings
// or doubles in an expression: they are pc.Decimal or pc.Money values, which
// compare and add exactly. Comparing or adding money in different currencies
// is an evaluation error, which the caller turns into a fail-closed decision.
var (
	DecimalType = types.NewOpaqueType("pc.Decimal")
	MoneyType   = types.NewOpaqueType("pc.Money")
)

// runtimeType is the runtime type of pc.Decimal and pc.Money values. It has
// the name of the checked opaque type and declares the traits the standard
// library's operators dispatch on (<, <=, >, >=, +, -).
type runtimeType string

func (runtimeType) HasTrait(trait int) bool {
	return trait&(traits.ComparerType|traits.AdderType|traits.SubtractorType) == trait
}

func (t runtimeType) TypeName() string { return string(t) }

// Decimal is a pc.Decimal value.
type Decimal struct{ D money.Decimal }

// Money is a pc.Money value.
type Money struct{ M money.Money }

var (
	_ ref.Val         = Decimal{}
	_ traits.Comparer = Decimal{}
	_ traits.Adder    = Decimal{}
	_ ref.Val         = Money{}
	_ traits.Comparer = Money{}
	_ traits.Adder    = Money{}
)

func errVal(err error) ref.Val { return types.WrapErr(err) }

// convert implements ConvertToType for both amount types: only the type
// itself is supported, so an amount never silently becomes a string or a
// double.
func convert(v ref.Val, checked *types.Type, t ref.Type) ref.Val {
	if t == types.TypeType {
		return checked
	}
	if t.TypeName() == checked.TypeName() {
		return v
	}
	return types.NewErr("%s cannot convert to %s", checked.TypeName(), t.TypeName())
}

// ConvertToNative implements ref.Val.
func (d Decimal) ConvertToNative(t reflect.Type) (any, error) {
	if reflect.TypeOf(d.D) == t {
		return d.D, nil
	}
	return nil, fmt.Errorf("pc.Decimal cannot convert to %v", t)
}

// ConvertToType implements ref.Val.
func (d Decimal) ConvertToType(t ref.Type) ref.Val { return convert(d, DecimalType, t) }

// Equal implements ref.Val.
func (d Decimal) Equal(o ref.Val) ref.Val {
	e, ok := o.(Decimal)
	return types.Bool(ok && d.D.Equal(e.D))
}

// Type implements ref.Val.
func (Decimal) Type() ref.Type { return runtimeType("pc.Decimal") }

// Value implements ref.Val.
func (d Decimal) Value() any { return d.D }

// Compare implements traits.Comparer.
func (d Decimal) Compare(o ref.Val) ref.Val {
	e, ok := o.(Decimal)
	if !ok {
		return types.MaybeNoSuchOverloadErr(o)
	}
	return types.Int(d.D.Cmp(e.D))
}

// Add implements traits.Adder.
func (d Decimal) Add(o ref.Val) ref.Val { return d.arith(o, money.Decimal.Add) }

// Subtract implements traits.Subtractor.
func (d Decimal) Subtract(o ref.Val) ref.Val { return d.arith(o, money.Decimal.Sub) }

func (d Decimal) arith(o ref.Val, op func(a, b money.Decimal) (money.Decimal, error)) ref.Val {
	e, ok := o.(Decimal)
	if !ok {
		return types.MaybeNoSuchOverloadErr(o)
	}
	r, err := op(d.D, e.D)
	if err != nil {
		return errVal(err)
	}
	return Decimal{r}
}

// ConvertToNative implements ref.Val.
func (m Money) ConvertToNative(t reflect.Type) (any, error) {
	if reflect.TypeOf(m.M) == t {
		return m.M, nil
	}
	return nil, fmt.Errorf("pc.Money cannot convert to %v", t)
}

// ConvertToType implements ref.Val.
func (m Money) ConvertToType(t ref.Type) ref.Val { return convert(m, MoneyType, t) }

// Equal implements ref.Val. Amounts in different currencies are unequal.
func (m Money) Equal(o ref.Val) ref.Val {
	n, ok := o.(Money)
	return types.Bool(ok && m.M.Currency == n.M.Currency && m.M.Amount.Equal(n.M.Amount))
}

// Type implements ref.Val.
func (Money) Type() ref.Type { return runtimeType("pc.Money") }

// Value implements ref.Val.
func (m Money) Value() any { return m.M }

// Compare implements traits.Comparer for two moneys of one currency; other
// currencies are an error, never an ordering.
func (m Money) Compare(o ref.Val) ref.Val {
	n, ok := o.(Money)
	if !ok {
		return types.MaybeNoSuchOverloadErr(o)
	}
	c, err := m.M.Cmp(n.M)
	if err != nil {
		return errVal(err)
	}
	return types.Int(c)
}

// Add implements traits.Adder.
func (m Money) Add(o ref.Val) ref.Val { return m.arith(o, money.Money.Add) }

// Subtract implements traits.Subtractor.
func (m Money) Subtract(o ref.Val) ref.Val { return m.arith(o, money.Money.Sub) }

func (m Money) arith(o ref.Val, op func(a, b money.Money) (money.Money, error)) ref.Val {
	n, ok := o.(Money)
	if !ok {
		return types.MaybeNoSuchOverloadErr(o)
	}
	r, err := op(m.M, n.M)
	if err != nil {
		return errVal(err)
	}
	return Money{r}
}

// overloads declares typed operator overloads for both amount types. They
// carry no binding: evaluation goes through the standard library's trait
// dispatch to the methods above.
func overloads(name string, result func(t *cel.Type) *cel.Type) []cel.FunctionOpt {
	return []cel.FunctionOpt{
		cel.Overload(name+"_pc_decimal", []*cel.Type{DecimalType, DecimalType}, result(DecimalType)),
		cel.Overload(name+"_pc_money", []*cel.Type{MoneyType, MoneyType}, result(MoneyType)),
	}
}

func boolResult(*cel.Type) *cel.Type   { return cel.BoolType }
func sameResult(t *cel.Type) *cel.Type { return t }

// moneyLibrary declares the pc.Decimal and pc.Money functions:
//
//	decimal("85.50") pc.Decimal       money("85.50", "USD") pc.Money
//	minor_money(8550, "USD") pc.Money
//	m.amount() pc.Decimal             m.currency() string
//	<, <=, >, >=, +, - on two decimals or two moneys of one currency
func moneyLibrary() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("decimal", cel.Overload("decimal_string", []*cel.Type{cel.StringType}, DecimalType,
			cel.UnaryBinding(func(v ref.Val) ref.Val {
				d, err := money.Parse(string(v.(types.String)))
				if err != nil {
					return errVal(err)
				}
				return Decimal{d}
			}))),
		cel.Function("money", cel.Overload("money_string_string", []*cel.Type{cel.StringType, cel.StringType}, MoneyType,
			cel.BinaryBinding(func(a, c ref.Val) ref.Val {
				m, err := money.ParseMoney(string(a.(types.String)), string(c.(types.String)))
				if err != nil {
					return errVal(err)
				}
				return Money{m}
			}))),
		// minor_money(8550, "USD") is 85.50 USD: an amount an API sends
		// in integer minor units (G0 M14 D8). Such APIs write currencies in
		// lower case, so the code is taken in any case and is upper case in
		// the money (D73). A currency outside the minor-unit list, or a
		// negative count, is an error.
		cel.Function("minor_money", cel.Overload("minor_money_int_string", []*cel.Type{cel.IntType, cel.StringType}, MoneyType,
			cel.BinaryBinding(func(n, c ref.Val) ref.Val {
				// Three ASCII letters only, so no confusable (such as U+017F, the long s)
				// is folded into a code (HR-102, D85).
				code := string(c.(types.String))
				if !currencyCodeRe.MatchString(code) {
					return types.NewErr("minor_money: a currency is three letters")
				}
				m, err := money.FromMinor(int64(n.(types.Int)), money.Currency(strings.ToUpper(code)))
				if err != nil {
					return errVal(err)
				}
				return Money{m}
			}))),
		cel.Function("amount", cel.MemberOverload("pc_money_amount", []*cel.Type{MoneyType}, DecimalType,
			cel.UnaryBinding(func(v ref.Val) ref.Val { return Decimal{v.(Money).M.Amount} }))),
		cel.Function("currency", cel.MemberOverload("pc_money_currency", []*cel.Type{MoneyType}, cel.StringType,
			cel.UnaryBinding(func(v ref.Val) ref.Val { return types.String(v.(Money).M.Currency) }))),
		cel.Function(operators.Less, overloads("less", boolResult)...),
		cel.Function(operators.LessEquals, overloads("less_equals", boolResult)...),
		cel.Function(operators.Greater, overloads("greater", boolResult)...),
		cel.Function(operators.GreaterEquals, overloads("greater_equals", boolResult)...),
		cel.Function(operators.Add, overloads("add", sameResult)...),
		cel.Function(operators.Subtract, overloads("subtract", sameResult)...),
	}
}

// currencyCodeRe is a currency code as minor_money takes it: three ASCII
// letters in any case.
var currencyCodeRe = regexp.MustCompile(`^[A-Za-z]{3}$`)
