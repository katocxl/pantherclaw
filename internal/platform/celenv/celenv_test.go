// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"context"
	"errors"
	"strings"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/platform/money"
)

var testSchema = Schema{
	"t.Action": {Name: "t.Action", Fields: map[string]Field{
		"amount": {Type: MoneyType},
		"limit":  {Type: cel.IntType, Optional: true},
		"name":   {Type: cel.StringType},
		"target": {Type: types.NewObjectType("t.Target")},
		"items":  {Type: cel.ListType(types.NewObjectType("t.Target"))},
	}},
	"t.Target": {Name: "t.Target", Fields: map[string]Field{
		"id":      {Type: cel.StringType},
		"account": {Type: cel.StringType, Optional: true},
	}},
}

func testEnv(t *testing.T, limits Limits) *Env {
	t.Helper()
	e, err := New(limits, testSchema,
		Variable{"action", types.NewObjectType("t.Action")},
		Variable{"d", cel.MapType(cel.StringType, cel.DynType)})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func target(id string, items int) *Record {
	return &Record{TypeName: "t.Target", Fields: map[string]ref.Val{"id": types.String(id)}}
}

func action(amount, currency string, limit *int64, items int) *Record {
	m, err := money.ParseMoney(amount, currency)
	if err != nil {
		panic(err)
	}
	r := &Record{TypeName: "t.Action", Fields: map[string]ref.Val{
		"amount": Money{m}, "name": types.String("refund"), "target": target("ch_1", 0),
	}}
	list := make([]ref.Val, items)
	for i := range list {
		list[i] = target("x", 0)
	}
	r.Fields["items"] = types.NewRefValList(types.DefaultTypeAdapter, list)
	if limit != nil {
		r.Fields["limit"] = types.Int(*limit)
	}
	return r
}

func evalBool(t *testing.T, e *Env, src string, act *Record) (bool, error) {
	t.Helper()
	p, err := e.Compile(src, cel.BoolType)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	b, _, err := p.EvalBool(context.Background(), map[string]any{"action": act, "d": map[string]any{"x": int64(1)}})
	return b, err
}

func TestHR041_DecimalAndMoneyAreExact(t *testing.T) {
	e := testEnv(t, DefaultLimits)
	ten := int64(10)
	for src, want := range map[string]bool{
		`action.amount > money("50.00", "USD")`:                               true,
		`action.amount <= money("85.50", "USD")`:                              true,
		`action.amount >= money("85.51", "USD")`:                              false,
		`action.amount == money("85.5", "USD")`:                               true,
		`action.amount.amount() > decimal("85.49")`:                           true,
		`action.amount.currency() == "USD"`:                                   true,
		`decimal("0.1") + decimal("0.2") == decimal("0.3")`:                   true,
		`decimal("100") > decimal("85")`:                                      true,
		`money("1.10", "USD") + money("2.20", "USD") == money("3.30", "USD")`: true,
		`money("1.00", "USD") - money("2.00", "USD") < money("0", "USD")`:     true,
		`has(action.limit) && action.limit > 5`:                               true,
		`money("1.00", "USD") == money("1.00", "EUR")`:                        false,
	} {
		got, err := evalBool(t, e, src, action("85.50", "USD", &ten, 0))
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", src, got, err, want)
		}
	}
}

func TestHR041_MixedCurrenciesFailClosed(t *testing.T) {
	e := testEnv(t, DefaultLimits)
	for _, src := range []string{
		`action.amount > money("50.00", "EUR")`,
		`action.amount + money("1.00", "EUR") > money("0", "USD")`,
		`money("1.001", "USD") > action.amount`,
		`decimal("1e3") > decimal("1")`,
		`money("1.00", "XXX") > action.amount`,
	} {
		if _, err := evalBool(t, e, src, action("85.50", "USD", nil, 0)); !errors.Is(err, ErrEval) {
			t.Errorf("%s: err = %v, want an evaluation error (never false)", src, err)
		}
	}
}

func TestHR041_UnsafeOrderingIsATypeError(t *testing.T) {
	e := testEnv(t, DefaultLimits)
	for _, src := range []string{
		`action.name < "m"`,
		`"100" > "85"`,
		`b"a" < b"b"`,
		`1.5 > 1.0`,
		`double(1) > 0`,
		`d.x > 5`,
		`d.x < d.y`,
		`action.amount > 50`,
		`action.amount > decimal("50")`,
		`action.amount.amount() > 50`,
		`dyn(action.name) > dyn("a")`,
	} {
		_, err := e.Compile(src, cel.BoolType)
		if !errors.Is(err, ErrCompile) {
			t.Errorf("%s: err = %v, want ErrCompile", src, err)
		}
		t.Logf("%s: %v", src, err)
	}
	for _, src := range []string{`1 < 2`, `timestamp("2026-10-08T00:00:00Z") < timestamp("2027-01-01T00:00:00Z")`, `action.name == "refund"`} {
		if _, err := e.Compile(src, cel.BoolType); err != nil {
			t.Errorf("%s: %v", src, err)
		}
	}
}

func TestHR042_OptionalFieldsNeedHasGuards(t *testing.T) {
	e := testEnv(t, DefaultLimits)
	for _, src := range []string{
		`action.limit > 5`,
		`action.target.account == "acct_1"`,
		`has(action.name) && action.limit > 5`,
		`action.limit > 5 && has(action.limit)`,
		`has(action.limit) || action.limit > 5`,
		`has(action.limit) ? false : action.limit > 5`,
		`has(action.target.account) && action.target.id == "x" || action.target.account == "y"`,
	} {
		if _, err := e.Compile(src, cel.BoolType); !errors.Is(err, ErrCompile) || !strings.Contains(err.Error(), "has()") {
			t.Errorf("%s: err = %v, want a has() guard error", src, err)
		}
	}
	for _, src := range []string{
		`has(action.limit) && action.limit > 5`,
		`!has(action.limit) || action.limit > 5`,
		`has(action.limit) ? action.limit > 5 : false`,
		`!has(action.limit) ? false : action.limit > 5`,
		`has(action.limit) && action.name == "x" && action.limit < 100`,
		`action.?limit.orValue(0) > 5`,
		`has(action.target.account) && action.target.account == "acct_1"`,
	} {
		if _, err := e.Compile(src, cel.BoolType); err != nil {
			t.Errorf("%s: %v", src, err)
		}
	}
	// At runtime an absent field is absent: has() is false, never a default.
	if got, err := evalBool(t, e, `has(action.limit)`, action("1.00", "USD", nil, 0)); err != nil || got {
		t.Fatalf("has(absent) = %v, %v", got, err)
	}
}

func TestHR043_CostIsBoundedAtCompileAndRuntime(t *testing.T) {
	e := testEnv(t, DefaultLimits)
	for name, src := range map[string]string{
		"estimated cost": `action.items.all(x, action.items.all(y, x.id == y.id))`,
		"nesting":        `action.items.all(x, action.items.all(y, action.items.all(z, true)))`,
		"source size":    `action.name == "` + strings.Repeat("a", 5000) + `"`,
	} {
		if _, err := e.Compile(src, cel.BoolType); !errors.Is(err, ErrCompile) {
			t.Errorf("%s: err = %v, want ErrCompile", name, err)
		}
	}
	// An environment that underestimates sizes still stops at runtime.
	small := testEnv(t, Limits{MaxExpressionBytes: 4096, MaxCost: 1000, MaxComprehensionNesting: 2, EstimatedCollectionSize: 1})
	_, err := evalBool(t, small, `action.items.all(x, x.id == "x")`, action("1.00", "USD", nil, 5000))
	if !errors.Is(err, ErrCost) {
		t.Fatalf("runtime cost overrun: %v, want ErrCost", err)
	}
	p, _ := e.Compile(`action.items.all(x, x.id == "x")`, cel.BoolType)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := p.EvalBool(ctx, map[string]any{"action": action("1.00", "USD", nil, 1000)}); !errors.Is(err, ErrEval) {
		t.Fatalf("canceled evaluation: %v", err)
	}
}

func TestHR040_ErrorsAreNeverFalse(t *testing.T) {
	e := testEnv(t, DefaultLimits)
	if _, err := evalBool(t, e, `d.missing == 1`, action("1.00", "USD", nil, 0)); !errors.Is(err, ErrEval) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := e.Compile(`1 + 1`, cel.BoolType); !errors.Is(err, ErrCompile) {
		t.Fatalf("a non-boolean condition must not compile: %v", err)
	}
	p, err := e.Compile(`d.x`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.EvalBool(context.Background(), map[string]any{"d": map[string]any{"x": int64(1)}}); !errors.Is(err, ErrEval) {
		t.Fatalf("non-boolean result: %v", err)
	}
	// Records cannot be forged inside an expression.
	if p, err := e.Compile(`t.Target{id: "x"} == action.target`, cel.BoolType); err == nil {
		if _, _, err := p.EvalBool(context.Background(), map[string]any{"action": action("1.00", "USD", nil, 0)}); err == nil {
			t.Fatal("constructing a struct in an expression must fail")
		}
	}
}

func TestRecordValues(t *testing.T) {
	a, b := target("x", 0), target("x", 0)
	if a.Equal(b) != types.True || a.Equal(target("y", 0)) != types.False || a.Equal(types.String("x")) != types.False {
		t.Fatal("record equality")
	}
	if a.ConvertToType(types.TypeType).(*types.Type).TypeName() != "t.Target" || !types.IsError(a.ConvertToType(types.StringType)) {
		t.Fatal("record conversion")
	}
	d := Decimal{money.MustParse("1.5")}
	if !types.IsError(d.ConvertToType(types.StringType)) || !types.IsError(d.ConvertToType(types.DoubleType)) {
		t.Fatal("a decimal never silently becomes a string or a double")
	}
	if _, err := New(Limits{}, nil); err == nil {
		t.Fatal("zero limits must be refused")
	}
}

func TestFieldsReportsWhatAnExpressionReads(t *testing.T) {
	e := testEnv(t, DefaultLimits)
	for src, want := range map[string]string{
		`d.a == 1 && has(d.b) && d.?c.orValue(0) == 2 && d["e"] == 3`: "a,b,c,e",
		`action.name == "x"`:    "",
		`size(d) > 0`:           "opaque",
		`d.exists(k, k == "a")`: "opaque",
	} {
		p, err := e.Compile(src, cel.BoolType)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		fields, ok := p.Fields("d")
		got := strings.Join(fields, ",")
		if !ok {
			got = "opaque"
		}
		if got != want {
			t.Errorf("%s: Fields = %q, want %q", src, got, want)
		}
	}
}

// TestHR043_ConfiguredLimitsHaveACeiling: configuration can lower the CEL
// limits or raise them to at most four times the defaults, never remove
// the bound; a value above the ceiling is refused with the ceiling named.
func TestHR043_ConfiguredLimitsHaveACeiling(t *testing.T) {
	if err := DefaultLimits.Validate(); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	if err := Ceiling.Validate(); err != nil {
		t.Fatalf("the ceiling itself refused: %v", err)
	}
	if Ceiling.MaxCost != 40_000 || Ceiling.EstimatedCollectionSize != 4096 ||
		Ceiling.MaxExpressionBytes != 16<<10 || Ceiling.MaxComprehensionNesting != 8 {
		t.Fatalf("ceiling %+v, want four times the defaults", Ceiling)
	}
	for name, c := range map[string]struct {
		mutate func(*Limits)
		want   string
	}{
		"max_expression_bytes":      {func(l *Limits) { l.MaxExpressionBytes = Ceiling.MaxExpressionBytes + 1 }, "between 1 and 16384"},
		"max_cost":                  {func(l *Limits) { l.MaxCost = Ceiling.MaxCost + 1 }, "between 1 and 40000"},
		"max_comprehension_nesting": {func(l *Limits) { l.MaxComprehensionNesting = Ceiling.MaxComprehensionNesting + 1 }, "between 1 and 8"},
		"estimated_collection_size": {func(l *Limits) { l.EstimatedCollectionSize = Ceiling.EstimatedCollectionSize + 1 }, "between 1 and 4096"},
		"zero max_cost":             {func(l *Limits) { l.MaxCost = 0 }, "max_cost must be between 1 and 40000"},
	} {
		l := DefaultLimits
		c.mutate(&l)
		if err := l.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, c.want)
		}
	}
}
