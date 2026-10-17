// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// formWrite is a write whose HTTP dispatch is a form, for the template
// checks below.
func formWrite(body map[string]string) *domain.Definition {
	d := minimal(map[string]domain.ParamSpec{
		"amount": {Type: domain.TypeMoney, Material: true, Currencies: []string{"USD", "JPY"}},
		"kinds":  {Type: domain.TypeIdentifierList, Material: true, MaxItems: 4},
		"reason": {Type: domain.TypeEnum, Material: true, Values: []string{"duplicate"}},
	})
	d.Target.IDPattern = `^(?:(?P<pi>pi_[A-Za-z0-9]{8,64})|(?P<ch>ch_[A-Za-z0-9]{8,64}))$`
	d.Dispatch = &domain.Dispatch{HTTP: &domain.HTTPDispatch{Method: "POST", Path: "/v1/refunds", Encoding: domain.EncodingForm, Body: body}}
	return d
}

// TestM14_FormTemplates: a form body's keys follow the parser's bracket
// grammar, a list goes alone under a key ending in [], literals and the
// transaction key are body values only, and money is sent in minor units
// only in currencies with an agreed exponent (G0 M14 D8, D50, D52).
func TestM14_FormTemplates(t *testing.T) {
	ok := map[string]string{
		"amount": "params.amount.minor", "payment_intent": "target.id.pi", "charge": "target.id.ch",
		"metadata[pantherclaw_key]": "transaction.key", "payment_method_types[]": "literal.card", "kinds[]": "params.kinds",
		"confirm": "literal.true", "reason": "params.reason",
	}
	if err := formWrite(ok).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]map[string]string{
		"depth four":            {"a[b][c][d]": "literal.x"},
		"depth four with list":  {"a[b][c][]": "literal.x"},
		"digits segment":        {"a[0]": "literal.x"},
		"value and object":      {"a": "literal.x", "a[b]": "literal.y"},
		"value and list":        {"a[b]": "literal.x", "a[b][]": "literal.y"},
		"unclosed bracket":      {"a[b": "literal.x"},
		"text after bracket":    {"a[b]c": "literal.x"},
		"list under scalar key": {"kinds": "params.kinds"},
		"scalar under list key": {"reason[]": "params.reason"},
		"long literal":          {"a": "literal." + strings.Repeat("x", 65)},
		"literal with brace":    {"a": "literal.{params.amount}"},
		"empty literal":         {"a": "literal."},
		"unknown reference":     {"a": "transaction.id"},
		"minor of text":         {"a": "params.reason.minor"},
	} {
		if err := formWrite(body).Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	kwd := formWrite(map[string]string{"amount": "params.amount.minor"})
	kwd.Params["amount"] = domain.ParamSpec{Type: domain.TypeMoney, Material: true, Currencies: []string{"KWD"}}
	if err := kwd.Validate(); err == nil || !strings.Contains(err.Error(), "CURRENCY_UNSUPPORTED") {
		t.Errorf("KWD in minor units: %v", err)
	}
	for name, edit := range map[string]func(h *domain.HTTPDispatch){
		"transaction key in the path": func(h *domain.HTTPDispatch) { h.Path = "/v1/{transaction.key}" },
		"transaction key in a query":  func(h *domain.HTTPDispatch) { h.Query = map[string]string{"k": "transaction.key"} },
		"literal in the path":         func(h *domain.HTTPDispatch) { h.Path = "/v1/{literal.x}" },
		"form on GET":                 func(h *domain.HTTPDispatch) { h.Method, h.Body = "GET", nil },
		"unknown encoding":            func(h *domain.HTTPDispatch) { h.Encoding = "xml" },
		"bracket key in JSON":         func(h *domain.HTTPDispatch) { h.Encoding = domain.EncodingJSON },
	} {
		d := formWrite(map[string]string{"metadata[k]": "literal.v"})
		edit(d.Dispatch.HTTP)
		if err := d.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	q := formWrite(map[string]string{"reason": "params.reason"})
	q.Dispatch.HTTP.Query = map[string]string{"limit": "literal.10", "charge": "target.id.ch"}
	if err := q.Validate(); err != nil {
		t.Errorf("a literal and a target group in a query (D71): %v", err)
	}
	json := formWrite(map[string]string{"key": "transaction.key", "mode": "literal.true"})
	json.Dispatch.HTTP.Encoding = domain.EncodingJSON
	if err := json.Validate(); err != nil {
		t.Errorf("literal and transaction key in a JSON body: %v", err)
	}
}

// TestM14_StaticHeadersSuccessAndCredentialPattern: static headers are
// literal and never reserved, the success field is a name, and the
// credential pattern is anchored and short (G0 M14 D8).
func TestM14_StaticHeadersSuccessAndCredentialPattern(t *testing.T) {
	d := formWrite(map[string]string{"reason": "params.reason"})
	d.Dispatch.HTTP.Headers = map[string]string{"Stripe-Version": "2026-09-30.endive"}
	d.Dispatch.HTTP.IdempotencyHeader = "Idempotency-Key"
	d.Dispatch.HTTP.Success = &domain.SuccessCheck{Field: "ok", Equals: true}
	d.Dispatch.CredentialPattern = `^(sk|rk)_test_[A-Za-z0-9]{16,}$`
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(x *domain.Dispatch){
		"reserved header":        func(x *domain.Dispatch) { x.HTTP.Headers = map[string]string{"Authorization": "Bearer x"} },
		"content type":           func(x *domain.Dispatch) { x.HTTP.Headers = map[string]string{"content-type": "text/plain"} },
		"the idempotency header": func(x *domain.Dispatch) { x.HTTP.Headers = map[string]string{"idempotency-key": "k"} },
		"a pap header":           func(x *domain.Dispatch) { x.HTTP.Headers = map[string]string{"PAP-Run-Id": "r"} },
		"a reference value":      func(x *domain.Dispatch) { x.HTTP.Headers = map[string]string{"X-A": "{params.reason}"} },
		"a control character":    func(x *domain.Dispatch) { x.HTTP.Headers = map[string]string{"X-A": "a\r\nb"} },
		"a long value":           func(x *domain.Dispatch) { x.HTTP.Headers = map[string]string{"X-A": strings.Repeat("v", 129)} },
		"success field":          func(x *domain.Dispatch) { x.HTTP.Success = &domain.SuccessCheck{Field: "a.b"} },
		"unanchored pattern":     func(x *domain.Dispatch) { x.CredentialPattern = `sk_test_` },
		"long pattern":           func(x *domain.Dispatch) { x.CredentialPattern = "^" + strings.Repeat("a", 128) + "$" },
	} {
		c := formWrite(map[string]string{"reason": "params.reason"})
		c.Dispatch.HTTP.IdempotencyHeader = "Idempotency-Key"
		edit(c.Dispatch)
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !d.Dispatch.CredentialMatches([]byte("rk_" + "test_" + "0123456789abcdefXYZ")) || d.Dispatch.CredentialMatches([]byte("sk_" + "live_" + "0123456789abcdefXYZ")) {
		t.Fatal("credential pattern")
	}
}

// TestM14_SQLAndA2AParts: a definition has exactly one of http, mcp, sql
// and a2a; sql is a read of rows, aggregate or tables; a2a names an A2A
// method; a2a mappings name a method too (G0 M14 D9).
func TestM14_SQLAndA2AParts(t *testing.T) {
	sql := minimal(nil)
	sql.Dispatch = &domain.Dispatch{SQL: &domain.SQLDispatch{Operation: "rows"}}
	if err := sql.Validate(); err != nil {
		t.Fatal(err)
	}
	peer := minimal(nil)
	peer.Dispatch = &domain.Dispatch{A2A: &domain.A2ADispatch{Method: "SendMessage"}}
	peer.Mappings = []domain.Mapping{{Channel: domain.ChannelA2A, Method: "SendMessage", Route: "send", Extract: domain.Extract{TargetID: "'a'"}}}
	if err := peer.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(d *domain.Definition){
		"two parts":     func(d *domain.Definition) { d.Dispatch.A2A = &domain.A2ADispatch{Method: "GetTask"} },
		"sql operation": func(d *domain.Definition) { d.Dispatch.SQL.Operation = "insert" },
		"sql write":     func(d *domain.Definition) { d.Access = domain.AccessWrite },
		"a2a method": func(d *domain.Definition) {
			d.Dispatch = &domain.Dispatch{A2A: &domain.A2ADispatch{Method: "SetTaskPushNotificationConfig"}}
		},
		"a2a mapping": func(d *domain.Definition) {
			d.Mappings[0] = domain.Mapping{Channel: domain.ChannelA2A, Method: "Send", Route: "x"}
		},
		"a2a with a tool": func(d *domain.Definition) {
			d.Mappings[0] = domain.Mapping{Channel: domain.ChannelA2A, Method: "GetTask", Tool: "t", Route: "x"}
		},
		"hook encoding": func(d *domain.Definition) { d.Mappings[0].Encoding = domain.EncodingForm },
	} {
		c := minimal(nil)
		c.Dispatch = &domain.Dispatch{SQL: &domain.SQLDispatch{Operation: "rows"}}
		edit(c)
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestM14_ResponseAndScoping: a definition's answer fields are distinct
// dotted paths with a data class, and only a read declares the data scope
// it can enforce (G0 M14 D9).
func TestM14_ResponseAndScoping(t *testing.T) {
	d := minimal(nil)
	d.Response = &domain.ResponseSpec{Format: "json", Fields: []domain.ResponseField{
		{Path: "billing_details.*", Class: "pii"}, {Path: "receipt_email", Class: "pii"}, {Path: "data.*.ssn", Class: "secret"},
	}}
	d.Scoping = []string{"classes", "records"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(d *domain.Definition){
		"format":        func(d *domain.Definition) { d.Response.Format = "xml" },
		"class":         func(d *domain.Definition) { d.Response.Fields[0].Class = "confidential" },
		"path twice":    func(d *domain.Definition) { d.Response.Fields[1].Path = d.Response.Fields[0].Path },
		"empty segment": func(d *domain.Definition) { d.Response.Fields[0].Path = "a..b" },
		"scoping kind":  func(d *domain.Definition) { d.Scoping = []string{"rows"} },
		"scoping twice": func(d *domain.Definition) { d.Scoping = []string{"records", "records"} },
		"a write":       func(d *domain.Definition) { d.Access = domain.AccessWrite },
	} {
		c := *d
		c.Response = &domain.ResponseSpec{Format: d.Response.Format, Fields: append([]domain.ResponseField(nil), d.Response.Fields...)}
		edit(&c)
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestM14_QueryFilters: a query filter is a list of at most 20 predicates
// over lower-case columns, each operator with exactly the value it takes,
// strings only; it is decoded as strictly as any param (G0 M14 D9).
func TestM14_QueryFilters(t *testing.T) {
	d := minimal(map[string]domain.ParamSpec{"filters": {Type: domain.TypeQueryFilter}})
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	good := `[{"column":"tier","op":"eq","value":"gold"},{"column":"id","op":"in","values":["a","b"]},{"column":"email","op":"not_null"}]`
	vals, err := d.DecodeParams([]byte(`{"filters":` + good + `}`))
	if err != nil || len(vals["filters"].Filter) != 3 {
		t.Fatalf("decode: %+v %v", vals, err)
	}
	if raw, err := d.EncodeParams(vals); err != nil || string(raw) != `{"filters":`+good+`}` {
		t.Fatalf("encode: %s %v", raw, err)
	}
	many := "[" + strings.TrimSuffix(strings.Repeat(`{"column":"a","op":"is_null"},`, 21), ",") + "]"
	for name, f := range map[string]string{
		"not a list":         `{"column":"a","op":"eq","value":"x"}`,
		"unknown member":     `[{"column":"a","op":"eq","value":"x","raw":"1=1"}]`,
		"quoted column":      `[{"column":"\"a\"","op":"eq","value":"x"}]`,
		"upper-case column":  `[{"column":"Name","op":"eq","value":"x"}]`,
		"unknown op":         `[{"column":"a","op":"like","value":"x"}]`,
		"eq without value":   `[{"column":"a","op":"eq"}]`,
		"eq with values":     `[{"column":"a","op":"eq","values":["x"]}]`,
		"is_null with value": `[{"column":"a","op":"is_null","value":"x"}]`,
		"in without values":  `[{"column":"a","op":"in","values":[]}]`,
		"number value":       `[{"column":"a","op":"eq","value":1}]`,
		"long value":         `[{"column":"a","op":"eq","value":"` + strings.Repeat("x", 257) + `"}]`,
		"control character":  `[{"column":"a","op":"eq","value":"a\u0000"}]`,
		"21 predicates":      many,
		"101 values":         `[{"column":"a","op":"in","values":[` + strings.TrimSuffix(strings.Repeat(`"x",`, 101), ",") + `]}]`,
	} {
		if _, err := d.DecodeParams([]byte(`{"filters":` + f + `}`)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	tmpl := minimal(map[string]domain.ParamSpec{"filters": {Type: domain.TypeQueryFilter}})
	tmpl.Dispatch = &domain.Dispatch{HTTP: &domain.HTTPDispatch{Method: "POST", Path: "/q", Body: map[string]string{"f": "params.filters"}}}
	if err := tmpl.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("a query filter sent from a template: %v", err)
	}
}

// TestM14_BindingAtMost: a binding may compare with le, a material money
// or integer param at most the fact's member; eq keeps its types (G0 M14
// D48).
func TestM14_BindingAtMost(t *testing.T) {
	d := minimal(map[string]domain.ParamSpec{
		"amount": {Type: domain.TypeMoney, Material: true, Currencies: []string{"USD"}},
		"count":  {Type: domain.TypeInteger, Material: true, Unit: "count"},
		"id":     {Type: domain.TypeIdentifier, Material: true},
	})
	for name, c := range map[string]struct {
		b  domain.FactBinding
		ok bool
	}{
		"le money":   {domain.FactBinding{Member: "remaining", Param: "amount", Reason: "AMOUNT_NOT_REFUNDABLE", Op: "le"}, true},
		"le integer": {domain.FactBinding{Member: "left", Param: "count", Reason: "TOO_MANY", Op: "le"}, true},
		"eq default": {domain.FactBinding{Member: "id", Param: "id", Reason: "MOVED"}, true},
		"eq named":   {domain.FactBinding{Member: "id", Param: "id", Reason: "MOVED", Op: "eq"}, true},
		"le id":      {domain.FactBinding{Member: "id", Param: "id", Reason: "MOVED", Op: "le"}, false},
		"eq money":   {domain.FactBinding{Member: "remaining", Param: "amount", Reason: "MOVED", Op: "eq"}, false},
		"lt":         {domain.FactBinding{Member: "left", Param: "count", Reason: "TOO_MANY", Op: "lt"}, false},
	} {
		x := *d
		x.Prerequisites = []domain.Prerequisite{{Fact: "x.thing.left", MaxAgeSeconds: 60, Binds: &c.b}}
		if err := x.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestM14_VerifierExpectsMinorUnits: a verifier may compare a target's
// integer amount with params.<money>.minor (G0 M14 D8).
func TestM14_VerifierExpectsMinorUnits(t *testing.T) {
	m, err := money.ParseMoney("85.50", "USD")
	if err != nil {
		t.Fatal(err)
	}
	v := &domain.VerifierSpec{Expect: []domain.Expectation{{Field: "/amount", Equals: "params.amount.minor"}}}
	got, ok := v.Expected(actionir.Target{}, domain.Values{"amount": {Type: domain.TypeMoney, Money: m}})
	if !ok || got["/amount"] != "8550" {
		t.Fatalf("expected %v %v", got, ok)
	}
}

// TestM14_ResponseClassesCoverSubtrees: a field naming an object or an
// array classifies everything under it, and where declarations overlap
// the strictest class wins; an undeclared value is public (G0 M14 D73).
func TestM14_ResponseClassesCoverSubtrees(t *testing.T) {
	r := &domain.ResponseSpec{Format: "json", Fields: []domain.ResponseField{
		{Path: "billing_details", Class: "pii"},
		{Path: "billing_details.name", Class: "internal"},
		{Path: "data.*.ssn", Class: "secret"},
		{Path: "data", Class: "internal"},
		{Path: "metadata.*", Class: "internal"},
	}}
	for path, want := range map[string]string{
		"billing_details":               "pii",
		"billing_details.name":          "pii",
		"billing_details.address.line1": "pii",
		"data":                          "internal",
		"data.*.ssn":                    "secret",
		"data.*.id":                     "internal",
		"metadata.order":                "internal",
		"metadata":                      "public",
		"id":                            "public",
	} {
		if got := r.ClassOf(strings.Split(path, ".")); got != want {
			t.Errorf("%s: %s, want %s", path, got, want)
		}
	}
	if (*domain.ResponseSpec)(nil).ClassOf([]string{"x"}) != "public" || domain.Stricter("secret", "pii") != "secret" {
		t.Fatal("helpers")
	}
	d := minimal(nil)
	d.Response = r
	if err := d.Validate(); err != nil {
		t.Fatalf("overlapping declarations are valid: %v", err)
	}
}
