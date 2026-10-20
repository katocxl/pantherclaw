// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"strings"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

func scopeConn(kind string) *control.Connection {
	return &control.Connection{GatewayConnection: &pb.GatewayConnection{Kind: kind, AccessMode: "pantherclaw_held"}}
}

func readDef(scoping ...string) *defs.Definition {
	return &defs.Definition{Operation: "x.read", Access: defs.AccessRead, Scoping: scoping}
}

func records(key string, values ...string) *pb.Obligation {
	return &pb.Obligation{Kind: obligationRecordScope, Param: key, Values: values, Timing: "before_execution"}
}

func classes(values ...string) *pb.Obligation {
	return &pb.Obligation{Kind: obligationDataClasses, Values: values, Timing: "before_execution"}
}

// TestHR310_ScopeIsAppliedOrNothingIsSent (D20, HR-302): a record scope
// reaches a postgres read; anywhere it cannot be enforced, and for any
// malformed or duplicated obligation, the dispatch is refused before
// anything is sent. Without a scope obligation there is no scope.
func TestHR310_ScopeIsAppliedOrNothingIsSent(t *testing.T) {
	ctx, code := withScope(context.Background(), scopeConn("postgres"), readDef("records", "classes"),
		[]*pb.Obligation{records("customer", "7"), classes("public"), {Kind: "count_max", Param: "limit"}})
	acc, rs := scopeOf(ctx).pgAccess()
	if code != "" || rs == nil || rs.Key != "customer" || rs.Values[0] != "7" || len(acc.Classes) != 1 {
		t.Fatalf("postgres: %q %+v %+v", code, acc, rs)
	}
	if ctx, code := withScope(context.Background(), scopeConn("postgres"), readDef(), []*pb.Obligation{{Kind: "count_max"}}); code != "" || scopeOf(ctx) != nil {
		t.Fatal("a scope without a scope obligation")
	}
	write := readDef("records", "classes")
	write.Access = defs.AccessWrite
	for name, c := range map[string]struct {
		conn *control.Connection
		def  *defs.Definition
		obs  []*pb.Obligation
	}{
		"records on http":    {scopeConn("http"), readDef("records", "classes"), []*pb.Obligation{records("customer", "7")}},
		"records undeclared": {scopeConn("postgres"), readDef("classes"), []*pb.Obligation{records("customer", "7")}},
		"classes undeclared": {scopeConn("postgres"), readDef("records"), []*pb.Obligation{classes("public")}},
		"a write":            {scopeConn("postgres"), write, []*pb.Obligation{classes("public")}},
		"two record scopes":  {scopeConn("postgres"), readDef("records"), []*pb.Obligation{records("customer", "7"), records("customer", "8")}},
		"secret allowed":     {scopeConn("postgres"), readDef("classes"), []*pb.Obligation{classes("public", "secret")}},
		"unknown class":      {scopeConn("postgres"), readDef("classes"), []*pb.Obligation{classes("confidential")}},
		"bad key":            {scopeConn("postgres"), readDef("records"), []*pb.Obligation{records(`customer"; --`, "7")}},
		"after execution":    {scopeConn("postgres"), readDef("classes"), []*pb.Obligation{{Kind: obligationDataClasses, Values: []string{"public"}, Timing: "after_execution"}}},
	} {
		if _, code := withScope(context.Background(), c.conn, c.def, c.obs); code != CodeScopeUnsupported {
			t.Errorf("%s: %q", name, code)
		}
	}
}

// TestHR311_JSONAnswersAreRedactedByClass (D20, D73): under a data_classes
// obligation every value of a class it does not allow is withheld, a
// declared object or array path covers its whole subtree, the strictest
// covering class wins, secret is always withheld, integers stay exact, and
// an answer the engine cannot read is withheld.
func TestHR311_JSONAnswersAreRedactedByClass(t *testing.T) {
	spec := &defs.ResponseSpec{Format: "json", Fields: []defs.ResponseField{
		{Path: "billing_details", Class: "pii"},
		{Path: "receipt_email", Class: "pii"},
		{Path: "charges.*.card", Class: "internal"},
		{Path: "charges.*.card.fingerprint", Class: "secret"},
		{Path: "metadata.note", Class: "internal"},
	}}
	body := `{"id":"pi_1","amount":12345678901234567890,"receipt_email":"a@example.com","billing_details":{"name":"Ada","address":{"city":"London"}},` +
		`"charges":[{"id":"ch_1","card":{"last4":"4242","fingerprint":"fp"}}],"metadata":{"note":"vip","tag":"x"}}`
	s := &dataScope{classes: []pgdispatch.Class{pgdispatch.ClassPublic, pgdispatch.ClassInternal}}
	out, n, ok := scopeJSON([]byte(body), false, spec, s)
	got := string(out)
	for _, want := range []string{
		`"amount":12345678901234567890`, `"billing_details":"[redacted:pii]"`, `"receipt_email":"[redacted:pii]"`,
		`"fingerprint":"[redacted:secret]"`, `"last4":"4242"`, `"note":"vip"`, `"id":"pi_1"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("answer lacks %s: %s", want, got)
		}
	}
	if !ok || n != 3 || strings.Contains(got, "Ada") || strings.Contains(got, "London") || strings.Contains(got, `"fp"`) {
		t.Fatalf("ok %v, %d redacted: %s", ok, n, got)
	}
	s = &dataScope{classes: []pgdispatch.Class{pgdispatch.ClassPublic}}
	out, _, _ = scopeJSON([]byte(body), false, spec, s)
	if !strings.Contains(string(out), `"card":"[redacted:internal]"`) || strings.Contains(string(out), "4242") {
		t.Fatalf("subtree: %s", out)
	}
	// The strictest covering class wins even when a nested path is laxer.
	spec2 := &defs.ResponseSpec{Fields: []defs.ResponseField{{Path: "a", Class: "pii"}, {Path: "a.b", Class: "public"}}}
	out, _, _ = scopeJSON([]byte(`{"a":{"b":"x"}}`), false, spec2, s)
	if string(out) != `{"a":"[redacted:pii]"}` {
		t.Fatalf("strictest: %s", out)
	}
	for name, b := range map[string]string{"not json": "<html>", "two values": `{} {}`, "duplicate": `{"a":1,"a":2}`, "empty": ` `} {
		if _, _, ok := scopeJSON([]byte(b), false, spec, s); ok {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, ok := scopeJSON([]byte(`{}`), true, spec, s); ok {
		t.Error("a truncated answer accepted")
	}
}

// TestHR311_JSONScopeBounds (D116): an answer nested deeper than the bound,
// or larger than it, is withheld, and a root scalar is checked like any
// value.
func TestHR311_JSONScopeBounds(t *testing.T) {
	s := &dataScope{classes: []pgdispatch.Class{pgdispatch.ClassPublic}}
	deep := strings.Repeat("[", maxScopedDepth+2) + "1" + strings.Repeat("]", maxScopedDepth+2)
	if _, _, ok := scopeJSON([]byte(deep), false, nil, s); ok {
		t.Error("a too deep answer was scoped")
	}
	ok32 := strings.Repeat("[", maxScopedDepth) + "1" + strings.Repeat("]", maxScopedDepth)
	if _, _, ok := scopeJSON([]byte(ok32), false, nil, s); !ok {
		t.Error("an answer within the depth bound was withheld")
	}
	if _, _, ok := scopeJSON([]byte(`"`+strings.Repeat("a", maxScopedAnswer)+`"`), false, nil, s); ok {
		t.Error("a too large answer was scoped")
	}
	none := &dataScope{classes: []pgdispatch.Class{}}
	out, n, ok := scopeJSON([]byte(`"ada@example.com"`), false, nil, none)
	if !ok || n != 1 || string(out) != `"[redacted:public]"` {
		t.Fatalf("root scalar with no readable class: %s %d %v", out, n, ok)
	}
	if out, _, _ := scopeJSON([]byte(`"x"`), false, nil, s); string(out) != `"x"` {
		t.Fatalf("readable root scalar: %s", out)
	}
}
