// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"context"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// m14Package is the M14 format fixture the mapping golden test pins.
func m14Package(t testing.TB) *defs.Package {
	t.Helper()
	raw, err := os.ReadFile("../../definitions/mapping/testdata/m14-format.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fataler is testing.TB or *rapid.T.
type fataler interface {
	Helper()
	Fatal(args ...any)
}

// nested is what the form parser makes of a flat body object.
func nested(t fataler, obj map[string]any) map[string]any {
	t.Helper()
	out := map[string]any{}
	for k, v := range obj {
		fk, err := defs.ParseFormKey(k)
		if err != nil {
			t.Fatal(err)
		}
		cur := out
		for _, name := range fk.Path[:len(fk.Path)-1] {
			next, ok := cur[name].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[name] = next
			}
			cur = next
		}
		leaf := fk.Path[len(fk.Path)-1]
		switch x := v.(type) {
		case []string:
			l := make([]any, len(x))
			for i, s := range x {
				l[i] = s
			}
			cur[leaf] = l
		case string:
			if fk.List {
				cur[leaf] = []any{x}
			} else {
				cur[leaf] = x
			}
		}
	}
	return out
}

// TestHR300_FormRebuildRoundTrips: the outbound form is rebuilt from the
// resolved template alone, keys sorted and every byte but the unreserved
// ones percent-encoded (RFC 3986), and the one form parser reads it back
// exactly (G0 M14 D8).
func TestHR300_FormRebuildRoundTrips(t *testing.T) {
	obj := map[string]any{
		"amount": "8550", "metadata[note]": "a b+c&d=e%f", "expand[]": []string{"charge", "customer"},
		"metadata[order_id]": "A-1.2_3~", "zeta[x][]": "only",
	}
	b, err := EncodeForm(obj)
	want := "amount=8550&expand%5B%5D=charge&expand%5B%5D=customer&metadata%5Bnote%5D=a%20b%2Bc%26d%3De%25f" +
		"&metadata%5Border_id%5D=A-1.2_3~&zeta%5Bx%5D%5B%5D=only"
	if err != nil || string(b) != want {
		t.Fatalf("built %s, %v", b, err)
	}
	got, err := mapping.DecodeForm(FormContentType, b)
	if err != nil || !reflect.DeepEqual(got, nested(t, obj)) {
		t.Fatalf("read back %#v, %v", got, err)
	}
	for name, bad := range map[string]map[string]any{
		"a list under a scalar key": {"a": []string{"x"}},
		"two meanings":              {"a": "x", "a[b]": "y"},
		"a map value":               {"a": map[string]any{"b": "c"}},
		"a key outside the grammar": {"a b": "x"},
	} {
		if b, err := EncodeForm(bad); err == nil {
			t.Errorf("%s: built %s", name, b)
		}
	}
}

// TestT140_FormParseAndRebuildAgree: whatever keys and values a body has,
// the target reads the rebuilt form exactly as the agent-facing parser
// read the agent's form, whichever common encoder wrote it (Go's url
// encoding with + for spaces, or the gateway's RFC 3986 rebuild): no
// separator, escape, bracket or Unicode text changes the meaning between
// the decision and the dispatch (G0 M14 D10).
func TestT140_FormParseAndRebuildAgree(t *testing.T) {
	name := rapid.StringMatching(`[A-Za-z_][A-Za-z0-9_]{0,8}`)
	seg := rapid.StringMatching(`[A-Za-z_.-][A-Za-z0-9_.-]{0,8}`)
	value := rapid.StringOfN(rapid.RuneFrom([]rune("aZ09 &=+%[]?#/;,~-_.é€\U0001F600\t")), 0, 24, -1)
	rapid.Check(t, func(t *rapid.T) {
		obj := map[string]any{}
		agent := url.Values{}
		for _, root := range rapid.SliceOfNDistinct(name, 1, 6, strings.ToLower).Draw(t, "roots") {
			switch rapid.IntRange(0, 2).Draw(t, "shape") {
			case 0:
				v := value.Draw(t, "v")
				if strings.ContainsRune(v, '\t') {
					continue // a control character: refused, tested elsewhere
				}
				obj[root] = v
				agent.Set(root, v)
			case 1:
				k := root + "[" + seg.Draw(t, "seg") + "]"
				v := strings.ReplaceAll(value.Draw(t, "v"), "\t", " ")
				obj[k] = v
				agent.Set(k, v)
			case 2:
				items := rapid.SliceOfN(value, 1, 4).Draw(t, "items")
				for i := range items {
					items[i] = strings.ReplaceAll(items[i], "\t", " ")
				}
				obj[root+"[]"] = items
				for _, it := range items {
					agent.Add(root+"[]", it)
				}
			}
		}
		if len(obj) == 0 {
			return
		}
		fromAgent, err := mapping.DecodeForm(FormContentType, []byte(agent.Encode()))
		if err != nil {
			t.Fatalf("agent form %q: %v", agent.Encode(), err)
		}
		rebuilt, err := EncodeForm(obj)
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		fromTarget, err := mapping.DecodeForm(FormContentType, rebuilt)
		if err != nil {
			t.Fatalf("rebuilt form %q: %v", rebuilt, err)
		}
		if !reflect.DeepEqual(fromAgent, fromTarget) || !reflect.DeepEqual(fromTarget, nested(t, obj)) {
			t.Fatalf("agent read %#v, target reads %#v", fromAgent, fromTarget)
		}
	})
}

// TestHR300_FormRefundIsRebuiltFromTheAction: an agent's form refund maps
// to an action, and the outbound form carries exactly that action:
// integer minor units, the matched part of the target id only (the payment
// intent or the charge, D49), the transaction key (D50), literals (D52),
// the static Stripe-Version header and the form media type (D8).
func TestHR300_FormRefundIsRebuiltFromTheAction(t *testing.T) {
	pkg := m14Package(t)
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := pkg.Definition("shop.refund.create")
	tc := mapping.Context{
		Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
		RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
		AgentInstance: "01920000-0000-7000-8000-000000000005",
	}
	for _, c := range []struct{ in, want string }{
		{
			"payment_intent=pi_0123456789&amount=8550&currency=USD&reason=duplicate",
			"amount=8550&expand%5B%5D=charge&metadata%5Bpantherclaw_key%5D=pc-" + txn + "&payment_intent=pi_0123456789&reason=duplicate",
		},
		{
			"charge=ch_0123456789&amount=1200&currency=JPY",
			"amount=1200&charge=ch_0123456789&expand%5B%5D=charge&metadata%5Bpantherclaw_key%5D=pc-" + txn,
		},
	} {
		p, err := m.HTTPRequest(context.Background(), tc, "POST", "/v1/refunds", "", mapping.FormContentType, []byte(c.in))
		if err != nil {
			t.Fatal(err)
		}
		r, err := Build("https://api.stripe.example.test", d, p.Action, txn)
		if err != nil || string(r.Body) != c.want || r.ContentType != FormContentType ||
			r.Headers["Stripe-Version"] != "2026-09-30.endive" || r.IdempotencyKey != "pc-"+txn {
			t.Fatalf("built %s %s %v %v", r.Body, r.ContentType, r.Headers, err)
		}
	}
	// An id matching neither group names no target, so nothing is built.
	a := actionir.ActionIR{Target: actionir.Target{Type: "shop.payment", ID: "re_0123456789"}, Params: []byte(`{"amount":{"currency":"USD","value":"1.00"}}`)}
	if _, err := Build("https://api.stripe.example.test", d, a, txn); !errors.Is(err, ErrBuild) {
		t.Fatalf("an id of neither kind: %v", err)
	}
}

// TestM14_TemplateReferences: an optional, unmatched target group leaves
// its body field out but still fails in a path (D49); minor units refuse a
// currency outside their list at dispatch (D8); literals and the
// transaction key are plain strings in a JSON body (D50, D52); a JSON
// boolean is bool.true or bool.false (G0 M20 D263, D272).
func TestM14_TemplateReferences(t *testing.T) {
	d := &defs.Definition{
		Operation: "shop.refund.create",
		Target:    defs.TargetSpec{Type: "shop.payment", IDPattern: `^(?:(?P<pi>pi_[a-z0-9]+)|(?P<ch>ch_[a-z0-9]+))$`},
		Params:    map[string]defs.ParamSpec{"amount": {Type: defs.TypeMoney, Material: true, Required: true, Currencies: []string{"USD", "KWD"}}},
		Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{Method: "POST", Path: "/r", Body: map[string]string{
			"pi": "target.id.pi", "ch": "target.id.ch", "minor": "params.amount.minor", "key": "transaction.key", "mode": "literal.true",
			"kind": "literal.refund",
		}}},
	}
	a := actionir.ActionIR{Target: actionir.Target{Type: "shop.payment", ID: "ch_abc"}, Params: []byte(`{"amount":{"currency":"USD","value":"0.05"}}`)}
	r, err := Build("https://x.example.test", d, a, txn)
	if err != nil || string(r.Body) != `{"ch":"ch_abc","key":"pc-`+txn+`","kind":"refund","minor":"5","mode":"true"}` || r.ContentType != JSONContentType {
		t.Fatalf("built %s %v", r.Body, err)
	}
	kwd := a
	kwd.Params = []byte(`{"amount":{"currency":"KWD","value":"1.500"}}`)
	if _, err := Build("https://x.example.test", d, kwd, txn); !errors.Is(err, ErrBuild) {
		t.Fatalf("KWD in minor units: %v", err)
	}
	path := *d
	path.Dispatch = &defs.Dispatch{HTTP: &defs.HTTPDispatch{Method: "GET", Path: "/r/{target.id.pi}"}}
	if _, err := Build("https://x.example.test", &path, a, txn); !errors.Is(err, ErrBuild) {
		t.Fatalf("an unmatched group in the path: %v", err)
	}
}

// TestM14_QueryLiteralsAndOptionalGroups: query values may be literals,
// and a target group the id left unmatched leaves its query parameter out;
// when every target-group reference of body and query is left out the
// build fails (G0 M14 D71).
func TestM14_QueryLiteralsAndOptionalGroups(t *testing.T) {
	d := &defs.Definition{
		Operation: "shop.refund.list",
		Target:    defs.TargetSpec{Type: "shop.payment", IDPattern: `^(?:(?P<pi>pi_[a-z0-9]+)|(?P<ch>ch_[a-z0-9]+))$`},
		Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{Method: "GET", Path: "/v1/refunds", Query: map[string]string{
			"payment_intent": "target.id.pi", "charge": "target.id.ch", "limit": "literal.10",
		}}},
	}
	a := actionir.ActionIR{Target: actionir.Target{Type: "shop.payment", ID: "pi_abc"}, Params: []byte(`{}`)}
	r, err := Build("https://x.example.test", d, a, txn)
	if err != nil || r.URL.RawQuery != "limit=10&payment_intent=pi_abc" {
		t.Fatalf("built %v %v", r.URL, err)
	}
	only := *d
	only.Dispatch = &defs.Dispatch{HTTP: &defs.HTTPDispatch{Method: "GET", Path: "/v1/refunds", Query: map[string]string{"charge": "target.id.ch"}}}
	if _, err := Build("https://x.example.test", &only, a, txn); !errors.Is(err, ErrBuild) {
		t.Fatalf("no target group matched: %v", err)
	}
	split := *d
	split.Dispatch = &defs.Dispatch{HTTP: &defs.HTTPDispatch{
		Method: "POST", Path: "/v1/refunds", Query: map[string]string{"charge": "target.id.ch"}, Body: map[string]string{"payment_intent": "target.id.pi"},
	}}
	if r, err := Build("https://x.example.test", &split, a, txn); err != nil || r.URL.RawQuery != "" || string(r.Body) != `{"payment_intent":"pi_abc"}` {
		t.Fatalf("one group in the body, one in the query: %v %s %v", r.URL, r.Body, err)
	}
}
