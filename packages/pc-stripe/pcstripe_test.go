// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcstripe_test

import (
	"context"
	"encoding/json/v2"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
)

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func mapper(t *testing.T) *mapping.Mapper {
	t.Helper()
	p, err := manifest.Decode(pcstripe.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pcstripe.Name || p.Version != pcstripe.Version {
		t.Fatalf("package %s %s", p.Name, p.Version)
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestPackageMapsStripeRequests: the package decodes, its mappings compile,
// and a Stripe refund maps to the same action over the HTTP face (form,
// lowercase currency, by charge or payment intent) and the MCP face; a
// refund naming both or neither payment is refused (HR-305, D71).
func TestPackageMapsStripeRequests(t *testing.T) {
	m := mapper(t)
	ctx := context.Background()
	form := func(body string) (string, string, error) {
		a, err := m.HTTPRequest(ctx, tc, "POST", "/v1/refunds", "", mapping.FormContentType, []byte(body))
		if err != nil {
			return "", "", err
		}
		return a.Action.Operation + " " + a.Action.Target.ID, string(a.Action.Params), nil
	}
	op, params, err := form("payment_intent=pi_SimPayment0001&amount=1250&currency=usd&reason=duplicate")
	want := `{"amount":{"currency":"USD","value":"12.50"},"reason":"duplicate"}`
	if err != nil || op != "stripe.refund.create pi_SimPayment0001" || !sameJSON(params, want) {
		t.Fatalf("by intent: %s %s %v", op, params, err)
	}
	if op, _, err := form("charge=ch_SimCharge0001&amount=100&currency=jpy"); err != nil || op != "stripe.refund.create ch_SimCharge0001" {
		t.Fatalf("by charge: %s %v", op, err)
	}
	for name, body := range map[string]string{
		"both":     "payment_intent=pi_SimPayment0001&charge=ch_SimCharge0001&amount=100&currency=usd",
		"neither":  "amount=100&currency=usd",
		"currency": "payment_intent=pi_SimPayment0001&amount=100&currency=xyz",
		"decimal":  "payment_intent=pi_SimPayment0001&amount=1.50&currency=usd",
	} {
		if op, _, err := form(body); err == nil {
			t.Errorf("%s mapped to %s", name, op)
		}
	}
	a, err := m.MCP(ctx, tc, "create_refund", []byte(`{"payment":"pi_SimPayment0001","amount":1250,"currency":"USD","reason":"duplicate"}`))
	if err != nil || a.Action.Operation != "stripe.refund.create" || !sameJSON(string(a.Action.Params), want) {
		t.Fatalf("mcp: %+v %v", a.Action, err)
	}
	b, err := m.HTTPRequest(ctx, tc, "GET", "/v1/balance", "", "", nil)
	if err != nil || b.Action.Operation != "stripe.balance.read" || b.Action.Target.ID != "balance" {
		t.Fatalf("balance: %+v %v", b.Action, err)
	}
	tr, err := m.HTTPRequest(ctx, tc, "POST", "/v1/transfers", "", mapping.FormContentType,
		[]byte("destination=acct_SimPayee0001&amount=1000&currency=usd&description=Invoice+42"))
	if err != nil || tr.Action.Operation != "stripe.transfer.create" || len(tr.Action.Destinations) != 1 ||
		tr.Action.Destinations[0].ID != "acct_SimPayee0001" {
		t.Fatalf("transfer: %+v %v", tr.Action, err)
	}
}

func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x, json.Deterministic(true))
	jb, _ := json.Marshal(y, json.Deterministic(true))
	return string(ja) == string(jb)
}
