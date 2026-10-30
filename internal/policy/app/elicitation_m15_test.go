// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"os"
	"testing"

	"cel.dev/cel-go/cel"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// TestHR420_PolicyReadsElicitationAnswersAsANestedStruct (G0 M15 D46): an
// answer to a declared elicitation field is action.params.elicitation.<field>
// in policy, set only when an answer is present; an operation without an
// elicitation spec has no elicitation field, so a rule naming it does not
// compile. The ActionIR keeps the elicitation.<field> names (D38).
// Covers: PN-015.2
func TestHR420_PolicyReadsElicitationAnswersAsANestedStruct(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	createMCP := []byte("      - channel: mcp\n        tool: create_refund\n        route: payments-refund\n")
	raw = bytes.Replace(raw, createMCP, append(createMCP, []byte("        elicitation:\n          fields:\n"+
		"            channel:\n              type: enum\n              values: [email, sms]\n")...), 1)
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	create, _ := pkg.Definition("payments.refund.create")
	env, err := celenv.New(celenv.DefaultLimits, ActionSchema(create), ActionVariable)
	if err != nil {
		t.Fatal(err)
	}
	const rule = `has(action.params.elicitation) && has(action.params.elicitation.channel) && action.params.elicitation.channel == "sms"`
	p, err := env.Compile(rule, cel.BoolType)
	if err != nil {
		t.Fatalf("the nested form: %v", err)
	}
	args := []byte(`{"charge":"ch_1","amount":"30","currency":"USD","reason":"duplicate"}`)
	for want, answer := range map[bool]defs.Values{
		true:  {"channel": {Type: defs.TypeEnum, Str: "sms"}},
		false: {"channel": {Type: defs.TypeEnum, Str: "email"}},
	} {
		a, err := m.MCPAnswered(context.Background(), tc, "create_refund", args, answer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(a.Action.Params, []byte(`"elicitation.channel"`)) {
			t.Fatalf("the ActionIR param %s", a.Action.Params)
		}
		vals, err := create.DecodeParams(a.Action.Params)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := p.EvalBool(context.Background(), map[string]any{"action": ActionRecord(create, a.Action, vals, "")})
		if err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", answer["channel"].Str, got, err, want)
		}
	}
	plain, err := m.MCP(context.Background(), tc, "create_refund", args)
	if err != nil {
		t.Fatal(err)
	}
	vals, _ := create.DecodeParams(plain.Action.Params)
	if got, _, err := p.EvalBool(context.Background(), map[string]any{"action": ActionRecord(create, plain.Action, vals, "")}); err != nil || got {
		t.Errorf("no answer: %v %v", got, err)
	}

	get, _ := pkg.Definition("payments.refund.get")
	genv, err := celenv.New(celenv.DefaultLimits, ActionSchema(get), ActionVariable)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genv.Compile(`has(action.params.elicitation)`, cel.BoolType); err == nil {
		t.Fatal("an operation without an elicitation spec has an elicitation field")
	}
}
