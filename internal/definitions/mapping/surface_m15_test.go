// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

func replaceOnce(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	if bytes.Count(raw, []byte(from)) != 1 {
		t.Fatalf("%q not found once", from)
	}
	return bytes.Replace(raw, []byte(from), []byte(to), 1)
}

// resourceRaw serves get_refund as the resource payments://refunds/{refund}.
func resourceRaw(t *testing.T) []byte {
	t.Helper()
	raw := replaceOnce(t, mockRaw(t),
		"      - channel: mcp\n        tool: get_refund\n        route: payments-refund-get\n"+
			"        description: Read one refund on the simulated payments API by its id.\n",
		"      - channel: mcp_resource\n        resource: 'payments://refunds/{refund}'\n        route: payments-refund-get\n")
	raw = replaceOnce(t, raw,
		"        input_schema:\n          type: object\n          additionalProperties: false\n          required: [refund]\n"+
			"          properties:\n            refund:\n              type: string\n              description: The refund id\n"+
			"              pattern: '^re_[A-Za-z0-9-]{1,64}$'\n        extract:\n          target_id: input.refund\n",
		"        extract:\n          target_id: path.refund\n")
	return replaceOnce(t, raw, "    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds/{target.id}\n",
		"    dispatch:\n      mcp:\n        resource: 'payments://refunds/{target.id}'\n        upstream_digest: sha256:"+strings.Repeat("0f", 32)+"\n")
}

// TestHR419_AResourceReadMapsOnlyThroughAReviewedTemplate: a URI that
// matches the reviewed template maps to the read's action, through the mcp
// channel and the mapping's route, with the template's values; any other
// URI is unmapped, and an extraction that reads a variable the template
// lacks is a package error.
// Covers: F352
func TestHR419_AResourceReadMapsOnlyThroughAReviewedTemplate(t *testing.T) {
	m := mapperFor(t, resourceRaw(t))
	if rs := m.Resources(); len(rs) != 1 || rs[0].URI != "payments://refunds/{refund}" || rs[0].Static || rs[0].Operation != "payments.refund.get" {
		t.Fatalf("resources %+v", rs)
	}
	p, err := m.ReadResource(context.Background(), tc, "payments://refunds/re_1")
	if err != nil {
		t.Fatal(err)
	}
	if a := p.Action; a.Operation != "payments.refund.get" || a.Channel != "mcp" || a.Route != "payments-refund-get" || a.Target.ID != "re_1" {
		t.Fatalf("action %+v", a)
	}
	for _, uri := range []string{"payments://refunds/re_1/x", "payments://refunds/", "https://refunds/re_1", "payments://refunds/ch_1"} {
		_, err := m.ReadResource(context.Background(), tc, uri)
		if uri == "payments://refunds/ch_1" {
			// Matches the template but not the target's identity pattern.
			if !errors.Is(err, actionir.ErrAmbiguous) {
				t.Errorf("%s: %v", uri, err)
			}
			continue
		}
		if !errors.Is(err, ErrUnmapped) {
			t.Errorf("%s: %v", uri, err)
		}
	}
	if _, _, ok := m.ResourceRoute("payments://other"); ok {
		t.Error("an unreviewed URI has a route")
	}
	const resExtract = "{refund}'\n        route: payments-refund-get\n        extract:\n          target_id: path."
	p2, err := manifest.Decode(replaceOnce(t, resourceRaw(t), resExtract+"refund\n", resExtract+"other\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(p2, celenv.DefaultLimits); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a variable the template lacks: %v", err)
	}
}

// TestHR420_AnswersBecomeDeclaredMaterialParams: a call with elicitation
// answers maps like the call, plus each answer as the material param
// elicitation.<field>; an undeclared field or a value of another type or
// outside the declared spec is ambiguous.
// Covers: PN-015.2
func TestHR420_AnswersBecomeDeclaredMaterialParams(t *testing.T) {
	createMCP := "      - channel: mcp\n        tool: create_refund\n        route: payments-refund\n"
	m := mapperFor(t, replaceOnce(t, mockRaw(t), createMCP, createMCP+"        elicitation:\n          fields:\n"+
		"            channel:\n              type: enum\n              values: [email, sms]\n"))
	if e := m.Elicitation("create_refund"); e == nil || len(e.Fields) != 1 || m.Elicitation("get_refund") != nil {
		t.Fatalf("elicitation %+v", e)
	}
	ctx := context.Background()
	p, err := m.MCPAnswered(ctx, tc, "create_refund", []byte(refundArgs),
		domain.Values{"channel": {Type: domain.TypeEnum, Str: "sms"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p.Action.Params), `"elicitation.channel":"sms"`) {
		t.Fatalf("params %s", p.Action.Params)
	}
	plain, _ := m.MCP(ctx, tc, "create_refund", []byte(refundArgs))
	if plain.HashHex() == p.HashHex() {
		t.Fatal("the answer is not part of the action")
	}
	for name, answers := range map[string]domain.Values{
		"undeclared":   {"note": {Type: domain.TypeEnum, Str: "sms"}},
		"another type": {"channel": {Type: domain.TypeIdentifier, Str: "sms"}},
		"not a value":  {"channel": {Type: domain.TypeEnum, Str: "fax"}},
		"another tool": nil,
	} {
		tool := "create_refund"
		if name == "another tool" {
			tool, answers = "get_refund", domain.Values{"channel": {Type: domain.TypeEnum, Str: "sms"}}
		}
		args := []byte(refundArgs)
		if tool == "get_refund" {
			args = []byte(`{"refund":"re_1"}`)
		}
		if _, err := m.MCPAnswered(ctx, tc, tool, args, answers); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
