// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

const pcShellFile = "../../../packages/pc-shell/package.yaml"

// TestHR124_PcShellGolden pins the reviewed meaning of pc.shell, the
// package the Claude Code hook maps through.
func TestHR124_PcShellGolden(t *testing.T) {
	raw, err := os.ReadFile(pcShellFile)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pc-shell.canonical.json", append(canon, '\n'))
	var digests strings.Builder
	for _, d := range p.Definitions {
		fmt.Fprintf(&digests, "%s %s\n", d.Operation, d.Digest)
	}
	golden(t, "pc-shell.digests", []byte(digests.String()))
	d := p.Definitions[0]
	// G0 M30 D943 adds agent_config.write, the protected-config write route.
	if p.Name != "pc.shell" || len(p.Definitions) != 2 || d.Operation != "shell.command.run" || d.Dispatch != nil ||
		p.Definitions[1].Operation != "agent_config.write" || p.Definitions[1].Dispatch != nil ||
		d.Params["command"].Type != domain.TypeCommand || d.Params["cwd"].Type != domain.TypePath ||
		d.Mappings[0].Channel != domain.ChannelHook {
		t.Fatalf("decoded %+v", p)
	}
}

// TestHR075_TheDispatchTemplateIsPartOfTheDigest: what the gateway sends is
// reviewed with the rest of the definition.
func TestHR075_TheDispatchTemplateIsPartOfTheDigest(t *testing.T) {
	raw := readMock(t)
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := p.Definitions[0].Dispatch.HTTP
	if h == nil || h.Method != http.MethodPost || h.Path != "/v1/refunds" || h.Body["amount"] != "params.amount.value" ||
		h.IdempotencyHeader != "Idempotency-Key" {
		t.Fatalf("dispatch %+v", p.Definitions[0].Dispatch)
	}
	for _, change := range [][2]string{
		{"charge: target.id", "charge_id: target.id"},
		{"idempotency_header: Idempotency-Key", "idempotency_header: X-Request-Key"},
		{"description: The charge to refund", "description: The charge to refund now"},
	} {
		q, err := Decode(mutate(t, raw, change[0], change[1]))
		if err != nil {
			t.Fatalf("%s: %v", change[1], err)
		}
		if q.Definitions[0].Digest == p.Definitions[0].Digest {
			t.Errorf("changing %q left the digest unchanged", change[0])
		}
	}
}

func mutate(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	if !strings.Contains(string(raw), from) {
		t.Fatalf("the package has no %q", from)
	}
	return []byte(strings.Replace(string(raw), from, to, 1))
}

// TestHR075_DispatchTemplatesReadOnlyCanonicalFields: templates reference
// only the target and declared params, never untrusted text; a money param
// splits into value and currency; a path segment takes only identifiers,
// enums and integers; reserved headers are refused; and target
// idempotency needs its header.
func TestHR075_DispatchTemplatesReadOnlyCanonicalFields(t *testing.T) {
	raw := readMock(t)
	for name, change := range map[string][2]string{
		"undeclared param":         {"reason: params.reason", "reason: params.note"},
		"raw input":                {"charge: target.id", "charge: input.charge"},
		"money as one field":       {"amount: params.amount.value", "amount: params.amount"},
		"money part":               {"amount: params.amount.value", "amount: params.amount.cents"},
		"part on a scalar":         {"reason: params.reason", "reason: params.reason.value"},
		"no account on the target": {"charge: target.id", "charge: target.account"},
		"bad field name":           {"charge: target.id", "charge-id: target.id"},
		"reserved header":          {"idempotency_header: Idempotency-Key", "idempotency_header: Authorization"},
		"credential-carrying":      {"idempotency_header: Idempotency-Key", "idempotency_header: Cookie"},
		"no idempotency header":    {"        idempotency_header: Idempotency-Key\n", ""},
		"money in a path":          {"path: /v1/refunds\n        body:", "path: /v1/refunds/{params.amount.value}\n        body:"},
		"dot segment":              {"path: /v1/refunds/{target.id}", "path: /v1/../refunds/{target.id}"},
		"partial segment":          {"path: /v1/refunds/{target.id}", "path: /v1/refunds/re-{target.id}"},
		"query in a path":          {"path: /v1/refunds/{target.id}", "path: /v1/refunds/{target.id}?x=1"},
		"a GET with a body":        {"path: /v1/refunds/{target.id}", "path: /v1/refunds/{target.id}\n        body:\n          id: target.id"},
		"both http and mcp": {
			"        idempotency_header: Idempotency-Key\n",
			"        idempotency_header: Idempotency-Key\n      mcp:\n        tool: refund\n        upstream_digest: sha256:" + strings.Repeat("a", 64) + "\n",
		},
	} {
		if _, err := Decode(mutate(t, raw, change[0], change[1])); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR082_UpstreamToolsCarryTheReviewedDigest: an MCP dispatch names the
// upstream tool and the digest of the definition that was reviewed.
func TestHR082_UpstreamToolsCarryTheReviewedDigest(t *testing.T) {
	raw := readMock(t)
	const getDispatch = "    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds/{target.id}\n"
	mcp := func(digest string) string {
		return "    dispatch:\n      mcp:\n        tool: get_refund\n        arguments:\n          refund: target.id\n" +
			"        upstream_digest: " + digest + "\n"
	}
	p, err := Decode(mutate(t, raw, getDispatch, mcp("sha256:"+strings.Repeat("0f", 32))))
	if err != nil {
		t.Fatal(err)
	}
	if m := p.Definitions[1].Dispatch.MCP; m == nil || m.Tool != "get_refund" || m.Arguments["refund"] != "target.id" {
		t.Fatalf("mcp dispatch %+v", p.Definitions[1].Dispatch)
	}
	for _, digest := range []string{"''", "sha256:" + strings.Repeat("0F", 32), "sha512:" + strings.Repeat("0f", 32), strings.Repeat("0f", 32)} {
		if _, err := Decode(mutate(t, raw, getDispatch, mcp(digest))); err == nil {
			t.Errorf("digest %q: accepted", digest)
		}
	}
	noDigest := strings.Replace(mcp("x"), "        upstream_digest: x\n", "", 1)
	if _, err := Decode(mutate(t, raw, getDispatch, noDigest)); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("no digest: %v", err)
	}
}

// TestHR081_InputSchemasAreAClosedSubset: MCP clients receive only reviewed
// schemas: closed objects, strings with anchored patterns or enums,
// integers, booleans and bounded arrays; no $ref, composition or unknown
// keyword; descriptions and schemas only on mcp mappings.
func TestHR081_InputSchemasAreAClosedSubset(t *testing.T) {
	raw := readMock(t)
	const reason = "            reason:\n              type: string\n              enum: [duplicate, fraudulent, requested_by_customer]\n"
	ok := map[string]string{
		"integer":       "            reason:\n              type: integer\n              minimum: 1\n              maximum: 3\n",
		"boolean":       "            reason:\n              type: boolean\n",
		"bounded array": "            reason:\n              type: array\n              maxItems: 3\n              items:\n                type: string\n",
		"nested object": "            reason:\n              type: object\n              additionalProperties: false\n              properties:\n                code:\n                  type: string\n",
	}
	for name, schema := range ok {
		if _, err := Decode(mutate(t, raw, reason, schema)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]string{
		"$ref":              "            reason:\n              $ref: '#/defs/reason'\n",
		"oneOf":             "            reason:\n              type: string\n              oneOf: []\n",
		"format":            "            reason:\n              type: string\n              format: email\n",
		"number":            "            reason:\n              type: number\n",
		"unanchored":        "            reason:\n              type: string\n              pattern: 'dup.*'\n",
		"bad pattern":       "            reason:\n              type: string\n              pattern: '^(dup$'\n",
		"enum on integer":   "            reason:\n              type: integer\n              enum: ['1']\n",
		"open object":       "            reason:\n              type: object\n              properties:\n                code:\n                  type: string\n",
		"array without max": "            reason:\n              type: array\n              items:\n                type: string\n",
		"repeated enum":     "            reason:\n              type: string\n              enum: [a, a]\n",
		"bidi description":  "            reason:\n              type: string\n              description: \"a\\u202eb\"\n",
		"min above max":     "            reason:\n              type: integer\n              minimum: 3\n              maximum: 1\n",
	}
	for name, schema := range bad {
		if _, err := Decode(mutate(t, raw, reason, schema)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, change := range map[string][2]string{
		"required but not a property": {"required: [charge, amount, currency, reason]", "required: [charge, amount, currency, reason, note]"},
		"root not an object":          {"        input_schema:\n          type: object\n          additionalProperties: false\n          required: [refund]", "        input_schema:\n          type: string\n          additionalProperties: false\n          required: [refund]"},
		"description on http": {
			"        route: payments-refund\n        extract:",
			"        route: payments-refund\n        description: Refund\n        extract:",
		},
	} {
		if _, err := Decode(mutate(t, raw, change[0], change[1])); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR080_ReviewedSchemasDeclareParameterHeaders: a reviewed input
// schema may name the Mcp-Param-* header MCP clients mirror an argument
// into (x-mcp-header), on a string, integer or boolean property reached
// through properties only; the declaration is what clients receive and
// part of the digest. Anything else is refused when the package decodes.
func TestHR080_ReviewedSchemasDeclareParameterHeaders(t *testing.T) {
	raw := readMock(t)
	const reason = "            reason:\n              type: string\n              enum: [duplicate, fraudulent, requested_by_customer]\n"
	const currency = "            currency:\n              type: string\n              enum: [USD, EUR]\n"
	header := "            reason:\n              type: string\n              x-mcp-header: Reason\n              enum: [duplicate, fraudulent, requested_by_customer]\n"
	p, err := Decode(mutate(t, raw, reason, header))
	if err != nil {
		t.Fatal(err)
	}
	def, _ := p.Definition("payments.refund.create")
	if s := def.Mappings[1].InputSchema.Properties["reason"]; s.Header != "Reason" {
		t.Fatalf("decoded %+v", s)
	}
	plain, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if plainDef, _ := plain.Definition("payments.refund.create"); plainDef.Digest == def.Digest {
		t.Fatal("the declaration is not part of the definition's digest")
	}
	for name, schema := range map[string]string{
		"integer":         "            reason:\n              type: integer\n              x-mcp-header: Count\n",
		"boolean":         "            reason:\n              type: boolean\n              x-mcp-header: Urgent\n",
		"nested property": "            reason:\n              type: object\n              additionalProperties: false\n              properties:\n                code:\n                  type: string\n                  x-mcp-header: Code\n",
	} {
		if _, err := Decode(mutate(t, raw, reason, schema)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, schema := range map[string]string{
		"inside items":   "            reason:\n              type: array\n              maxItems: 3\n              items:\n                type: string\n                x-mcp-header: Reason\n",
		"on an object":   "            reason:\n              type: object\n              additionalProperties: false\n              x-mcp-header: Reason\n              properties:\n                code:\n                  type: string\n",
		"on an array":    "            reason:\n              type: array\n              maxItems: 3\n              x-mcp-header: Reason\n              items:\n                type: string\n",
		"not a name":     "            reason:\n              type: string\n              x-mcp-header: 'Re ason'\n",
		"underscore":     "            reason:\n              type: string\n              x-mcp-header: Re_ason\n",
		"leading hyphen": "            reason:\n              type: string\n              x-mcp-header: -Reason\n",
		"too long":       "            reason:\n              type: string\n              x-mcp-header: R" + strings.Repeat("e", 64) + "\n",
		"not a string":   "            reason:\n              type: string\n              x-mcp-header: [Reason]\n",
		"twice ignoring case": "            reason:\n              type: string\n              x-mcp-header: CURRENCY\n" +
			"            note:\n              type: string\n              x-mcp-header: currency\n",
	} {
		if _, err := Decode(mutate(t, raw, reason, schema)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	root := mutate(t, raw, "        input_schema:\n          type: object\n          additionalProperties: false\n          required: [refund]",
		"        input_schema:\n          type: object\n          x-mcp-header: Refund\n          additionalProperties: false\n          required: [refund]")
	if _, err := Decode(root); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("on the root: %v", err)
	}
	if _, err := Decode(mutate(t, mutate(t, raw, reason, "            reason:\n              type: string\n              x-mcp-header: Currency\n"),
		currency, "            currency:\n              type: string\n              x-mcp-header: currency\n")); err == nil {
		t.Error("two properties with one header name: accepted")
	}
}
