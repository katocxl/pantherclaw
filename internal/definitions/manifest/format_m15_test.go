// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// The get_refund read as a reviewed resource (G0 M15 D30): its mcp mapping
// becomes an mcp_resource mapping and its dispatch an upstream resource
// read.
const (
	getMCPMapping = "      - channel: mcp\n        tool: get_refund\n        route: payments-refund-get\n" +
		"        description: Read one refund on the simulated payments API by its id.\n"
	httpGetMapping = "      - channel: http\n        method: GET\n        path: /v1/refunds/{refund}\n        route: payments-refund-get\n" +
		"        extract:\n          target_id: path.refund\n          params: {}\n"
	getDispatch = "    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds/{target.id}\n"
	// ResourceMapping replaces the mapping up to its input schema, which
	// the test removes separately.
	resourceMapping = "      - channel: mcp_resource\n        resource: 'payments://refunds/{refund}'\n        route: payments-refund-get\n" +
		"        description: One refund on the simulated payments API.\n"
	getSchema = "        input_schema:\n          type: object\n          additionalProperties: false\n          required: [refund]\n" +
		"          properties:\n            refund:\n              type: string\n              description: The refund id\n" +
		"              pattern: '^re_[A-Za-z0-9-]{1,64}$'\n        extract:\n          target_id: input.refund\n"
	resourceExtract  = "        extract:\n          target_id: path.refund\n"
	resourceDispatch = "    dispatch:\n      mcp:\n        resource: 'payments://refunds/{target.id}'\n" +
		"        upstream_digest: sha256:" + "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f" + "\n"
)

// withResource returns the mock package with get_refund served as a
// resource.
func withResource(t *testing.T) []byte {
	t.Helper()
	raw := mutate(t, readMock(t), getMCPMapping, resourceMapping)
	raw = mutate(t, raw, getSchema, resourceExtract)
	// One operation is a tool or a resource, never both (D36).
	raw = mutate(t, raw, httpGetMapping, "")
	return mutate(t, raw, getDispatch, resourceDispatch)
}

// TestHR419_ResourcesAreReviewedReadTemplates: an mcp_resource mapping
// names an RFC 6570 level-1 template whose variables the extraction reads
// as path.<name>, on a read without side effects that a resource dispatch
// sends; the upstream template's variables are canonical references the
// gateway percent-encodes. Everything else is refused.
// Covers: F352
func TestHR419_ResourcesAreReviewedReadTemplates(t *testing.T) {
	raw := withResource(t)
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := p.Definition("payments.refund.get")
	m := d.Mappings[0]
	tmpl, ok := m.ResourceTemplate()
	if m.Channel != domain.ChannelMCPResource || !ok || tmpl.Static() || tmpl.Vars[0] != "refund" ||
		d.Dispatch.MCP.Resource != "payments://refunds/{target.id}" || d.Dispatch.MCP.Tool != "" {
		t.Fatalf("resource mapping %+v, dispatch %+v", m, d.Dispatch.MCP)
	}
	if up, ok := d.Dispatch.MCP.DispatchTemplate(); !ok || up.Vars[0] != "target.id" {
		t.Fatalf("dispatch template %+v", up)
	}

	for name, change := range map[string][2]string{
		"a level-2 variable":            {"{refund}'\n        route", "{+refund}'\n        route"},
		"an exploded variable":          {"{refund}'\n        route", "{refund*}'\n        route"},
		"a variable twice":              {"refunds/{refund}'", "refunds/{refund}/{refund}'"},
		"two adjacent variables":        {"refunds/{refund}'", "refunds/{refund}{other}'"},
		"no scheme":                     {"resource: 'payments://refunds/{refund}'", "resource: '//refunds/{refund}'"},
		"a variable in the scheme":      {"resource: 'payments://refunds/{refund}'", "resource: '{refund}://refunds'"},
		"a space":                       {"'payments://refunds/{refund}'", "'payments://re funds/{refund}'"},
		"a bad escape":                  {"'payments://refunds/{refund}'", "'payments://refunds%zz/{refund}'"},
		"a tool beside the resource":    {"      - channel: mcp_resource\n", "      - channel: mcp_resource\n        tool: get_refund\n"},
		"a resource on an mcp tool":     {"      - channel: mcp\n        tool: create_refund\n", "      - channel: mcp\n        tool: create_refund\n        resource: 'payments://x'\n"},
		"no resource dispatch":          {resourceDispatch, getDispatch},
		"arguments on a resource":       {"        resource: 'payments://refunds/{target.id}'\n", "        resource: 'payments://refunds/{target.id}'\n        arguments:\n          refund: target.id\n"},
		"a tool on a resource read":     {"        resource: 'payments://refunds/{target.id}'\n", "        resource: 'payments://refunds/{target.id}'\n        tool: get_refund\n"},
		"no upstream digest":            {"        upstream_digest: sha256:0f0f", "        x_digest: sha256:0f0f"},
		"an unknown reference":          {"refunds/{target.id}'", "refunds/{params.refund}'"},
		"an agent-chosen host":          {"'payments://refunds/{target.id}'", "'payments://{target.id}/refunds'"},
		"side effects on a resource":    {"    params: {}\n    effects:\n      - kind: none\n        description: Reads only\n", "    params: {}\n    effects:\n      - kind: none\n        description: Reads only\n    side_effects:\n      - kind: payments.note\n        description: Leaves a note\n"},
		"a resource route mapped twice": {resourceMapping + resourceExtract, resourceMapping + resourceExtract + "          params: {}\n" + strings.Replace(resourceMapping, "route: payments-refund-get", "route: payments-refund-get2", 1) + resourceExtract},
		// Two templates with the same skeleton (D44 L5).
		"the same skeleton twice": {resourceMapping + resourceExtract, resourceMapping + resourceExtract + "          params: {}\n" +
			strings.NewReplacer("{refund}", "{other}", "route: payments-refund-get", "route: payments-refund-get2").Replace(resourceMapping) +
			"        extract:\n          target_id: path.other\n"},
		// One operation is a tool or a resource, never both (D36).
		"an http mapping beside it": {resourceMapping, httpGetMapping + resourceMapping},
		"an mcp tool beside it": {resourceMapping, "      - channel: mcp\n        tool: get_refund\n        route: payments-refund-get2\n" +
			"        extract:\n          target_id: input.refund\n          params: {}\n" + resourceMapping},
	} {
		changed := strings.Replace(string(raw), change[0], change[1], 1)
		if changed == string(raw) {
			t.Fatalf("%s: %q not found", name, change[0])
		}
		if _, err := Decode([]byte(changed)); !errors.Is(err, domain.ErrInvalid) && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR419_ATemplateValueCannotChangeTheHost: a template's values are
// percent-encoded on the way out and match only unreserved characters and
// escapes on the way in, so no value adds a path segment, a query or
// another authority.
// Covers: F352
func TestHR419_ATemplateValueCannotChangeTheHost(t *testing.T) {
	tmpl, err := domain.ParseResourceTemplate("payments://refunds/{refund}/notes{suffix}")
	if err != nil {
		t.Fatal(err)
	}
	vals, ok := tmpl.Match("payments://refunds/re_1%2Fx/notes.json")
	if !ok || vals["refund"] != "re_1/x" || vals["suffix"] != ".json" {
		t.Fatalf("match = %v %v", vals, ok)
	}
	for _, uri := range []string{
		"payments://refunds/re_1/x/notes.json", "payments://refunds//notes.json", "payments://refunds/re_1/notes",
		"payments://evil/refunds/re_1/notes.json", "payments://refunds/re_1?x=1/notes.json", "payments://refunds/re_%zz/notes.j",
		"payments://refunds/re_1/notes.json#frag",
	} {
		if v, ok := tmpl.Match(uri); ok {
			t.Errorf("%s matched %v", uri, v)
		}
	}
	up, err := domain.ParseResourceTemplate("https://api.example.com/v1/{refund}")
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"re_1":                "https://api.example.com/v1/re_1",
		"../admin":            "https://api.example.com/v1/..%2Fadmin",
		"@evil.example/x?y#z": "https://api.example.com/v1/%40evil.example%2Fx%3Fy%23z",
		"é":                   "https://api.example.com/v1/%C3%A9",
	} {
		if got, ok := up.Expand(map[string]string{"refund": in}); !ok || got != want {
			t.Errorf("expand %q = %q, want %q", in, got, want)
		}
	}
	if _, ok := up.Expand(map[string]string{"refund": ""}); ok {
		t.Error("an empty value expanded")
	}
}

// createMCP is the start of create_refund's mcp mapping.
const createMCP = "      - channel: mcp\n        tool: create_refund\n        route: payments-refund\n"

// withElicitation declares elicitation fields on create_refund's mcp
// mapping.
func withElicitation(t *testing.T, fields string) []byte {
	t.Helper()
	return mutate(t, readMock(t), createMCP, createMCP+"        elicitation:\n          fields:\n"+fields)
}

const noteField = "            note:\n              type: content\n              max_length: 200\n" +
	"            approve:\n              type: boolean\n" +
	"            channel:\n              type: enum\n              values: [email, sms]\n"

// TestHR420_ElicitationFieldsBecomeMaterialParams: an mcp mapping declares
// at most 16 elicitation fields of the form's types; each becomes a
// material, optional param elicitation.<field> of the operation, which a
// decoded package validates again unchanged. Anything else is refused.
// Covers: PN-015.2
func TestHR420_ElicitationFieldsBecomeMaterialParams(t *testing.T) {
	p, err := Decode(withElicitation(t, noteField))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := p.Definition("payments.refund.create")
	for _, name := range []string{"elicitation.note", "elicitation.approve", "elicitation.channel"} {
		if s, ok := d.Params[name]; !ok || !s.Material || s.Required {
			t.Errorf("%s = %+v %v", name, s, ok)
		}
	}
	if d.Params["elicitation.note"].Type != domain.TypeContent || d.Params["elicitation.note"].MaxLength != 200 {
		t.Errorf("note %+v", d.Params["elicitation.note"])
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("a decoded package does not validate again: %v", err)
	}
	plain, _ := Decode(readMock(t))
	if pd, _ := plain.Definition("payments.refund.create"); len(pd.Params) != len(d.Params)-3 {
		t.Fatalf("params %d and %d", len(pd.Params), len(d.Params))
	}

	var many strings.Builder
	for i := range domain.MaxElicitationFields + 1 {
		fmt.Fprintf(&many, "            f%d:\n              type: boolean\n", i)
	}
	for name, fields := range map[string]string{
		"no fields":          "            {}\n",
		"too many fields":    many.String(),
		"untrusted text":     "            note:\n              type: text\n",
		"money":              "            amount:\n              type: money\n              currencies: [USD]\n",
		"a required field":   "            approve:\n              type: boolean\n              required: true\n",
		"a bad name":         "            Note:\n              type: boolean\n",
		"an invalid spec":    "            channel:\n              type: enum\n",
		"an identifier list": "            ids:\n              type: identifier_list\n              max_items: 2\n",
	} {
		raw := withElicitation(t, fields)
		if name == "no fields" {
			raw = mutate(t, readMock(t), createMCP, createMCP+"        elicitation:\n          fields: {}\n")
		}
		if _, err := Decode(raw); !errors.Is(err, domain.ErrInvalid) && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Only an mcp mapping declares elicitation, and nobody declares a
	// derived param by hand.
	httpMapping := "      - channel: http\n        method: POST\n        path: /v1/refunds\n        route: payments-refund\n"
	for name, raw := range map[string][]byte{
		"on an http mapping": mutate(t, readMock(t), httpMapping, httpMapping+"        elicitation:\n          fields:\n            approve:\n              type: boolean\n"),
		"declared by hand": mutate(t, readMock(t), "    params:\n      amount:\n",
			"    params:\n      elicitation.approve:\n        type: boolean\n        material: true\n      amount:\n"),
		// Policy reads answers as action.params.elicitation (D46).
		"a param named elicitation": mutate(t, readMock(t), "    params:\n      amount:\n",
			"    params:\n      elicitation:\n        type: boolean\n      amount:\n"),
	} {
		if _, err := Decode(raw); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR420_OnlyDerivedParamsTakeTheExtraSlots (D44 L4): a definition
// declares at most 64 params of its own; the 16 extra slots are for the
// params derived from elicitation fields.
// Covers: PN-015.2
func TestHR420_OnlyDerivedParamsTakeTheExtraSlots(t *testing.T) {
	var fields strings.Builder
	for i := range domain.MaxElicitationFields {
		fmt.Fprintf(&fields, "            f%d:\n              type: boolean\n", i)
	}
	p, err := Decode(withElicitation(t, fields.String()))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := p.Definition("payments.refund.create")
	for i := 0; len(d.Params) < 64+domain.MaxElicitationFields; i++ {
		d.Params[fmt.Sprintf("extra_%d", i)] = domain.ParamSpec{Type: domain.TypeBoolean}
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("64 authored and 16 derived params: %v", err)
	}
	d.Params["one_more"] = domain.ParamSpec{Type: domain.TypeBoolean}
	if err := p.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("65 authored params: %v", err)
	}
	// Without elicitation fields, the extra slots are not there to take.
	plain, err := Decode(readMock(t))
	if err != nil {
		t.Fatal(err)
	}
	pd, _ := plain.Definition("payments.refund.create")
	for i := 0; len(pd.Params) < 65; i++ {
		pd.Params[fmt.Sprintf("extra_%d", i)] = domain.ParamSpec{Type: domain.TypeBoolean}
	}
	if err := plain.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("65 authored params without elicitation: %v", err)
	}
}
