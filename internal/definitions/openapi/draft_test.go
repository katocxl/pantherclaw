// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package openapi

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
)

// readSpec is a small OpenAPI 3.1 document with reads only: a path
// parameter (the target), an enum and an integer in the query.
const readSpec = `{
  "openapi": "3.1.0",
  "servers": [{"url": "https://api.acme.test/v1"}],
  "paths": {
    "/widgets/{widgetId}": {
      "get": {
        "operationId": "getWidget",
        "summary": "Read a widget",
        "parameters": [
          {"name": "widgetId", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^w-[0-9]{1,8}$"}},
          {"name": "view", "in": "query", "schema": {"type": "string", "enum": ["basic", "full"]}},
          {"name": "depth", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 3}}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

// writeSpec adds a write whose name reads like a read, with a header
// parameter and a composed body property the importer must not guess.
const writeSpec = `
openapi: 3.0.3
paths:
  /widgets/{widgetId}/get:
    post:
      operationId: getWidgetSafely
      parameters:
        - {name: widgetId, in: path, required: true, schema: {type: string}}
        - {name: X-Trace, in: header, schema: {type: string}}
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Body'
      responses: {'200': {description: ok}}
components:
  schemas:
    Body:
      type: object
      properties:
        color: {type: string, enum: [red, blue]}
        tags: {type: array, items: {type: string}, maxItems: 4}
        shape: {oneOf: [{type: string}, {type: integer}]}
`

func draft(t *testing.T, spec, name string) ([]byte, error) {
	t.Helper()
	s, err := Parse([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	return Draft(s, DraftOptions{Name: name, Version: "0.1.0", Source: "spec.json", Now: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)})
}

// reviewed removes the draft's review_required block, as the person who
// reviewed it does.
func reviewed(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out []string
	skipping := false
	for line := range strings.Lines(string(raw)) {
		switch {
		case strings.HasPrefix(line, "review_required:"):
			skipping = true
			continue
		case skipping && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "-")):
			continue
		}
		skipping = false
		out = append(out, line)
	}
	return []byte(strings.Join(out, ""))
}

// TestHR720_ADraftNeverLoadsUntilAPersonRemovesReviewRequired: the draft's
// first key is review_required and the decoder refuses it
// (DRAFT_NOT_REVIEWED); once a person removes it, the reviewed package
// decodes, its reads mapped from the spec.
//
// Covers: HR-720
func TestHR720_ADraftNeverLoadsUntilAPersonRemovesReviewRequired(t *testing.T) {
	raw, err := draft(t, readSpec, "acme.widgets")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimLeft(stripComments(raw), "\n"), "review_required:") {
		t.Fatalf("review_required is not the first key:\n%s", raw)
	}
	if _, err := manifest.Decode(raw); !errors.Is(err, manifest.ErrDraftNotReviewed) || !strings.Contains(err.Error(), "DRAFT_NOT_REVIEWED") {
		t.Fatalf("a draft decoded: %v", err)
	}
	p, err := manifest.Decode(reviewed(t, raw))
	if err != nil {
		t.Fatalf("the reviewed draft: %v\n%s", err, reviewed(t, raw))
	}
	d := p.Definitions[0]
	if d.Operation != "acme.widgets.get_widget" || d.Access != domain.AccessRead || d.Params["view"].Type != domain.TypeEnum ||
		d.Params["depth"].Type != domain.TypeInteger || d.Target.IDPattern != "^w-[0-9]{1,8}$" {
		t.Fatalf("drafted %+v", d)
	}
}

// A reviewed drafted write decodes: it is irreversible, never retried and
// reconciles an unknown outcome, as M4 requires of every irreversible
// operation (HR-720, HR-007, G0 M31 D1208).
func TestHR720_AReviewedDraftedWriteDecodes(t *testing.T) {
	raw, err := draft(t, writeSpec, "acme.widgets")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Decode(raw); !errors.Is(err, manifest.ErrDraftNotReviewed) {
		t.Fatalf("a draft decoded: %v", err)
	}
	p, err := manifest.Decode(reviewed(t, raw))
	if err != nil {
		t.Fatalf("the reviewed write: %v\n%s", err, reviewed(t, raw))
	}
	d, ok := p.Definition("acme.widgets.get_widget_safely")
	if !ok || d.Access != domain.AccessWrite || d.Reversibility != domain.Irreversible || d.Retry.Safe ||
		d.Retry.OnUnknown != domain.OnUnknownReconcile || len(d.Dedupe) == 0 || len(d.Approval.Fields) == 0 {
		t.Fatalf("drafted %+v", d)
	}
}

// stripComments drops the draft's leading comment lines.
func stripComments(raw []byte) string {
	var out []string
	for line := range strings.Lines(string(raw)) {
		if !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "")
}

// TestHR720_TheImporterRefusesWhatItCannotReadSafely: Swagger 2, another
// OpenAPI version, an external $ref and a $ref chain deeper than 16 fail
// the import; a pc. name is refused.
//
// Covers: HR-720
func TestHR720_TheImporterRefusesWhatItCannotReadSafely(t *testing.T) {
	if _, err := Parse([]byte(`{"swagger": "2.0", "paths": {}}`)); !errors.Is(err, ErrSwagger) {
		t.Errorf("swagger 2: %v", err)
	}
	if _, err := Parse([]byte(`{"openapi": "2.9.0", "paths": {}}`)); !errors.Is(err, ErrSpec) {
		t.Errorf("version: %v", err)
	}
	ext := strings.Replace(writeSpec, "'#/components/schemas/Body'", "'https://attacker.example/body.json'", 1)
	if _, err := Parse([]byte(ext)); !errors.Is(err, ErrExternalRef) {
		t.Errorf("external ref: %v", err)
	}
	var chain strings.Builder
	chain.WriteString("openapi: 3.0.3\npaths:\n  /w:\n    post:\n      operationId: w\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/S0'}\n      responses: {'200': {description: ok}}\ncomponents:\n  schemas:\n")
	for i := range 20 {
		chain.WriteString("    S" + itoa(i) + ": {$ref: '#/components/schemas/S" + itoa(i+1) + "'}\n")
	}
	chain.WriteString("    S20: {type: object}\n")
	if _, err := Parse([]byte(chain.String())); !errors.Is(err, ErrRefDepth) {
		t.Errorf("deep refs: %v", err)
	}
	if _, err := draft(t, readSpec, "pc.widgets"); !errors.Is(err, ErrDraft) {
		t.Errorf("a pc. name: %v", err)
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// TestT330_ASpecCannotSteerTheImporter: a POST whose name reads like a read
// is drafted as an irreversible write, never retried, approved over every
// param and deduplicated on its material params; the header parameter and
// the composed property are left out with a review comment, not guessed.
//
// Covers: T-330
func TestT330_ASpecCannotSteerTheImporter(t *testing.T) {
	raw, err := draft(t, writeSpec, "acme.widgets")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"operation: acme.widgets.get_widget_safely",
		"access: write",
		"reversibility: irreversible",
		"safe: false",
		"approval:",
		"dedupe_key:",
		"basis: declared",
		"# review: left out header",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the draft lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "shape") || !strings.Contains(s, "review") {
		t.Errorf("the composed property is not left for review:\n%s", s)
	}
	if strings.Contains(s, "X-Trace:") || strings.Contains(s, "x_trace:") {
		t.Errorf("the header parameter was mapped:\n%s", s)
	}
	for _, f := range []string{"params.color", "params.tags"} {
		if strings.Count(s, f) < 2 {
			t.Errorf("%s is not both approved and deduplicated:\n%s", f, s)
		}
	}
	if _, err := manifest.Decode(raw); !errors.Is(err, manifest.ErrDraftNotReviewed) {
		t.Fatalf("the draft decoded: %v", err)
	}
}
