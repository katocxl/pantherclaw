// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"context"
	"errors"
	"strings"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcjira "github.com/katocxl/pantherclaw/packages/pc-jira"
)

var m20tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func jiraBuild(t *testing.T, pkg *defs.Package, tool, args string) Request {
	t.Helper()
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.MCP(context.Background(), m20tc, tool, []byte(args))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := pkg.Definition(p.Action.Operation)
	r, err := Build("https://acme.atlassian.example.test", d, p.Action, txn)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestHR526_AJSONBodyIsNestedExactlyAsThePackageSays: bracket keys in a
// JSON body build nested objects, exactly and deterministically, and a flat
// key stays flat (G0 M20 D260).
//
// Covers: F756
func TestHR526_AJSONBodyIsNestedExactlyAsThePackageSays(t *testing.T) {
	pkg, err := manifest.Decode(pcjira.Package)
	if err != nil {
		t.Fatal(err)
	}
	r := jiraBuild(t, pkg, "jira_create_issue", `{"project_key":"ENG","summary":"Retries","description":"Fix them","issue_type":"Task"}`)
	want := `{"fields":{"description":"Fix them","issuetype":{"name":"Task"},"project":{"key":"ENG"},"summary":"Retries"}}`
	if string(r.Body) != want || r.ContentType != JSONContentType || r.URL.Path != "/rest/api/2/issue" {
		t.Fatalf("create: %s %s %s", r.URL, r.ContentType, r.Body)
	}
	// An absent optional param leaves its key out, never an empty object.
	r = jiraBuild(t, pkg, "jira_create_issue", `{"project_key":"ENG","summary":"Retries","issue_type":"Task"}`)
	if string(r.Body) != `{"fields":{"issuetype":{"name":"Task"},"project":{"key":"ENG"},"summary":"Retries"}}` {
		t.Fatalf("create without a description: %s", r.Body)
	}
	if r = jiraBuild(t, pkg, "jira_transition_issue", `{"issue_key":"ENG-1","transition_id":"31"}`); string(r.Body) != `{"transition":{"id":"31"}}` {
		t.Fatalf("transition: %s", r.Body)
	}
	if r = jiraBuild(t, pkg, "jira_add_comment", `{"issue_key":"ENG-1","body":"Done"}`); string(r.Body) != `{"body":"Done"}` {
		t.Fatalf("flat comment: %s", r.Body)
	}
}

// TestHR526_AnAgentArgumentNeverAddsABodyKey: what an agent sends is a
// value, never a key: brackets, quotes and nested input fields the mapping
// does not extract reach Jira as part of a string or not at all (G0 M20
// D260, HR-526).
//
// Covers: F756
func TestHR526_AnAgentArgumentNeverAddsABodyKey(t *testing.T) {
	pkg, err := manifest.Decode(pcjira.Package)
	if err != nil {
		t.Fatal(err)
	}
	r := jiraBuild(t, pkg, "jira_create_issue",
		`{"project_key":"ENG","summary":"x\",\"reporter\":{\"id\":\"1\"}","description":"fields[assignee][id]","issue_type":"Task"}`)
	want := `{"fields":{"description":"fields[assignee][id]","issuetype":{"name":"Task"},"project":{"key":"ENG"},` +
		`"summary":"x\",\"reporter\":{\"id\":\"1\"}"}}`
	if string(r.Body) != want {
		t.Fatalf("built %s", r.Body)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.HTTPRequest(context.Background(), m20tc, "POST", "/rest/api/2/issue", "", "application/json",
		[]byte(`{"fields":{"project":{"key":"ENG"},"summary":"S","issuetype":{"name":"Task"},"assignee":{"id":"1"},"security":{"id":"2"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := pkg.Definition("jira.issue.create")
	b, err := Build("https://acme.atlassian.example.test", d, p.Action, txn)
	if err != nil || string(b.Body) != `{"fields":{"issuetype":{"name":"Task"},"project":{"key":"ENG"},"summary":"S"}}` {
		t.Fatalf("built %s %v", b.Body, err)
	}
}

// boolPackage is a minimal package whose JSON body carries the boolean
// literals and a string param.
const boolPackage = `format: 1
name: test.bools
version: 1.0.0
publisher: pantherclaw
summary: Boolean literals
definitions:
  - operation: test.thing.post
    summary: Post a thing
    access: write
    target:
      type: test_thing
      id_pattern: '^[a-z]{1,10}$'
      account: none
    params:
      label:
        type: identifier
        material: true
        required: true
        pattern: '^[a-z]{1,10}$'
    effects:
      - kind: thing.post
        description: Posts
    reversibility: irreversible
    dedupe_key: [target.id, params.label]
    approval:
      title: Post thing {target.id}
      fields:
        - target.id
    retry:
      safe: false
      on_unknown: reconcile
    assurance:
      basis: documented
      reviewed_by: [pantherclaw-maintainers]
      valid_until: 2027-10-30
    mappings:
      - channel: mcp
        tool: post_thing
        route: test-thing-post
        extract:
          target_id: input.id
          params:
            label: input.label
    dispatch:
      http:
        method: POST
        path: /things/{target.id}
        body:
          isGroup: bool.true
          channelData[notify][silent]: bool.false
          legacy: literal.true
          label: params.label
          kind: literal.thing
`

// TestHR526_JSONBooleansComeOnlyFromThePackage: bool.true and bool.false
// are JSON booleans in a JSON body; literal.true stays the text "true", so
// no signed package changes meaning; an agent's "true" is still the string
// it sent; and a form body refuses a boolean (G0 M20 D263, D272).
//
// Covers: F756
func TestHR526_JSONBooleansComeOnlyFromThePackage(t *testing.T) {
	pkg, err := manifest.Decode([]byte(boolPackage))
	if err != nil {
		t.Fatal(err)
	}
	r := jiraBuild(t, pkg, "post_thing", `{"id":"abc","label":"true"}`)
	if want := `{"channelData":{"notify":{"silent":false}},"isGroup":true,"kind":"thing","label":"true","legacy":"true"}`; string(r.Body) != want {
		t.Fatalf("built %s", r.Body)
	}
	asForm := func(raw string) string {
		return strings.Replace(raw, "      http:\n        method: POST\n", "      http:\n        method: POST\n        encoding: form\n", 1)
	}
	if _, err := manifest.Decode([]byte(asForm(boolPackage))); !errors.Is(err, defs.ErrInvalid) {
		t.Fatalf("a boolean in a form body: %v", err)
	}
	// A form body keeps literals as the text it sends (G0 M14 D52).
	form, err := manifest.Decode([]byte(asForm(strings.NewReplacer(
		"          isGroup: bool.true\n", "", "          channelData[notify][silent]: bool.false\n", "").Replace(boolPackage))))
	if err != nil {
		t.Fatal(err)
	}
	if r = jiraBuild(t, form, "post_thing", `{"id":"abc","label":"x"}`); string(r.Body) != "kind=thing&label=x&legacy=true" {
		t.Fatalf("form %s", r.Body)
	}
}

// TestHR526_NestingRefusesWhatIsNotOneDocument: the builder checks the keys
// again and refuses a list, a value that is also a parent, or a key outside
// the grammar, so nothing is sent (G0 M20 D260).
//
// Covers: F756
func TestHR526_NestingRefusesWhatIsNotOneDocument(t *testing.T) {
	for name, obj := range map[string]map[string]any{
		"list":             {"a[]": "x"},
		"value and parent": {"a": "x", "a[b]": "y"},
		"digits":           {"a[0]": "x"},
		"too deep":         {"a[b][c][d]": "x"},
		"unpaired":         {"a[b": "x"},
	} {
		if _, err := nestJSON(obj); !errors.Is(err, ErrBuild) {
			t.Errorf("%s: %v", name, err)
		}
	}
	got, err := nestJSON(map[string]any{"a": "x", "b[c]": true, "b[d][e]": "y"})
	if err != nil || got["a"] != "x" || got["b"].(map[string]any)["c"] != true ||
		got["b"].(map[string]any)["d"].(map[string]any)["e"] != "y" {
		t.Fatalf("nested %v %v", got, err)
	}
}
