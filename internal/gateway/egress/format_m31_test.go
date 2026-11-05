// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/mail"
	"strings"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcgmail "github.com/katocxl/pantherclaw/packages/pc-gmail"
	pclinear "github.com/katocxl/pantherclaw/packages/pc-linear"
	pcm365 "github.com/katocxl/pantherclaw/packages/pc-m365"
	pcnotion "github.com/katocxl/pantherclaw/packages/pc-notion"
)

const (
	linearTeam = "9a1b0000-0000-4000-8000-000000000001"
	m365User   = "5a1e0000-0000-4000-8000-0000000000aa"
	mailbox    = "synthetic.user@example.test"
)

// m31Build maps an MCP call of the package's tool and builds its request;
// a mapping or build refusal is returned.
func m31Build(t *testing.T, raw []byte, tool, args string) (Request, *defs.Definition, error) {
	t.Helper()
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.MCP(context.Background(), m20tc, tool, []byte(args))
	if err != nil {
		return Request{}, nil, err
	}
	d, _ := pkg.Definition(p.Action.Operation)
	r, err := Build("https://api.example.test", d, p.Action, txn)
	return r, d, err
}

// TestHR723_AGraphQLDispatchSendsThePackagesDocument: a Linear issue is
// created with the package's fixed mutation and the body mapping as its
// variables; a [*] key builds one recipient object per address; index keys
// build arrays in order; and fixed headers are the package's literals.
//
// Covers: HR-723
func TestHR723_AGraphQLDispatchSendsThePackagesDocument(t *testing.T) {
	r, d, err := m31Build(t, pclinear.Package, "linear_create_issue", `{"team_id":"`+linearTeam+`","title":"Retries","description":"Fix them"}`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatal(err)
	}
	in, _ := got.Variables["input"].(map[string]any)
	if got.Query != d.Dispatch.HTTP.GraphQL.Document || in["teamId"] != linearTeam || in["title"] != "Retries" || r.URL.Path != "/graphql" {
		t.Fatalf("built %s", r.Body)
	}
	r, _, err = m31Build(t, pcm365.Package, "m365_send_mail", `{"user_id":"`+m365User+`","to":["a@example.test","b@example.test"],"subject":"Hi","text":"Hello"}`)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"message":{"body":{"content":"Hello","contentType":"Text"},"subject":"Hi","toRecipients":[{"emailAddress":{"address":"a@example.test"}},{"emailAddress":{"address":"b@example.test"}}]}}`
	if string(r.Body) != want {
		t.Fatalf("built %s", r.Body)
	}
	r, _, err = m31Build(t, pcnotion.Package, "notion_create_page", `{"parent_page_id":"2b1c0000000040008000000000000001","title":"Notes","text":"Body"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r.Body), `"children":[{"object":"block","paragraph":{"rich_text":[{"text":{"content":"Body"},"type":"text"}]},"type":"paragraph"}]`) ||
		r.Headers["Notion-Version"] != "2022-06-28" {
		t.Fatalf("built %s %v", r.Body, r.Headers)
	}
}

// TestHR723_TheAgentNeverWritesBodyStructureOrADocument: a package whose
// document is a subscription, whose [*] key maps anything but an
// identifier list, whose indices leave a gap or whose fixed header is
// Authorization is refused; at build time a [*] list over 64 items and an
// index gap left by an absent value build nothing.
//
// Covers: HR-723
func TestHR723_TheAgentNeverWritesBodyStructureOrADocument(t *testing.T) {
	raw := string(pclinear.Package)
	const doc = "mutation IssueCreate($input: IssueCreateInput!)"
	if !strings.Contains(raw, doc) {
		t.Fatal("fixture moved")
	}
	for name, mut := range map[string][2]string{
		"subscription":  {doc, "subscription IssueCreate($input: IssueCreateInput!)"},
		"each a text":   {"          input[title]: params.title\n", "          input[title][*][x]: params.title\n"},
		"index gap":     {"          input[title]: params.title\n", "          input[title]: params.title\n          input[labels][1]: params.title\n"},
		"authorization": {"        path: /graphql\n        graphql:\n          document: >-\n            mutation IssueCreate", "        path: /graphql\n        headers:\n          Authorization: x\n        graphql:\n          document: >-\n            mutation IssueCreate"},
	} {
		if !strings.Contains(raw, mut[0]) {
			t.Fatalf("%s: fixture moved", name)
		}
		if _, err := manifest.Decode([]byte(strings.Replace(raw, mut[0], mut[1], 1))); !errors.Is(err, defs.ErrInvalid) && !errors.Is(err, manifest.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	long := make([]string, defs.MaxEachItems+1)
	for i := range long {
		long[i] = "a@example.test"
	}
	if _, err := nestJSONBody(map[string]any{"to[*][address]": long}); !errors.Is(err, ErrBuild) {
		t.Errorf("65 items: %v", err)
	}
	if _, err := nestJSONBody(map[string]any{"roles[1]": "write"}); !errors.Is(err, ErrBuild) {
		t.Errorf("a gap: %v", err)
	}
}

// TestHR724_AMailMessageIsBuiltFromTheMappedFieldsOnly: Gmail's message has
// the mapped To, Cc and Subject headers and a base64 text/plain body.
//
// Covers: HR-724
func TestHR724_AMailMessageIsBuiltFromTheMappedFieldsOnly(t *testing.T) {
	r, _, err := m31Build(t, pcgmail.Package, "gmail_send_message",
		`{"mailbox":"`+mailbox+`","to":["a@example.test"],"cc":["b@example.test"],"subject":"Ré: retries","text":"Fixed.\nBcc: c@example.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(r.Body, &body); err != nil {
		t.Fatal(err)
	}
	b, err := base64.URLEncoding.DecodeString(body.Raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mail.ReadMessage(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("To") != "a@example.test" || m.Header.Get("Cc") != "b@example.test" || m.Header.Get("Bcc") != "" ||
		m.Header.Get("Content-Type") != "text/plain; charset=utf-8" || r.URL.Path != "/gmail/v1/users/me/messages/send" {
		t.Fatalf("message %v at %s", m.Header, r.URL.Path)
	}
	text, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(readAll(t, m), "\r\n", ""))
	if string(text) != "Fixed.\nBcc: c@example.test" {
		t.Fatalf("text %q", text)
	}
}

// TestHR724_AHeaderLineBreakOrSeparatorIsRefusedTwice: a line break in the
// subject or a separator in an address is refused when the params are
// decoded (PARAM_INVALID) and again by the builder, so nothing is sent.
//
// Covers: HR-724
func TestHR724_AHeaderLineBreakOrSeparatorIsRefusedTwice(t *testing.T) {
	pkg, err := manifest.Decode(pcgmail.Package)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := pkg.Definition("gmail.message.send")
	for name, vals := range map[string]defs.Values{
		"subject CRLF": {"to": {List: []string{"a@example.test"}}, "subject": {Str: "Hi\r\nBcc: c@example.test"}},
		"subject LF":   {"to": {List: []string{"a@example.test"}}, "subject": {Str: "Hi\nBcc: c@example.test"}},
		"address list": {"to": {List: []string{"a@example.test,c@example.test"}}, "subject": {Str: "Hi"}},
		"address CR":   {"to": {List: []string{"a@example.test\rBcc: c@example.test"}}, "subject": {Str: "Hi"}},
	} {
		if err := d.CheckMailHeaders(vals); err == nil || !strings.Contains(err.Error(), "PARAM_INVALID") {
			t.Errorf("%s: decided: %v", name, err)
		}
		obj := map[string]any{"to": vals["to"].List, "subject": vals["subject"].Str, "text": "x"}
		if _, err := mailBody(obj); !errors.Is(err, ErrBuild) {
			t.Errorf("%s: built: %v", name, err)
		}
	}
	if err := d.CheckMailHeaders(defs.Values{"to": {List: []string{"a@example.test"}}, "subject": {Str: "Hi"}}); err != nil {
		t.Fatalf("a plain message: %v", err)
	}
}

// TestT333_AnAgentCannotSendItsOwnGraphQLOperation: an argument the tool
// does not declare (a query of the agent's) is refused by the mapping, and
// text that reads like GraphQL stays a variable: the document sent is the
// package's.
//
// Covers: T-333
func TestT333_AnAgentCannotSendItsOwnGraphQLOperation(t *testing.T) {
	if _, _, err := m31Build(t, pclinear.Package, "linear_create_issue",
		`{"team_id":"`+linearTeam+`","title":"x","query":"mutation { teamDelete(id: \"`+linearTeam+`\") { success } }"}`); err == nil {
		t.Fatal("an undeclared query argument was mapped")
	}
	evil := `x\" } } mutation { teamDelete(id: \"` + linearTeam + `\") { success } } #`
	r, d, err := m31Build(t, pclinear.Package, "linear_create_issue", `{"team_id":"`+linearTeam+`","title":"`+evil+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(r.Body, &got); err != nil || got.Query != d.Dispatch.HTTP.GraphQL.Document || strings.Contains(got.Query, "teamDelete") {
		t.Fatalf("sent %s", r.Body)
	}
}

func readAll(t *testing.T, m *mail.Message) string {
	t.Helper()
	var b strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := m.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}
