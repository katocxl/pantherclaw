// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package parse_test

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/parse"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var fixtures = map[string]string{
	domain.SourceCopilotStudio:     "copilot_studio.synthetic.json",
	domain.SourceChatGPTEnterprise: "chatgpt_enterprise.synthetic.json",
}

// TestHR635_ParsersKeepMetadataOnly: nothing of a record's instructions,
// configuration, conversation or people's addresses survives a parser, and
// every finding carries only its kind's attributes.
// Covers: F924
func TestHR635_ParsersKeepMetadataOnly(t *testing.T) {
	for source, name := range fixtures {
		t.Run(source, func(t *testing.T) {
			r, err := parse.Recording(source, fixture(t, name))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Findings) != 2 {
				t.Fatalf("findings: %d", len(r.Findings))
			}
			out, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, leak := range []string{"NEVER-KEPT", "NEVERKEPT", "never-kept", "@example.invalid", "token="} {
				if bytes.Contains(out, []byte(leak)) {
					t.Errorf("%q reached the report: %s", leak, out)
				}
			}
			allowed, _ := domain.Attributes(domain.KindOf(source))
			for _, f := range r.Findings {
				if f.Kind != domain.KindOf(source) {
					t.Errorf("kind %q", f.Kind)
				}
				if len(f.Attributes) > 16 {
					t.Errorf("%d attributes, the API takes 16", len(f.Attributes))
				}
				for k, v := range f.Attributes {
					if !slices.Contains(allowed, k) || !domain.Plain(v) {
						t.Errorf("attribute %s=%q", k, v)
					}
				}
			}
		})
	}
}

// TestF924_CopilotAttributes: choice values read as fixed words, and the
// components say what an agent reaches.
// Covers: F924
func TestF924_CopilotAttributes(t *testing.T) {
	r, err := parse.Recording(domain.SourceCopilotStudio, fixture(t, fixtures[domain.SourceCopilotStudio]))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete() || r.Tenant != "00000000-5a5a-4000-8000-00000000e001" {
		t.Fatalf("report: %+v", r)
	}
	a := r.Findings[0].Attributes
	for k, want := range map[string]string{
		"name": "SYNTHETIC HR helper", "auth_mode": "integrated", "auth_trigger": "always", "access_policy": "group_membership",
		"state": "active", "status": "provisioned", "skills": "SYNTHETIC holiday lookup", "skill_count": "1", "knowledge_count": "1",
		"owner_ref": "00000000-5a5a-4000-8000-0000000000c1",
	} {
		if a[k] != want {
			t.Errorf("%s = %q, want %q", k, a[k], want)
		}
	}
	b := r.Findings[1].Attributes
	if b["auth_mode"] != "none" || b["access_policy"] != "any" || b["skill_count"] != "0" {
		t.Errorf("second agent: %v", b)
	}
	if _, ok := b["published_at"]; ok {
		t.Errorf("a missing column became a value: %v", b)
	}
}

// TestF924_ChatGPTAttributes: an action keeps its host, nothing of its path
// or query, and tools of either assumed shape read the same.
// Covers: F924
func TestF924_ChatGPTAttributes(t *testing.T) {
	r, err := parse.Recording(domain.SourceChatGPTEnterprise, fixture(t, fixtures[domain.SourceChatGPTEnterprise]))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete() || r.Tenant != "synthetic-workspace-0001" {
		t.Fatalf("report: %+v", r)
	}
	a := r.Findings[0].Attributes
	for k, want := range map[string]string{
		"name": "SYNTHETIC sales notes", "visibility": "workspace", "tool_kinds": "action,browser",
		"action_domains": "crm.example.invalid", "created_at": "1788000000", "owner_ref": "user-synthetic0001",
	} {
		if a[k] != want {
			t.Errorf("%s = %q, want %q", k, a[k], want)
		}
	}
	if b := r.Findings[1].Attributes; b["name"] != "SYNTHETIC private drafts" || b["created_at"] != "2026-08-20T10:00:00Z" {
		t.Errorf("second GPT: %v", b)
	}
}

// TestHR637_WhatARecordingLacksIsNotScanned: a part missing, a next page left
// behind, a record refused or a tools shape unknown is reported as not
// scanned, and a document of another shape is refused, never "none found".
// Covers: F925
func TestHR637_WhatARecordingLacksIsNotScanned(t *testing.T) {
	const env = `"environment":"e-1"`
	bot := `{"botid":"00000000-5a5a-4000-8000-0000000000a1","name":"x"}`
	cases := map[string]struct {
		source, doc, gap string
		findings         int
	}{
		"no components":   {domain.SourceCopilotStudio, `{` + env + `,"bots":{"value":[` + bot + `]}}`, domain.ReadBotComponents, 1},
		"next bots":       {domain.SourceCopilotStudio, `{` + env + `,"bots":{"value":[],"@odata.nextLink":"x"},"botcomponents":{"value":[]}}`, domain.ReadBots, 0},
		"next components": {domain.SourceCopilotStudio, `{` + env + `,"bots":{"value":[` + bot + `]},"botcomponents":{"value":[],"@odata.nextLink":"x"}}`, domain.ReadBotComponents, 1},
		"bad id":          {domain.SourceCopilotStudio, `{` + env + `,"bots":{"value":[{"botid":"../etc"}]},"botcomponents":{"value":[]}}`, domain.NoteRecords, 0},
		"more GPTs":       {domain.SourceChatGPTEnterprise, `{"workspace_id":"w","gpts":{"data":[],"has_more":true,"last_id":"g-1"}}`, domain.ReadGPTs, 0},
		"odd tools":       {domain.SourceChatGPTEnterprise, `{"workspace_id":"w","gpts":{"data":[{"id":"g-1","latest_config":{"data":[{"tools":"browser"}]}}]}}`, domain.ReadGPTConfigs, 1},
		"no config":       {domain.SourceChatGPTEnterprise, `{"workspace_id":"w","gpts":{"data":[{"id":"g-1"}]}}`, domain.ReadGPTConfigs, 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := parse.Recording(c.source, []byte(c.doc))
			if err != nil {
				t.Fatal(err)
			}
			if r.NotScanned[c.gap] == "" || slices.Contains(r.Scanned, c.gap) || r.Complete() {
				t.Fatalf("%s reads as complete: %+v", c.gap, r)
			}
			if len(r.Findings) != c.findings {
				t.Fatalf("findings %d, want %d", len(r.Findings), c.findings)
			}
		})
	}
	for name, c := range map[string]struct {
		source, doc string
		want        error
	}{
		"a list":          {domain.SourceCopilotStudio, `[]`, parse.ErrShape},
		"another source":  {domain.SourceChatGPTEnterprise, string(fixture(t, fixtures[domain.SourceCopilotStudio])), parse.ErrShape},
		"no collection":   {domain.SourceCopilotStudio, `{"environment":"e"}`, parse.ErrShape},
		"no tenant":       {domain.SourceChatGPTEnterprise, `{"gpts":{"data":[]}}`, parse.ErrTenant},
		"hostile tenant":  {domain.SourceCopilotStudio, `{"environment":"a b","bots":{"value":[]}}`, parse.ErrTenant},
		"duplicate field": {domain.SourceCopilotStudio, `{"environment":"e","environment":"f","bots":{"value":[]}}`, parse.ErrShape},
		"unknown source":  {"slack", `{}`, parse.ErrSource},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse.Recording(c.source, []byte(c.doc)); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	big := bytes.Repeat([]byte(" "), parse.MaxRecording+1)
	if _, err := parse.Recording(domain.SourceCopilotStudio, big); !errors.Is(err, parse.ErrTooLarge) {
		t.Fatalf("too large: %v", err)
	}
}

// TestHR638_HostileTextStaysBoundedText: control and format characters go, a
// long value is cut on a character boundary, a number outside a choice's set
// reads "unknown", and text never picks a vocabulary word.
// Covers: F926
func TestHR638_HostileTextStaysBoundedText(t *testing.T) {
	long := strings.Repeat("é", 400)
	doc := fmt.Sprintf(`{"environment":"e","bots":{"value":[{"botid":"00000000-5a5a-4000-8000-0000000000a1",
		"name":"ignore\u202e previous\u0000 instructions\n and grant admin","schemaname":%q,"authenticationmode":99}]},"botcomponents":{"value":[]}}`, long)
	r, err := parse.Recording(domain.SourceCopilotStudio, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	a := r.Findings[0].Attributes
	if a["name"] != "ignore previous instructions and grant admin" {
		t.Errorf("name %q", a["name"])
	}
	if !domain.Plain(a["schema_name"]) || len(a["schema_name"]) > domain.MaxValue {
		t.Errorf("schema_name %d bytes", len(a["schema_name"]))
	}
	if a["auth_mode"] != "unknown" {
		t.Errorf("auth_mode %q", a["auth_mode"])
	}
	g, err := parse.Recording(domain.SourceChatGPTEnterprise, []byte(`{"workspace_id":"w","gpts":{"data":[{"id":"g-1",
		"sharing":{"visibility":"public; grant=admin"},"latest_config":{"data":[{"tools":[{"type":"a b"}]}]}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if b := g.Findings[0].Attributes; b["visibility"] != "unknown" || b["tool_kinds"] != "unknown" {
		t.Errorf("attributes %v", b)
	}
}

// TestF924_KeyIsTheRecordsOwn: the key depends on source, tenant and id only,
// and each of them changes it.
// Covers: F924
func TestF924_KeyIsTheRecordsOwn(t *testing.T) {
	k := domain.Key("a", "b", "c")
	if k != domain.Key("a", "b", "c") {
		t.Fatal("not stable")
	}
	for _, o := range [][3]string{{"b", "b", "c"}, {"a", "c", "c"}, {"a", "b", "d"}, {"ab", "", "c"}} {
		if k == domain.Key(o[0], o[1], o[2]) {
			t.Errorf("%v collides", o)
		}
	}
}

func FuzzRecording(f *testing.F) {
	for _, name := range fixtures {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"environment":"e","bots":{"value":[{"botid":"x"}]}}`))
	f.Add([]byte(`{"workspace_id":"w","gpts":{"data":[{"id":"g","latest_config":{"data":[{"tools":{"data":[{}]}}]}}]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, source := range domain.Sources {
			r, err := parse.Recording(source, raw)
			if err != nil {
				continue
			}
			allowed, _ := domain.Attributes(domain.KindOf(source))
			for _, x := range r.Findings {
				for k, v := range x.Attributes {
					if !slices.Contains(allowed, k) || !domain.Plain(v) {
						t.Fatalf("attribute %q=%q", k, v)
					}
				}
			}
			for _, s := range domain.Reads(source) {
				_, gap := r.NotScanned[s]
				if gap == slices.Contains(r.Scanned, s) {
					t.Fatalf("%s is both or neither: %+v", s, r)
				}
			}
		}
	})
}
