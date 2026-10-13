// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"
)

// mergeAll adds what init adds to a document: the hook, a deny rule and a
// governed server at the top level (as in ~/.claude.json for the user
// scope), each only when it is missing, as init does.
func mergeAll(doc, hook, entry *jsonNode) error {
	if !hookRuns(doc) {
		if err := addHook(doc, hook); err != nil {
			return err
		}
	}
	if err := addDeny(doc, denyRule("docs")); err != nil {
		return err
	}
	servers, ok := doc.object("mcpServers")
	if !ok {
		return errReplace
	}
	return addServer(servers, governedPrefix+"docs", entry)
}

// keeps reports whether after keeps everything in before: each member,
// with a value that keeps the old one, and each list's old items first
// and unchanged.
func keeps(after, before any) bool {
	switch b := before.(type) {
	case map[string]any:
		a, ok := after.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range b {
			if av, ok := a[k]; !ok || !keeps(av, v) {
				return false
			}
		}
		return true
	case []any:
		a, ok := after.([]any)
		return ok && len(a) >= len(b) && reflect.DeepEqual(a[:len(b)], b)
	default:
		return reflect.DeepEqual(after, before)
	}
}

// strings collects every member name and string value.
func stringsOf(v any, into map[string]bool) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			into[k] = true
			stringsOf(x, into)
		}
	case []any:
		for _, x := range v {
			stringsOf(x, into)
		}
	case string:
		into[v] = true
	}
}

// FuzzSettingsMerge (HR-208): for any document init can parse, its
// additions keep every existing member, list item and value; they add
// only the strings init writes (no secret can come from anywhere else);
// and merging the result again changes nothing.
func FuzzSettingsMerge(f *testing.F) {
	for _, seed := range []string{
		existingLocal, `{}`, `{"hooks": {"PreToolUse": []}}`, `{"permissions": {"deny": ["mcp__docs__*"]}}`,
		`{"permissions": {"deny": "mcp__docs"}}`, `{"hooks": []}`, `{"mcpServers": {"pantherclaw-docs": {"command": "other"}}}`,
		`{"mcpServers": {"docs": {"command": "npx", "env": {"TOKEN": "` + "ghp_" + strings.Repeat("a1", 18) + `"}}}}`,
		`{"a": [1, 2.50, -0, 1e3, true, null, "\u00e9"], "permissions": {"allow": ["Bash(*)"]}}`,
	} {
		f.Add([]byte(seed))
	}
	fl := initFlags{gateway: "https://gw.example.test", connection: "shell", keyFile: "workload.json"}
	hook, err := fl.hookEntry()
	if err != nil {
		f.Fatal(err)
	}
	entry := jsonFields("type", "stdio", "command", "pclaw", "args", fl.proxyArgs("docs-sdk", "/k/workload.json"))
	var added map[string]bool
	{
		doc := &jsonNode{kind: '{'}
		if err := mergeAll(doc, hook, entry); err != nil {
			f.Fatal(err)
		}
		b, _ := doc.encode()
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			f.Fatal(err)
		}
		added = map[string]bool{}
		stringsOf(v, added)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		doc, err := parseJSONDoc(raw)
		if err != nil {
			return
		}
		var before any = map[string]any{} // an empty file is an empty object
		if len(bytes.TrimSpace(raw)) != 0 {
			if err := json.Unmarshal(raw, &before); err != nil {
				t.Fatalf("init parsed what encoding/json refuses: %v", err)
			}
		}
		if mergeAll(doc, hook, entry) != nil {
			return // init refuses and writes nothing
		}
		out, err := doc.encode()
		if err != nil {
			t.Fatal(err)
		}
		out = likeOriginal(raw, out)
		var after any
		if err := json.Unmarshal(out, &after); err != nil {
			t.Fatalf("init wrote JSON it cannot read: %v\n%s", err, out)
		}
		if !keeps(after, before) {
			t.Fatalf("lost or changed something:\n%s\n%s", raw, out)
		}
		old, now := map[string]bool{}, map[string]bool{}
		stringsOf(before, old)
		stringsOf(after, now)
		for s := range now {
			if !old[s] && !added[s] {
				t.Fatalf("wrote %q, which is neither the document's nor init's", s)
			}
		}
		again, err := parseJSONDoc(out)
		if err != nil {
			t.Fatal(err)
		}
		if err := mergeAll(again, hook, entry); err != nil {
			t.Fatal(err)
		}
		twice, _ := again.encode()
		if twice = likeOriginal(out, twice); !bytes.Equal(twice, out) {
			t.Fatalf("a second merge changed the document:\n%s\n%s", out, twice)
		}
	})
}
