// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
)

// ledgerKind finds an audit entry's ledger kind, "audit." and a dotted
// kind, in content; the next byte tells a prefix ("audit.grant.*") from a
// whole kind.
var ledgerKind = regexp.MustCompile(`audit\.([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)(.?)`)

// contentAllowed are audit.<kind> strings in content that name no kind the
// core writes, keyed "<path>|<kind>", each with why.
var contentAllowed = map[string]string{
	"internal/detection/pack/builtin/integrity_action_tampered.yaml|security.evidence_integrity_reset":           noFireEvent,
	"internal/detection/pack/builtin/integrity_effect_without_receipt.yaml|security.evidence_integrity_reset":    noFireEvent,
	"internal/detection/pack/builtin/integrity_evidence_integrity_failed.yaml|security.evidence_integrity_reset": noFireEvent,
}

// noFireEvent: a rule test event the rule must not fire on. Its kind is the
// name of a notification type, not of an audit entry, and is used only as
// "something else".
const noFireEvent = "a no-fire test event named after a notification type"

// TestHR664_ContentNamesKnownKinds reads the content that names audit
// kinds by text: the built-in detection rules, the Hub items, the SIEM
// integration's samples and rules, and the SQL queries. Every audit.<kind>
// there must be "audit." and a kind of auditkind.All(), and every prefix
// (followed by ".", "*" or "%") must start some kind, so a misspelt kind
// can't make a rule or a query miss the entries it is for (HR-664, T-286).
func TestHR664_ContentNamesKnownKinds(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	kinds := auditkind.All()
	known := map[string]bool{}
	for _, k := range kinds {
		known[k] = true
	}
	used := map[string]bool{}
	seen := 0
	check := func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for _, m := range ledgerKind.FindAllStringSubmatch(string(raw), -1) {
			kind, next := m[1], m[2]
			seen++
			ok := known[kind]
			if next == "." || next == "*" || next == "%" {
				ok = slices.ContainsFunc(kinds, func(k string) bool { return strings.HasPrefix(k, kind) })
			}
			if ok {
				continue
			}
			if _, allow := contentAllowed[rel+"|"+kind]; allow {
				used[rel+"|"+kind] = true
				continue
			}
			t.Errorf("%s: audit.%s names no audit kind the core writes (HR-664)", rel, kind)
		}
	}
	walk := func(dir string, keep func(string) bool) {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && keep(path) {
				check(path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	ext := func(exts ...string) func(string) bool {
		return func(p string) bool {
			for _, e := range exts {
				if strings.HasSuffix(p, e) {
					return true
				}
			}
			return false
		}
	}
	walk("internal/detection/pack/builtin", ext(".yaml"))
	walk("hub/items", func(p string) bool { return filepath.Base(p) == "item.yaml" })
	walk("integrations/siem", func(p string) bool {
		return !strings.HasSuffix(p, ".md") && filepath.Base(p) != "LICENSE" && filepath.Base(p) != "NOTICE"
	})
	walk("queries", ext(".sql"))
	if seen < 30 {
		t.Errorf("saw %d audit kinds in content, want at least 30: the walk is broken", seen)
	}
	for key := range contentAllowed {
		if !used[key] {
			t.Errorf("contentAllowed entry %q matches nothing; remove it", key)
		}
	}
}
