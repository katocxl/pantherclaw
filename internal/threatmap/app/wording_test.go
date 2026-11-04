// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
	"github.com/katocxl/pantherclaw/internal/threatmap/navigator"
)

var at = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// shippedMaps evaluates both frameworks with the shipped mapping: an org
// with nothing, and one with every edition, an active agent and rules with
// recent input.
func shippedMaps(t *testing.T) []domain.Map {
	t.Helper()
	var out []domain.Map
	for _, f := range catalog.Frameworks() {
		m := mapset.Evaluator(f)
		rich := domain.Inputs{
			Framework: f, EvaluatedAt: at, ContentMode: "WATCHING",
			Editions: domain.Editions{
				AdvancedDetections: true, CustomDetections: true, BehaviorAnalytics: true, ContentSignals: true,
				Automations: true, AutomationPlaybooks: true,
			},
			Agents: []domain.Agent{{ID: "a1", Name: "builder", Active: true, LastRealTransaction: at.Add(-time.Hour)}},
			Routes: []domain.Route{{AgentID: "a1", ConnectionID: "c1", Operation: "repo.write", State: "PARTIAL"}},
			Cursor: domain.Cursor{CaughtUp: true, AdvancedAt: at.Add(-time.Minute)},
		}
		for id := range m.Builtins {
			rich.Rules = append(rich.Rules, domain.Rule{ID: id, Source: domain.SourceBuiltin, Published: true, Disabled: len(id)%3 == 0})
		}
		for _, in := range []domain.Inputs{{Framework: f, EvaluatedAt: at}, rich} {
			out = append(out, domain.Evaluate(catalog.Load(f), m, in))
		}
	}
	return out
}

// names are every catalog technique and tactic name, longest first: MITRE's
// names are printed verbatim and stripped before a wording scan (G0 M28
// D745c(3)).
func names() []string {
	var out []string
	for _, f := range catalog.Frameworks() {
		c := catalog.Load(f)
		for _, t := range c.Techniques {
			out = append(out, t.Name)
		}
		for _, t := range c.Tactics {
			out = append(out, t.Name)
		}
	}
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// TestHR681_ShippedMapHasNoBannedWord: every string an evaluation of the
// shipped mapping yields, in its JSON and in its Navigator layer, carries
// none of the banned words once the Statement and MITRE's own names are
// removed; and no JSON key names a score (G0 M28 D717, D717a).
// Covers: F960, F962, F969, HR-681, T-305
func TestHR681_ShippedMapHasNoBannedWord(t *testing.T) {
	strip := names()
	keyRE := regexp.MustCompile(`(?i)score|percent|rating|weight|gradient`)
	for _, m := range shippedMaps(t) {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		docs := []string{string(raw)}
		if layer, _, err := navigator.JSON(m); err == nil {
			docs = append(docs, string(layer))
		}
		for _, doc := range docs {
			named := 0
			defer func() {
				if named == 0 {
					t.Errorf("%s: read no member names", m.Framework)
				}
			}()
			keys(t, doc, func(k string) {
				named++
				if keyRE.MatchString(k) {
					t.Errorf("%s: key %q", m.Framework, k)
				}
			})
			s := doc
			for _, n := range strip {
				s = strings.ReplaceAll(s, n, "")
			}
			if w := domain.BannedWord(s); w != "" {
				i := strings.Index(strings.ToLower(s), strings.ToLower(w))
				t.Errorf("%s: %q in ...%s...", m.Framework, w, s[max(0, i-80):min(len(s), i+80)])
			}
		}
	}
}

// keys calls fn with every object member name of the JSON document.
func keys(t *testing.T, doc string, fn func(string)) {
	t.Helper()
	dec := jsontext.NewDecoder(strings.NewReader(doc))
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return
		}
		// In an object, a member name is the odd-numbered token.
		if kind, n := dec.StackIndex(dec.StackDepth()); tok.Kind() == '"' && kind == '{' && n%2 == 1 {
			fn(tok.String())
		}
	}
}
