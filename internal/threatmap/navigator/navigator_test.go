// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package navigator_test

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
	"github.com/katocxl/pantherclaw/internal/threatmap/navigator"
)

func evaluate(f catalog.Framework) domain.Map {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	return domain.Evaluate(catalog.Load(f), mapset.Evaluator(f), domain.Inputs{Framework: f, EvaluatedAt: at})
}

// TestHR681_NavigatorLayerColorsStatusesAndHasNoScore: the ATT&CK layer is
// format 4.5 on the enterprise domain with the Statement as its
// description; one entry per technique and tactic, sub-techniques too, each
// colored by its status with its four lanes in the comment; no score,
// gradient or metadata anywhere (G0 M28 D720).
// Covers: F969, HR-681, T-305
func TestHR681_NavigatorLayerColorsStatusesAndHasNoScore(t *testing.T) {
	m := evaluate(catalog.FrameworkATTACK)
	raw, name, err := navigator.JSON(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "pantherclaw-threat-map-attack-enterprise-") {
		t.Errorf("file name %q", name)
	}
	for _, banned := range []string{`"score"`, `"gradient"`, `"metadata"`, `"maxValue"`, `"minValue"`} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("layer has %s", banned)
		}
	}
	var l navigator.Layer
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	if l.Domain != "enterprise-attack" || l.Versions.Layer != "4.5" || l.Versions.ATTACK != "20" || l.Description != domain.Statement {
		t.Errorf("layer header %+v", l)
	}
	want := 0
	colors := map[domain.Status]string{
		domain.StatusEvidenced: "#2e7d32", domain.StatusPartial: "#f9a825", domain.StatusGap: "#c62828", domain.StatusOutside: "#9e9e9e",
	}
	byKey := map[string]navigator.Entry{}
	for _, e := range l.Techniques {
		byKey[e.TechniqueID+"/"+e.Tactic] = e
	}
	check := func(tech domain.Technique) {
		for _, tactic := range tech.Tactics {
			want++
			e, ok := byKey[tech.ID+"/"+tactic]
			if !ok {
				t.Errorf("no entry for %s under %s", tech.ID, tactic)
				continue
			}
			if e.Color != colors[tech.Status] || !e.Enabled || e.ShowSubtechniques || e.Comment != navigator.Comment(tech) {
				t.Errorf("%s/%s: %+v", tech.ID, tactic, e)
			}
		}
	}
	for _, tech := range m.Techniques {
		check(tech)
		for _, s := range tech.Subtechniques {
			check(s)
		}
	}
	if len(l.Techniques) != want {
		t.Errorf("%d entries, want %d", len(l.Techniques), want)
	}
	if len(l.LegendItems) != 4 {
		t.Errorf("legend %v", l.LegendItems)
	}
}

// TestNavigatorATLASIsNotAvailable: MITRE publishes no Navigator domain for
// the pinned ATLAS catalog, so its export says so (D720, D711a).
// Covers: F969
func TestNavigatorATLASIsNotAvailable(t *testing.T) {
	if _, _, err := navigator.JSON(evaluate(catalog.FrameworkATLAS)); !errors.Is(err, navigator.ErrNotAvailable) {
		t.Fatalf("ATLAS layer: %v", err)
	}
}
