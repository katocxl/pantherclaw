// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package navigator writes a threat map as a MITRE ATT&CK Navigator layer
// (G0 M28 D720): one entry per technique and tactic, colored by status, with
// the lanes in its comment. It has no score, no gradient and no numeric
// metadata. Pure.
package navigator

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// Versions the layer is written for (D720): layer format 4.5, checked
// against ATT&CK Navigator 5.3.2 (21 April 2026, the newest release when
// this was pinned; its newest layer format is 4.5).
const (
	LayerVersion     = "4.5"
	NavigatorVersion = "5.3.2"
	// Domain is the ATT&CK Enterprise Navigator domain.
	Domain = "enterprise-attack"
)

// ErrNotAvailable: MITRE publishes no Navigator domain for the pinned ATLAS
// catalog (D720, D711a). mitre-atlas/atlas-navigator-data is deprecated and
// frozen at ATLAS 5.6.0 (domain "atlas-atlas", layer 4.3): it still lists
// ids ATLAS 2026.10 dropped (AML.T0019, AML.T0056, AML.T0057), so a layer
// of the pinned catalog would not match it.
var ErrNotAvailable = errors.New("navigator: no Navigator domain for this catalog")

// Colors of the statuses (D720, fixed).
var colors = map[domain.Status]string{
	domain.StatusEvidenced: "#2e7d32",
	domain.StatusPartial:   "#f9a825",
	domain.StatusGap:       "#c62828",
	domain.StatusOutside:   "#9e9e9e",
}

var legendLabels = map[domain.Status]string{
	domain.StatusEvidenced: "Evidenced",
	domain.StatusPartial:   "Partial",
	domain.StatusGap:       "Gap",
	domain.StatusOutside:   "Outside PantherClaw",
}

// Layer is a Navigator layer. Its fields are the only ones written.
type Layer struct {
	Name        string   `json:"name"`
	Versions    Versions `json:"versions"`
	Domain      string   `json:"domain"`
	Description string   `json:"description"`
	Techniques  []Entry  `json:"techniques"`
	LegendItems []Legend `json:"legendItems"`
	HideDisable bool     `json:"hideDisabled"`
}

// Versions are the layer's versions.
type Versions struct {
	Layer     string `json:"layer"`
	Navigator string `json:"navigator"`
	ATTACK    string `json:"attack"`
}

// Entry is one technique under one tactic.
type Entry struct {
	TechniqueID       string `json:"techniqueID"`
	Tactic            string `json:"tactic"`
	Color             string `json:"color"`
	Comment           string `json:"comment"`
	Enabled           bool   `json:"enabled"`
	ShowSubtechniques bool   `json:"showSubtechniques"`
}

// Legend is one legend row.
type Legend struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

// Comment is an entry's comment: its four lanes and its first gap's label.
func Comment(t domain.Technique) string {
	c := fmt.Sprintf("Prevent %s · Detect %s · Respond %s · Test %s", t.Prevent.State, t.Detect.State, t.Respond.State, t.Test.State)
	if len(t.Gaps) > 0 {
		c += " · " + t.Gaps[0].Fix.Label
	}
	return c
}

// Build writes m as a layer. ATLAS answers ErrNotAvailable.
func Build(m domain.Map) (Layer, error) {
	if m.Framework != catalog.FrameworkATTACK {
		return Layer{}, ErrNotAvailable
	}
	major, _, _ := strings.Cut(m.CatalogVersion, ".")
	l := Layer{
		Name:        "PantherClaw threat map",
		Versions:    Versions{Layer: LayerVersion, Navigator: NavigatorVersion, ATTACK: major},
		Domain:      Domain,
		Description: domain.Statement,
		Techniques:  []Entry{},
	}
	add := func(t domain.Technique) {
		for _, tactic := range t.Tactics {
			l.Techniques = append(l.Techniques, Entry{
				TechniqueID: t.ID, Tactic: tactic, Color: colors[t.Status], Comment: Comment(t), Enabled: true,
			})
		}
	}
	for _, t := range m.Techniques {
		add(t)
		for _, s := range t.Subtechniques {
			add(s)
		}
	}
	for _, s := range domain.Statuses() {
		l.LegendItems = append(l.LegendItems, Legend{Label: legendLabels[s], Color: colors[s]})
	}
	return l, nil
}

// JSON writes m's layer as indented JSON, and its file name.
func JSON(m domain.Map) ([]byte, string, error) {
	l, err := Build(m)
	if err != nil {
		return nil, "", err
	}
	b, err := json.Marshal(l, json.Deterministic(true))
	if err != nil {
		return nil, "", err
	}
	name := fmt.Sprintf("pantherclaw-threat-map-%s-%s.json", m.Framework, m.EvaluatedAt.UTC().Format("20060102"))
	return b, name, nil
}
