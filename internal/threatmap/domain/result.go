// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"time"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// Control is one mapped Prevent control as a technique page shows it.
type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Surface     string   `json:"surface"`
	HR          []string `json:"hr"`
	ReasonCodes []string `json:"reason_codes"`
	// Applies is what the control requires holding in this org.
	Applies bool   `json:"applies"`
	Why     string `json:"why,omitzero"`
}

// RouteCounts counts the in-scope routes by coverage state; Stale counts
// ENFORCED records past their freshness, which read PARTIAL.
type RouteCounts struct {
	Enforced    int `json:"enforced"`
	Partial     int `json:"partial"`
	ObserveOnly int `json:"observe_only"`
	Unknown     int `json:"unknown"`
	Stale       int `json:"stale"`
}

// Total is every route counted.
func (r RouteCounts) Total() int { return r.Enforced + r.Partial + r.ObserveOnly + r.Unknown + r.Stale }

// PreventLane is a technique's Prevent lane.
type PreventLane struct {
	State    LaneState   `json:"state"`
	Reasons  []Reason    `json:"reasons"`
	Detail   string      `json:"detail,omitzero"`
	Controls []Control   `json:"controls"`
	Routes   RouteCounts `json:"routes"`
}

// RuleRow is one rule or signal kind in a Detect lane.
type RuleRow struct {
	RuleID      string     `json:"rule_id"`
	Title       string     `json:"title"`
	Source      RuleSource `json:"source"`
	Licensed    bool       `json:"licensed"`
	Disabled    bool       `json:"disabled"`
	Suppressed  bool       `json:"suppressed"`
	LastInputAt time.Time  `json:"last_input_at,omitzero"`
	Inputs      []string   `json:"inputs"`
	// InputLive says why the input counts as live, or "" when it does not.
	InputLive Reason    `json:"input_live,omitzero"`
	State     LaneState `json:"state"`
	Reason    Reason    `json:"reason,omitzero"`
	fix       Fix
}

// DetectLane is a technique's Detect lane.
type DetectLane struct {
	State   LaneState `json:"state"`
	Reasons []Reason  `json:"reasons"`
	Detail  string    `json:"detail,omitzero"`
	Rules   []RuleRow `json:"rules"`
}

// AutomationRow is one automation or Hub playbook in a Respond lane.
type AutomationRow struct {
	ID           string    `json:"id,omitzero"`
	Name         string    `json:"name"`
	State        string    `json:"state,omitzero"`
	TriggerRules []string  `json:"trigger_rules"`
	HasContain   bool      `json:"has_contain,omitzero"`
	HubItem      string    `json:"hub_item,omitzero"`
	Lane         LaneState `json:"lane"`
	Reason       Reason    `json:"reason,omitzero"`
	fix          Fix
}

// RespondLane is a technique's Respond lane.
type RespondLane struct {
	State       LaneState       `json:"state"`
	Reasons     []Reason        `json:"reasons"`
	Detail      string          `json:"detail,omitzero"`
	Automations []AutomationRow `json:"automations"`
}

// ScenarioRow is one mapped library scenario and its newest result.
type ScenarioRow struct {
	ScenarioID string    `json:"scenario_id"`
	Title      string    `json:"title,omitzero"`
	Why        string    `json:"why,omitzero"`
	RecordedAt time.Time `json:"recorded_at,omitzero"`
	Verdict    string    `json:"verdict,omitzero"`
	ObservedBy string    `json:"observed_by,omitzero"`
	RangeID    string    `json:"range_id,omitzero"`
	State      TestState `json:"state"`
	Reason     Reason    `json:"reason,omitzero"`
}

// TestLane is a technique's Test lane.
type TestLane struct {
	State     TestState     `json:"state"`
	Reasons   []Reason      `json:"reasons"`
	Scenarios []ScenarioRow `json:"scenarios"`
}

// Seen counts what happened in the window, in scope (D713).
type Seen struct {
	AlertsRaised int64 `json:"alerts_raised"`
	Refusals     int64 `json:"refusals"`
	Holds        int64 `json:"holds"`
	WindowDays   int   `json:"window_days"`
}

// Technique is one technique's page.
type Technique struct {
	ID      string                `json:"id"`
	Name    string                `json:"name"`
	Parent  string                `json:"parent,omitzero"`
	URL     string                `json:"url"`
	Tactics []string              `json:"tactics"`
	Status  Status                `json:"status"`
	Prevent PreventLane           `json:"prevent"`
	Detect  DetectLane            `json:"detect"`
	Respond RespondLane           `json:"respond"`
	Test    TestLane              `json:"test"`
	Seen    Seen                  `json:"seen"`
	Outside *mapping.OutsideEntry `json:"outside,omitzero"`
	// UnaddressedWhy is set when PantherClaw ships no control for it yet.
	UnaddressedWhy string   `json:"unaddressed_why,omitzero"`
	Gaps           []Gap    `json:"gaps"`
	Campaigns      []string `json:"campaigns"`
	// Subtechniques are the active sub-techniques, each evaluated alone.
	Subtechniques []Technique `json:"subtechniques,omitzero"`
}

// TacticCount is one tactic column: its techniques, by name, and how many
// of them are in each status. There is no total across tactics.
type TacticCount struct {
	ID           string   `json:"id"`
	ShortName    string   `json:"short_name"`
	Name         string   `json:"name"`
	Order        int      `json:"order"`
	TechniqueIDs []string `json:"technique_ids"`
	Evidenced    int      `json:"evidenced"`
	Partial      int      `json:"partial"`
	Gap          int      `json:"gap"`
	Outside      int      `json:"outside"`
}

// Map is a whole evaluation of one framework.
type Map struct {
	Framework      catalog.Framework `json:"framework"`
	CatalogVersion string            `json:"catalog_version"`
	CatalogDigest  string            `json:"catalog_digest"`
	MappingDigest  string            `json:"mapping_digest"`
	Scope          Scope             `json:"scope"`
	EvaluatedAt    time.Time         `json:"evaluated_at"`
	Statement      string            `json:"statement"`
	OrgWide        []Lane            `json:"org_wide_lanes"`
	Tactics        []TacticCount     `json:"tactics"`
	Techniques     []Technique       `json:"techniques"`
}

// Technique finds a technique or sub-technique of the map.
func (m Map) Technique(id string) (Technique, bool) {
	for _, t := range m.Techniques {
		if t.ID == id {
			return t, true
		}
		for _, s := range t.Subtechniques {
			if s.ID == id {
				return s, true
			}
		}
	}
	return Technique{}, false
}

// Gaps lists every gap of the matrix techniques, grouped by fix target, then
// technique (D721).
func (m Map) Gaps() []Gap {
	var out []Gap
	for _, t := range m.Techniques {
		out = append(out, t.Gaps...)
	}
	sortGaps(out)
	return out
}
