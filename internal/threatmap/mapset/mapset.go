// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mapset gathers every technique mapping PantherClaw declares (G0
// M28 D710, D714): the mapping tables (Prevent controls, kinds, Outside,
// Unaddressed), the built-in detection pack's rules, the scenario and
// campaign library, and the Hub's detection rules and playbooks (hub.json,
// generated from hub/items). It builds the set once and gives its digest,
// which threat-map packs and snapshots carry. It owns the closure test
// (D715).
package mapset

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"slices"
	"sync"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// TechniqueMappings is everything PantherClaw maps to one technique or
// sub-technique (D714). Lists are sorted and hold each id once.
type TechniqueMappings struct {
	// Prevent are Prevent control ids (mapping.Prevent).
	Prevent []string `json:"prevent,omitzero"`
	// Rules are built-in detection rule ids (pc.*).
	Rules []string `json:"rules,omitzero"`
	// Kinds are behavior and content signal kinds (mapping.Kinds keys).
	Kinds []string `json:"kinds,omitzero"`
	// Scenarios and Campaigns are library RT ids.
	Scenarios []string `json:"scenarios,omitzero"`
	Campaigns []string `json:"campaigns,omitzero"`
	// HubRules are Hub detection rule ids (org.hub.*); HubPlaybooks are
	// Hub automation item names whose trigger rules map the technique.
	HubRules     []string                  `json:"hub_rules,omitzero"`
	HubPlaybooks []string                  `json:"hub_playbooks,omitzero"`
	Outside      *mapping.OutsideEntry     `json:"outside,omitzero"`
	Unaddressed  *mapping.UnaddressedEntry `json:"unaddressed,omitzero"`
}

// Mapped reports whether anything but an Outside or Unaddressed entry maps
// the technique.
func (m TechniqueMappings) Mapped() bool {
	return len(m.Prevent)+len(m.Rules)+len(m.Kinds)+len(m.Scenarios)+len(m.Campaigns)+len(m.HubRules)+len(m.HubPlaybooks) > 0
}

func (m *TechniqueMappings) lists() []*[]string {
	return []*[]string{&m.Prevent, &m.Rules, &m.Kinds, &m.Scenarios, &m.Campaigns, &m.HubRules, &m.HubPlaybooks}
}

// clone deep-copies the mappings (G0 M28 D714c L5).
func (m TechniqueMappings) clone() TechniqueMappings {
	for _, l := range m.lists() {
		*l = slices.Clone(*l)
	}
	if m.Outside != nil {
		o := *m.Outside
		m.Outside = &o
	}
	if m.Unaddressed != nil {
		u := *m.Unaddressed
		m.Unaddressed = &u
	}
	return m
}

// HubRule is one Hub detection rule's techniques.
type HubRule struct {
	// ID is the rule id (org.hub.*); Item is the Hub item's name.
	ID     string   `json:"id"`
	Item   string   `json:"item"`
	ATLAS  []string `json:"atlas,omitzero"`
	ATTACK []string `json:"attack,omitzero"`
}

// HubPlaybook is one Hub automation and the rule ids its trigger names.
type HubPlaybook struct {
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

// HubTable is the golden table of the Hub's detection rules and of the
// automations a rule triggers (G0 M28 D714b), generated from hub/items by
// TestHR683_HubTableIsCurrent -update.
type HubTable struct {
	Rules     []HubRule     `json:"rules"`
	Playbooks []HubPlaybook `json:"playbooks"`
}

//go:embed hub.json
var hubRaw []byte

// Set is every declared mapping, by framework and technique id.
type Set struct {
	techniques map[catalog.Framework]map[string]TechniqueMappings
	unknown    []string
	digest     string
}

// Techniques returns a copy of a framework's mappings, by technique id.
// Ids are listed under the framework their form names (catalog.FrameworkOf);
// the closure test checks that each is in its catalog.
func (s *Set) Techniques(f catalog.Framework) map[string]TechniqueMappings {
	out := make(map[string]TechniqueMappings, len(s.techniques[f]))
	for id, m := range s.techniques[f] {
		out[id] = m.clone()
	}
	return out
}

// Unknown lists, sorted, every declared id that is no technique id of
// either framework, as "<source>: <id>", and every playbook trigger rule
// that no rule defines (G0 M28 D714a, D714c L4). The set skips them; the
// closure test fails naming them.
func (s *Set) Unknown() []string { return slices.Clone(s.unknown) }

// Digest is the hex SHA-256 of the RFC 8785 canonical JSON of the whole
// mapping document the set was built from: every Prevent control with all
// its fields, the kinds, the tags and techniques_none of every rule,
// scenario and campaign, the Hub table, Outside and Unaddressed (D714c M2).
func (s *Set) Digest() string { return s.digest }

// Load returns the set, built once. It panics when the built-in detection
// pack or the Hub table does not load: both are embedded in the build and
// their own tests prove they load, so this means a broken build.
var Load = sync.OnceValue(func() *Set {
	src, err := shippedSources()
	if err != nil {
		panic(fmt.Sprintf("mapset: %v", err))
	}
	s, err := build(src)
	if err != nil {
		panic(fmt.Sprintf("mapset: %v", err))
	}
	return s
})

// sources is what a Set is built from.
type sources struct {
	prevent     []mapping.PreventControl
	kinds       map[string]mapping.KindMapping
	outside     []mapping.OutsideEntry
	unaddressed []mapping.UnaddressedEntry
	rules       []*rules.Rule
	scenarios   map[string]library.Entry
	campaigns   map[string]library.CampaignEntry
	hub         HubTable
}

// shippedSources gathers what this build ships; Load and the closure test
// read the same sources.
func shippedSources() (sources, error) {
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		return sources{}, err
	}
	p, err := pack.Load(env)
	if err != nil {
		return sources{}, err
	}
	builtins := make([]*rules.Rule, 0, len(p.Rules))
	for _, c := range p.Rules {
		builtins = append(builtins, c.Rule)
	}
	var hub HubTable
	if err := json.Unmarshal(hubRaw, &hub, json.RejectUnknownMembers(true)); err != nil {
		return sources{}, fmt.Errorf("hub.json: %w", err)
	}
	return sources{
		prevent: mapping.Prevent, kinds: mapping.Kinds, outside: mapping.Outside, unaddressed: mapping.Unaddressed,
		rules: builtins, scenarios: library.All(), campaigns: library.Campaigns(), hub: hub,
	}, nil
}

// document is the digested form of the sources (D714c M2).
type document struct {
	Prevent     []mapping.PreventControl       `json:"prevent"`
	Kinds       map[string]mapping.KindMapping `json:"kinds"`
	Outside     []mapping.OutsideEntry         `json:"outside"`
	Unaddressed []mapping.UnaddressedEntry     `json:"unaddressed"`
	Rules       map[string]tags                `json:"rules"`
	Scenarios   map[string]tags                `json:"scenarios"`
	Campaigns   map[string]tags                `json:"campaigns"`
	Hub         HubTable                       `json:"hub"`
}

// tags are one rule's, scenario's or campaign's techniques.
type tags struct {
	ATLAS          []string          `json:"atlas,omitzero"`
	ATTACK         []string          `json:"attack,omitzero"`
	Why            map[string]string `json:"why,omitzero"`
	TechniquesNone string            `json:"techniques_none,omitzero"`
}

func (src sources) document() document {
	d := document{
		Prevent: src.prevent, Kinds: src.kinds, Outside: src.outside, Unaddressed: src.unaddressed, Hub: src.hub,
		Rules: map[string]tags{}, Scenarios: map[string]tags{}, Campaigns: map[string]tags{},
	}
	for _, r := range src.rules {
		d.Rules[r.ID] = tags{ATLAS: r.ATLAS, ATTACK: r.ATTACK, TechniquesNone: r.TechniquesNone}
	}
	for id, e := range src.scenarios {
		d.Scenarios[id] = tags{ATLAS: e.ATLAS, ATTACK: e.ATTACK, Why: e.TechniqueWhy, TechniquesNone: e.TechniquesNone}
	}
	for id, e := range src.campaigns {
		d.Campaigns[id] = tags{ATLAS: e.ATLAS, ATTACK: e.ATTACK, Why: e.TechniqueWhy, TechniquesNone: e.TechniquesNone}
	}
	return d
}

func joined(atlas, attack []string) []string { return append(slices.Clone(atlas), attack...) }

func build(src sources) (*Set, error) {
	s := &Set{techniques: map[catalog.Framework]map[string]TechniqueMappings{}}
	for _, f := range catalog.Frameworks() {
		s.techniques[f] = map[string]TechniqueMappings{}
	}
	at := func(source, id string, edit func(*TechniqueMappings)) {
		f, ok := catalog.FrameworkOf(id)
		if !ok {
			s.unknown = append(s.unknown, source+": "+id)
			return
		}
		m := s.techniques[f][id]
		edit(&m)
		s.techniques[f][id] = m
	}
	for _, c := range src.prevent {
		for _, id := range c.Techniques {
			at(c.ID, id, func(m *TechniqueMappings) { m.Prevent = append(m.Prevent, c.ID) })
		}
	}
	for k, km := range src.kinds {
		for _, id := range joined(km.ATLAS, km.ATTACK) {
			at(k, id, func(m *TechniqueMappings) { m.Kinds = append(m.Kinds, k) })
		}
	}
	byRule := map[string][]string{} // rule id → its techniques, for playbooks
	for _, r := range src.rules {
		byRule[r.ID] = joined(r.ATLAS, r.ATTACK)
		for _, id := range byRule[r.ID] {
			at(r.ID, id, func(m *TechniqueMappings) { m.Rules = append(m.Rules, r.ID) })
		}
	}
	for sid, e := range src.scenarios {
		for _, id := range joined(e.ATLAS, e.ATTACK) {
			at(sid, id, func(m *TechniqueMappings) { m.Scenarios = append(m.Scenarios, sid) })
		}
	}
	for cid, e := range src.campaigns {
		for _, id := range joined(e.ATLAS, e.ATTACK) {
			at(cid, id, func(m *TechniqueMappings) { m.Campaigns = append(m.Campaigns, cid) })
		}
	}
	for _, r := range src.hub.Rules {
		byRule[r.ID] = joined(r.ATLAS, r.ATTACK)
		for _, id := range byRule[r.ID] {
			at(r.ID, id, func(m *TechniqueMappings) { m.HubRules = append(m.HubRules, r.ID) })
		}
	}
	for _, p := range src.hub.Playbooks {
		for _, rule := range p.Rules {
			techniques, ok := byRule[rule]
			if !ok {
				s.unknown = append(s.unknown, p.Name+": trigger rule "+rule)
				continue
			}
			for _, id := range techniques {
				at(p.Name, id, func(m *TechniqueMappings) { m.HubPlaybooks = append(m.HubPlaybooks, p.Name) })
			}
		}
	}
	for _, o := range src.outside {
		at("outside", o.ID, func(m *TechniqueMappings) {
			if m.Outside == nil {
				m.Outside = &o
			}
		})
	}
	for _, u := range src.unaddressed {
		at("unaddressed", u.ID, func(m *TechniqueMappings) {
			if m.Unaddressed == nil {
				m.Unaddressed = &u
			}
		})
	}
	for _, byID := range s.techniques {
		for id, m := range byID {
			for _, l := range m.lists() {
				slices.Sort(*l)
				*l = slices.Compact(*l)
			}
			byID[id] = m
		}
	}
	slices.Sort(s.unknown)
	s.unknown = slices.Compact(s.unknown)
	raw, err := json.Marshal(src.document(), json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(v)
	s.digest = hex.EncodeToString(sum[:])
	return s, nil
}
