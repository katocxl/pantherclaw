// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mapset gathers every technique mapping PantherClaw declares (G0
// M28 D710, D714): the mapping tables (Prevent controls, kinds, Outside,
// Unaddressed), the built-in detection pack's rules, and the scenario and
// campaign library. It builds the set once and gives its digest, which
// threat-map packs and snapshots carry. It owns the closure test (D715).
package mapset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
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
	// Hub automation item names.
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

// Set is every declared mapping, by framework and technique id.
type Set struct {
	techniques map[catalog.Framework]map[string]TechniqueMappings
	digest     string
}

// Techniques returns a copy of a framework's mappings, by technique id.
// Ids are listed under the framework their form names (catalog.FrameworkOf);
// the closure test checks that each is in its catalog.
func (s *Set) Techniques(f catalog.Framework) map[string]TechniqueMappings {
	return maps.Clone(s.techniques[f])
}

// Digest is the hex SHA-256 of the set's RFC 8785 canonical JSON.
func (s *Set) Digest() string { return s.digest }

// Load returns the set, built once. It panics when the built-in detection
// pack does not load: the pack is embedded in the build and its own test
// proves it loads, so this means a broken build.
var Load = sync.OnceValue(func() *Set {
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		panic(fmt.Sprintf("mapset: %v", err))
	}
	p, err := pack.Load(env)
	if err != nil {
		panic(fmt.Sprintf("mapset: %v", err))
	}
	builtins := make([]*rules.Rule, 0, len(p.Rules))
	for _, c := range p.Rules {
		builtins = append(builtins, c.Rule)
	}
	s, err := build(sources{
		prevent: mapping.Prevent, kinds: mapping.Kinds, outside: mapping.Outside, unaddressed: mapping.Unaddressed,
		rules: builtins, scenarios: library.All(), campaigns: library.Campaigns(),
	})
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
}

func build(src sources) (*Set, error) {
	s := &Set{techniques: map[catalog.Framework]map[string]TechniqueMappings{}}
	for _, f := range catalog.Frameworks() {
		s.techniques[f] = map[string]TechniqueMappings{}
	}
	at := func(id string, edit func(*TechniqueMappings)) {
		f, ok := catalog.FrameworkOf(id)
		if !ok {
			return // not a technique id; the closure test names it
		}
		m := s.techniques[f][id]
		edit(&m)
		s.techniques[f][id] = m
	}
	for _, c := range src.prevent {
		for _, id := range c.Techniques {
			at(id, func(m *TechniqueMappings) { m.Prevent = append(m.Prevent, c.ID) })
		}
	}
	for k, km := range src.kinds {
		for _, id := range append(slices.Clone(km.ATLAS), km.ATTACK...) {
			at(id, func(m *TechniqueMappings) { m.Kinds = append(m.Kinds, k) })
		}
	}
	for _, r := range src.rules {
		for _, id := range append(slices.Clone(r.ATLAS), r.ATTACK...) {
			at(id, func(m *TechniqueMappings) { m.Rules = append(m.Rules, r.ID) })
		}
	}
	for sid, e := range src.scenarios {
		for _, id := range append(slices.Clone(e.ATLAS), e.ATTACK...) {
			at(id, func(m *TechniqueMappings) { m.Scenarios = append(m.Scenarios, sid) })
		}
	}
	for cid, e := range src.campaigns {
		for _, id := range append(slices.Clone(e.ATLAS), e.ATTACK...) {
			at(id, func(m *TechniqueMappings) { m.Campaigns = append(m.Campaigns, cid) })
		}
	}
	for _, o := range src.outside {
		at(o.ID, func(m *TechniqueMappings) {
			if m.Outside == nil {
				m.Outside = &o
			}
		})
	}
	for _, u := range src.unaddressed {
		at(u.ID, func(m *TechniqueMappings) {
			if m.Unaddressed == nil {
				m.Unaddressed = &u
			}
		})
	}
	for _, byID := range s.techniques {
		for id, m := range byID {
			for _, l := range []*[]string{&m.Prevent, &m.Rules, &m.Kinds, &m.Scenarios, &m.Campaigns, &m.HubRules, &m.HubPlaybooks} {
				slices.Sort(*l)
				*l = slices.Compact(*l)
			}
			byID[id] = m
		}
	}
	raw, err := json.Marshal(s.techniques, json.Deterministic(true))
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
