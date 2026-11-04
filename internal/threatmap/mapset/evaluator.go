// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapset

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// Inputs lists the kinds a rule reads: its on list and every sequence
// step's, sorted, each once (G0 M28 D716).
func Inputs(r *rules.Rule) []string {
	out := slices.Clone(r.On)
	if r.Sequence != nil {
		for _, s := range r.Sequence.Steps {
			out = append(out, s.On...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

var evaluators = sync.OnceValue(func() map[catalog.Framework]domain.Mapping {
	src, err := shippedSources()
	if err != nil {
		panic(fmt.Sprintf("mapset: %v", err))
	}
	s := Load()
	out := map[catalog.Framework]domain.Mapping{}
	for _, f := range catalog.Frameworks() {
		out[f] = evaluator(s, src, f)
	}
	return out
})

// Evaluator returns the mapping the evaluator reads for framework f: every
// field it reads, so a pack carries it and an offline verifier derives from
// it (G0 M28 D714c M2, D720). Each call returns a copy.
func Evaluator(f catalog.Framework) domain.Mapping {
	m := evaluators()[f]
	return clone(m)
}

func evaluator(s *Set, src sources, f catalog.Framework) domain.Mapping {
	m := domain.Mapping{
		Digest: s.Digest(), Techniques: map[string]domain.TechniqueMap{}, Controls: slices.Clone(src.prevent),
		Kinds: maps.Clone(src.kinds), Builtins: map[string]domain.BuiltinRule{}, Scenarios: map[string]domain.Scenario{},
		HubPlaybookRules: map[string][]string{},
	}
	for id, t := range s.Techniques(f) {
		m.Techniques[id] = domain.TechniqueMap{
			Prevent: t.Prevent, Rules: t.Rules, Kinds: t.Kinds, Scenarios: t.Scenarios, Campaigns: t.Campaigns,
			HubRules: t.HubRules, HubPlaybooks: t.HubPlaybooks, Outside: t.Outside, Unaddressed: t.Unaddressed,
		}
	}
	for _, r := range src.rules {
		m.Builtins[r.ID] = domain.BuiltinRule{Title: r.Title, Business: r.Edition == rules.EditionBusiness, Inputs: Inputs(r)}
	}
	for id, e := range src.scenarios {
		m.Scenarios[id] = domain.Scenario{Digest: e.Digest, Why: e.TechniqueWhy}
	}
	for _, p := range src.hub.Playbooks {
		m.HubPlaybookRules[p.Name] = slices.Clone(p.Rules)
	}
	return m
}

// clone deep-copies the parts a caller could change.
func clone(m domain.Mapping) domain.Mapping {
	out := m
	out.Techniques = make(map[string]domain.TechniqueMap, len(m.Techniques))
	for id, t := range m.Techniques {
		t.Prevent, t.Rules, t.Kinds = slices.Clone(t.Prevent), slices.Clone(t.Rules), slices.Clone(t.Kinds)
		t.Scenarios, t.Campaigns = slices.Clone(t.Scenarios), slices.Clone(t.Campaigns)
		t.HubRules, t.HubPlaybooks = slices.Clone(t.HubRules), slices.Clone(t.HubPlaybooks)
		if t.Outside != nil {
			o := *t.Outside
			t.Outside = &o
		}
		if t.Unaddressed != nil {
			u := *t.Unaddressed
			t.Unaddressed = &u
		}
		out.Techniques[id] = t
	}
	out.Controls = make([]mapping.PreventControl, len(m.Controls))
	for i, c := range m.Controls {
		c.ReasonCodes, c.OutcomeCodes, c.HR = slices.Clone(c.ReasonCodes), slices.Clone(c.OutcomeCodes), slices.Clone(c.HR)
		c.Techniques, c.Why = slices.Clone(c.Techniques), maps.Clone(c.Why)
		out.Controls[i] = c
	}
	out.Kinds = make(map[string]mapping.KindMapping, len(m.Kinds))
	for k, km := range m.Kinds {
		km.ATLAS, km.ATTACK, km.Why = slices.Clone(km.ATLAS), slices.Clone(km.ATTACK), maps.Clone(km.Why)
		out.Kinds[k] = km
	}
	out.Builtins = make(map[string]domain.BuiltinRule, len(m.Builtins))
	for id, b := range m.Builtins {
		b.Inputs = slices.Clone(b.Inputs)
		out.Builtins[id] = b
	}
	out.Scenarios = make(map[string]domain.Scenario, len(m.Scenarios))
	for id, sc := range m.Scenarios {
		sc.Why = maps.Clone(sc.Why)
		out.Scenarios[id] = sc
	}
	out.HubPlaybookRules = make(map[string][]string, len(m.HubPlaybookRules))
	for n, r := range m.HubPlaybookRules {
		out.HubPlaybookRules[n] = slices.Clone(r)
	}
	return out
}
