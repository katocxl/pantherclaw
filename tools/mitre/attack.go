// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//nolint:misspell // MITRE is a proper noun (the ATT&CK and ATLAS publisher) and mitre-attack its STIX source name.
package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"regexp"
	"slices"
	"strings"
)

// stixBundle is the part of an ATT&CK STIX 2.1 bundle the generator reads.
type stixBundle struct {
	Type    string           `json:"type"`
	Objects []jsontext.Value `json:"objects"`
}

type stixRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url"`
}

type stixPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// stixObject holds the fields read from any object; the rest (descriptions,
// detections, …) are never decoded.
type stixObject struct {
	Type            string      `json:"type"`
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	ExternalRefs    []stixRef   `json:"external_references"`
	KillChainPhases []stixPhase `json:"kill_chain_phases"`
	TacticRefs      []string    `json:"tactic_refs"`
	ShortName       string      `json:"x_mitre_shortname"`
	IsSubtechnique  bool        `json:"x_mitre_is_subtechnique"`
	Platforms       []string    `json:"x_mitre_platforms"`
	Deprecated      bool        `json:"x_mitre_deprecated"`
	Revoked         bool        `json:"revoked"`
	Domains         []string    `json:"x_mitre_domains"`
	MitreVersion    string      `json:"x_mitre_version"`
}

var (
	attackTacticID    = regexp.MustCompile(`^TA[0-9]{4}$`)
	attackTechniqueID = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	attackShortName   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

// mitreRef returns the object's single mitre-attack external reference.
func mitreRef(o *stixObject) (stixRef, bool) {
	var out []stixRef
	for _, r := range o.ExternalRefs {
		if r.SourceName == "mitre-attack" {
			out = append(out, r)
		}
	}
	if len(out) != 1 {
		return stixRef{}, false
	}
	return out[0], true
}

// buildATTACK reads the Enterprise matrix (tactic order), its tactics and
// every attack-pattern (G0 M28 D711).
func buildATTACK(src []byte, pin Pin) (*Catalog, error) {
	var b stixBundle
	if err := json.Unmarshal(src, &b); err != nil {
		return nil, err
	}
	if b.Type != "bundle" {
		return nil, shape("type %q, want bundle", b.Type)
	}
	var matrices, collections []stixObject
	tactics := map[string]stixObject{} // by STIX id
	var patterns []stixObject
	for _, raw := range b.Objects {
		var o stixObject
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		switch o.Type {
		case "x-mitre-collection":
			collections = append(collections, o)
		case "x-mitre-matrix":
			matrices = append(matrices, o)
		case "x-mitre-tactic":
			tactics[o.ID] = o
		case "attack-pattern":
			patterns = append(patterns, o)
		}
		switch o.Type {
		case "x-mitre-matrix", "x-mitre-tactic", "attack-pattern":
			if !slices.Contains(o.Domains, "enterprise-attack") {
				return nil, shape("%s %s is not in the enterprise-attack domain", o.Type, o.ID)
			}
		}
	}
	if len(collections) != 1 || collections[0].MitreVersion != pin.Version {
		return nil, shape("the bundle must hold one x-mitre-collection of version %q", pin.Version)
	}
	if len(matrices) != 1 {
		return nil, shape("%d matrices, want 1", len(matrices))
	}
	c := &Catalog{
		Format: Format, Framework: frameworkATTACK, Version: pin.Version,
		SourceURL: pin.URL, SourceSHA256: pin.SHA256, Notice: noticeATTACK,
	}
	order := map[string]int{} // short name → order
	for i, ref := range matrices[0].TacticRefs {
		t, ok := tactics[ref]
		if !ok {
			return nil, shape("matrix names tactic %s, which the bundle lacks", ref)
		}
		r, ok := mitreRef(&t)
		switch {
		case !ok || !attackTacticID.MatchString(r.ExternalID):
			return nil, shape("tactic %s: no mitre-attack TA#### id", ref)
		case !attackShortName.MatchString(t.ShortName) || order[t.ShortName] != 0:
			return nil, shape("tactic %s: short name %q", r.ExternalID, t.ShortName)
		case t.Name == "" || !strings.HasPrefix(r.URL, "https://"):
			return nil, shape("tactic %s: name or url missing", r.ExternalID)
		}
		order[t.ShortName] = i + 1
		c.Tactics = append(c.Tactics, Tactic{ID: r.ExternalID, ShortName: t.ShortName, Name: t.Name, Order: i + 1, URL: r.URL})
	}
	if len(c.Tactics) == 0 {
		return nil, shape("the matrix lists no tactic")
	}
	seen := map[string]bool{}
	for i := range patterns {
		p := &patterns[i]
		r, ok := mitreRef(p)
		if !ok || !attackTechniqueID.MatchString(r.ExternalID) {
			return nil, shape("attack-pattern %s: no mitre-attack T#### id", p.ID)
		}
		id := r.ExternalID
		if seen[id] {
			return nil, shape("technique %s appears twice", id)
		}
		seen[id] = true
		var tacs []string
		for _, ph := range p.KillChainPhases {
			if ph.KillChainName != "mitre-attack" {
				continue
			}
			if order[ph.PhaseName] == 0 {
				return nil, shape("technique %s: tactic %q is not in the matrix", id, ph.PhaseName)
			}
			if !slices.Contains(tacs, ph.PhaseName) {
				tacs = append(tacs, ph.PhaseName)
			}
		}
		slices.SortFunc(tacs, func(a, b string) int { return order[a] - order[b] })
		active := !p.Deprecated && !p.Revoked
		var parent string
		if dot := strings.IndexByte(id, '.'); dot > 0 {
			parent = id[:dot]
		}
		switch {
		case p.Name == "" || !strings.HasPrefix(r.URL, "https://"):
			return nil, shape("technique %s: name or url missing", id)
		case active && len(tacs) == 0:
			return nil, shape("technique %s: no tactic", id)
		case p.IsSubtechnique != (parent != ""):
			return nil, shape("technique %s: x_mitre_is_subtechnique disagrees with the id", id)
		}
		c.Techniques = append(c.Techniques, Technique{
			ID: id, Name: p.Name, Tactics: nonNil(tacs), Parent: parent, Platforms: nonNil(p.Platforms),
			Deprecated: p.Deprecated, Revoked: p.Revoked, URL: r.URL,
		})
	}
	return c, checkParents(c)
}

// checkParents requires every sub-technique's parent in the catalog.
func checkParents(c *Catalog) error {
	ids := map[string]bool{}
	for _, t := range c.Techniques {
		ids[t.ID] = true
	}
	for _, t := range c.Techniques {
		if t.Parent != "" && !ids[t.Parent] {
			return shape("technique %s: parent %s is not in the catalog", t.ID, t.Parent)
		}
	}
	return nil
}
