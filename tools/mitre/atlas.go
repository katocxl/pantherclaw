// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//nolint:misspell // MITRE is a proper noun (the ATT&CK and ATLAS publisher) and mitre-attack its STIX source name.
package main

import (
	"regexp"
	"slices"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// atlasTopLevel is every top-level key of an ATLAS v6 file; any other key
// is a shape the generator does not know, and it stops (G0 M28 D711a).
var atlasTopLevel = []string{
	"format-version", "collection", "matrix", "tactics", "techniques",
	"mitigations", "case-studies", "entities", "software", "relationships",
}

// atlasFile is the part of an ATLAS v6 file the generator reads.
type atlasFile struct {
	FormatVersion string `yaml:"format-version"`
	Collection    struct {
		Version string `yaml:"version"`
	} `yaml:"collection"`
	Matrix struct {
		ID string `yaml:"id"`
	} `yaml:"matrix"`
	Tactics       map[string]atlasObject                `yaml:"tactics"`
	Techniques    map[string]atlasObject                `yaml:"techniques"`
	Relationships map[string]map[string][]atlasRelation `yaml:"relationships"`
}

type atlasObject struct {
	ID        string   `yaml:"id"`
	Name      string   `yaml:"name"`
	Platforms []string `yaml:"platforms"`
}

type atlasRelation struct {
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	Type     string `yaml:"relationship-type"`
	Position *int   `yaml:"position"`
}

var (
	atlasTacticID    = regexp.MustCompile(`^AML\.TA[0-9]{4}$`)
	atlasTechniqueID = regexp.MustCompile(`^AML\.T[0-9]{4}(\.[0-9]{3})?$`)
)

const atlasSite = "https://atlas.mitre.org"

// Slug is an ATLAS tactic's short name (D711a): the name in lowercase
// ASCII, each run of other characters one "-", trimmed.
func Slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
			continue
		}
		dash = true
	}
	return b.String()
}

// buildATLAS reads an ATLAS v6 file (D711a): tactics and techniques from
// the id-keyed maps, technique → tactic from relationships.<id>.achieves,
// parent from relationships.<id>.specializes, tactic order from the
// matrix's sequences positions. ATLAS v6 has no deprecated or revoked
// flags, so both are always false.
func buildATLAS(src []byte, pin Pin) (*Catalog, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, shape("the file is not one YAML mapping")
	}
	top := root.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if k := top.Content[i].Value; !slices.Contains(atlasTopLevel, k) {
			return nil, shape("unknown top-level key %q", k)
		}
	}
	var f atlasFile
	if err := top.Decode(&f); err != nil {
		return nil, err
	}
	switch {
	case !strings.HasPrefix(f.FormatVersion, "6."):
		return nil, shape("format-version %q, want 6.x", f.FormatVersion)
	case f.Collection.Version != pin.Version:
		return nil, shape("collection version %q, pinned %q", f.Collection.Version, pin.Version)
	case f.Matrix.ID == "":
		return nil, shape("the matrix has no id")
	case len(f.Tactics) == 0 || len(f.Techniques) == 0:
		return nil, shape("no tactics or no techniques")
	}
	c := &Catalog{
		Format: Format, Framework: frameworkATLAS, Version: pin.Version,
		SourceURL: pin.URL, SourceSHA256: pin.SHA256, Notice: noticeATLAS,
	}

	position := map[string]int{}
	used := map[int]bool{}
	for _, r := range f.Relationships[f.Matrix.ID]["sequences"] {
		switch {
		case r.Position == nil || *r.Position < 1 || used[*r.Position]:
			return nil, shape("matrix sequence to %s: a missing or repeated position", r.Target)
		case f.Tactics[r.Target].ID == "":
			return nil, shape("matrix sequence to %s, which is not a tactic", r.Target)
		case position[r.Target] != 0:
			return nil, shape("tactic %s is sequenced twice", r.Target)
		}
		position[r.Target] = *r.Position
		used[*r.Position] = true
	}
	shortNames := map[string]string{} // tactic id → short name
	seenShort := map[string]bool{}
	for key, t := range f.Tactics {
		sn := Slug(t.Name)
		switch {
		case key != t.ID || !atlasTacticID.MatchString(t.ID):
			return nil, shape("tactic %q: id %q", key, t.ID)
		case t.Name == "" || sn == "" || seenShort[sn]:
			return nil, shape("tactic %s: name %q gives no unique short name", t.ID, t.Name)
		case position[t.ID] == 0:
			return nil, shape("tactic %s has no position in the matrix", t.ID)
		}
		seenShort[sn] = true
		shortNames[t.ID] = sn
		c.Tactics = append(c.Tactics, Tactic{ID: t.ID, ShortName: sn, Name: t.Name, Order: position[t.ID], URL: atlasSite + "/tactics/" + t.ID})
	}
	for key, t := range f.Techniques {
		if key != t.ID || !atlasTechniqueID.MatchString(t.ID) || t.Name == "" {
			return nil, shape("technique %q: id %q, name %q", key, t.ID, t.Name)
		}
		rel := f.Relationships[t.ID]
		var tacs []string
		for _, r := range rel["achieves"] {
			sn, ok := shortNames[r.Target]
			if r.Source != t.ID || !ok {
				return nil, shape("technique %s achieves %s, which is not a tactic", t.ID, r.Target)
			}
			if !slices.Contains(tacs, sn) {
				tacs = append(tacs, sn)
			}
		}
		if len(tacs) == 0 {
			return nil, shape("technique %s has no tactic", t.ID)
		}
		slices.SortFunc(tacs, func(a, b string) int { return order(c, a) - order(c, b) })
		var parent string
		switch sp := rel["specializes"]; len(sp) {
		case 0:
		case 1:
			parent = sp[0].Target
			if sp[0].Source != t.ID || f.Techniques[parent].ID == "" {
				return nil, shape("technique %s specializes %s, which is not a technique", t.ID, parent)
			}
		default:
			return nil, shape("technique %s specializes %d techniques", t.ID, len(sp))
		}
		if want, _, sub := strings.Cut(t.ID[len("AML."):], "."); sub != (parent != "") || (sub && "AML."+want != parent) {
			return nil, shape("technique %s: parent %q disagrees with the id", t.ID, parent)
		}
		c.Techniques = append(c.Techniques, Technique{
			ID: t.ID, Name: t.Name, Tactics: tacs, Parent: parent, Platforms: nonNil(t.Platforms),
			URL: atlasSite + "/techniques/" + t.ID,
		})
	}
	return c, checkParents(c)
}

func order(c *Catalog, shortName string) int {
	for _, t := range c.Tactics {
		if t.ShortName == shortName {
			return t.Order
		}
	}
	return 0
}
