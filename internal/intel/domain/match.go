// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "slices"

// Mode is what an org does with a match (FQ38-2).
type Mode string

// Modes. No settings row is ModeOff.
const (
	ModeOff       Mode = "OFF"
	ModeHold      Mode = "HOLD"
	ModeAlertOnly Mode = "ALERT_ONLY"
)

// Valid reports whether m is a mode.
func (m Mode) Valid() bool { return m == ModeOff || m == ModeHold || m == ModeAlertOnly }

// Consumes reports whether the org matches in this mode.
func (m Mode) Consumes() bool { return m == ModeHold || m == ModeAlertOnly }

// Hit is one indicator something matched.
type Hit struct {
	ID       string
	Kind     Kind
	Severity Severity
}

// shingled is an injection_text indicator as the set matches it.
type shingled struct {
	hit  Hit
	need int
}

// Set is the current indicators, indexed for matching.
type Set struct {
	byHash    map[string][]Hit
	byShingle map[string][]int
	shingled  []shingled
}

// NewSet indexes indicators.
func NewSet(in []Indicator) *Set {
	s := &Set{byHash: map[string][]Hit{}, byShingle: map[string][]int{}}
	for _, x := range in {
		h := Hit{ID: x.ID, Kind: x.Kind, Severity: x.Severity}
		if x.Kind != KindInjectionText {
			s.byHash[string(x.Kind)+":"+x.SHA256] = append(s.byHash[string(x.Kind)+":"+x.SHA256], h)
			continue
		}
		i := len(s.shingled)
		sh := slices.Clone(x.Shingles)
		slices.Sort(sh)
		sh = slices.Compact(sh)
		s.shingled = append(s.shingled, shingled{hit: h, need: Needed(len(sh))})
		for _, v := range sh {
			s.byShingle[v] = append(s.byShingle[v], i)
		}
	}
	return s
}

// Empty reports whether the set holds nothing.
func (s *Set) Empty() bool { return s == nil || (len(s.byHash) == 0 && len(s.shingled) == 0) }

// Hashes are the hits of kind k among hashes.
func (s *Set) Hashes(k Kind, hashes ...string) []Hit {
	if s == nil {
		return nil
	}
	var out []Hit
	for _, h := range hashes {
		if h != "" {
			out = append(out, s.byHash[string(k)+":"+h]...)
		}
	}
	return compact(out)
}

// Server are the mcp_server hits of a server's reported name and version,
// its package reference and version, and its image digest; empty ones are
// skipped.
func (s *Set) Server(name, version, pkg, pkgVersion, image string) []Hit {
	return s.Hashes(KindMCPServer, ServerHash(name, version), PackageHash(pkg, pkgVersion), ImageHash(image))
}

// Description are the tool_description hits of a tool description.
func (s *Set) Description(text string) []Hit {
	return s.Hashes(KindToolDescription, DescriptionHash(text))
}

// Text are the injection_text hits of the given shingles of a text: each
// indicator whose shingles the text holds at least min(3, n) of.
func (s *Set) Text(shingles []string) []Hit {
	if s == nil || len(s.shingled) == 0 {
		return nil
	}
	count := map[int]int{}
	for _, v := range shingles {
		for _, i := range s.byShingle[v] {
			count[i]++
		}
	}
	var out []Hit
	for i, n := range count {
		if n >= s.shingled[i].need {
			out = append(out, s.shingled[i].hit)
		}
	}
	return compact(out)
}

// ShingleHashes are every injection_text shingle in the set, for a gateway.
func (s *Set) ShingleHashes() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.byShingle))
	for v := range s.byShingle {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

func compact(in []Hit) []Hit {
	slices.SortFunc(in, func(a, b Hit) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	return slices.CompactFunc(in, func(a, b Hit) bool { return a.ID == b.ID })
}
