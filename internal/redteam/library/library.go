// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package library is the PantherClaw scenario library as the server knows
// it (G0 M17 D125, HR-467): each shipped redteam/scenarios file's id, digest
// and tier, embedded in the build. A range accepts an RT scenario only when
// its declared digest is the library's, and takes its tier from here, never
// from the runner. library.json is generated from redteam/scenarios
// (`task range:library`); a test fails when the two differ.
package library

import (
	_ "embed"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
)

// Entry is one library scenario.
type Entry struct {
	Digest string `json:"digest"`
	Tier   string `json:"tier"`
	// ASI are the OWASP agentic risks the scenario exercises (G0 M25 D304).
	ASI []string `json:"asi,omitzero"`
	// ASIWhy says, per tag, how the scenario exercises that risk (D531).
	ASIWhy map[string]string `json:"asi_why,omitzero"`
	// ATLAS and ATTACK are the MITRE techniques the scenario tests, with one
	// line each in TechniqueWhy (G0 M28 D714).
	ATLAS        []string          `json:"atlas,omitzero"`
	ATTACK       []string          `json:"attack,omitzero"`
	TechniqueWhy map[string]string `json:"technique_why,omitzero"`
}

//go:embed library.json
var raw []byte

var entries = func() map[string]Entry {
	var m map[string]Entry
	if err := json.Unmarshal(raw, &m, json.RejectUnknownMembers(true)); err != nil {
		panic(fmt.Sprintf("library.json: %v", err))
	}
	return m
}()

// CampaignEntry is one library campaign (G0 M25 D310): its digest, and the
// attempts the server derives outcomes for, never the runner's.
type CampaignEntry struct {
	Digest   string           `json:"digest"`
	Tier     string           `json:"tier"`
	Attempts []domain.Attempt `json:"attempts"`
	// ASI are the OWASP agentic risks the campaign file tags (D529).
	ASI []string `json:"asi,omitzero"`
	// ATLAS and ATTACK are the MITRE techniques the campaign file tags, with
	// one line each in TechniqueWhy (G0 M28 D714); labels, never evidence.
	ATLAS        []string          `json:"atlas,omitzero"`
	ATTACK       []string          `json:"attack,omitzero"`
	TechniqueWhy map[string]string `json:"technique_why,omitzero"`
}

//go:embed campaigns.json
var campaignsRaw []byte

var campaigns = func() map[string]CampaignEntry {
	var m map[string]CampaignEntry
	if err := json.Unmarshal(campaignsRaw, &m, json.RejectUnknownMembers(true)); err != nil {
		panic(fmt.Sprintf("campaigns.json: %v", err))
	}
	return m
}()

// Campaign returns the library's campaign for an RT id.
func Campaign(id string) (CampaignEntry, bool) {
	e, ok := campaigns[id]
	return e, ok
}

// CampaignASI returns the OWASP agentic risks (ASI01..ASI10) a library
// campaign exercises, as its file tags them, ascending; nil for an id that
// is no library campaign or carries no tag (D529).
func CampaignASI(id string) []string {
	return slices.Clone(campaigns[id].ASI)
}

// Lookup returns the library's entry for an RT id.
func Lookup(id string) (Entry, bool) {
	e, ok := entries[id]
	return e, ok
}

// All returns a copy of every entry, by id.
func All() map[string]Entry {
	out := make(map[string]Entry, len(entries))
	for k, v := range entries {
		out[k] = v
	}
	return out
}

// ByTechnique returns the ids of the library scenarios that test a MITRE
// technique (G0 M28 D714): those naming id itself, or naming a
// sub-technique whose parent is id, in atlas or attack; sorted.
func ByTechnique(id string) []string {
	var out []string
	for sid, e := range entries {
		if slices.ContainsFunc(e.ATLAS, matches(id)) || slices.ContainsFunc(e.ATTACK, matches(id)) {
			out = append(out, sid)
		}
	}
	slices.Sort(out)
	return out
}

// matches reports whether a tag is id or one of id's sub-techniques.
func matches(id string) func(string) bool {
	return func(tag string) bool { return tag == id || strings.HasPrefix(tag, id+".") }
}
