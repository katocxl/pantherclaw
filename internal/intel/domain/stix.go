// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"strings"
	"time"
)

// STIX 2.1 export (D1105). Every indicator becomes one STIX indicator
// object, and an injection_text indicator one per shingle. The pattern is a
// custom observable of the hash alone, so nothing but hashes leaves
// (HR-818). Ids are UUIDv5-shaped from the indicator id and hash, so an
// export of the same set is the same bundle.

// stixNamespace seeds the deterministic STIX ids.
const stixNamespace = "pantherclaw-intel-stix-v1"

type stixKillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type stixIndicator struct {
	Type            string               `json:"type"`
	SpecVersion     string               `json:"spec_version"`
	ID              string               `json:"id"`
	Created         string               `json:"created"`
	Modified        string               `json:"modified"`
	Name            string               `json:"name"`
	Description     string               `json:"description,omitzero"`
	IndicatorTypes  []string             `json:"indicator_types"`
	Pattern         string               `json:"pattern"`
	PatternType     string               `json:"pattern_type"`
	ValidFrom       string               `json:"valid_from"`
	Labels          []string             `json:"labels"`
	KillChainPhases []stixKillChainPhase `json:"kill_chain_phases,omitzero"`
}

type stixBundle struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Objects []stixIndicator `json:"objects"`
}

// stixID is a deterministic STIX id of the given type.
func stixID(typ string, parts ...string) string {
	sum := sha256.Sum256([]byte(stixNamespace + "|" + strings.Join(parts, "|")))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s--%x-%x-%x-%x-%x", typ, b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// killChain maps techniques to kill chain phases: ATLAS ids to the
// mitre-atlas chain and ATT&CK ids to mitre-attack, the technique id as the
// phase name.
func killChain(techniques []string) []stixKillChainPhase {
	var out []stixKillChainPhase
	for _, t := range SortedTechniques(techniques) {
		chain := "mitre-attack"
		if strings.HasPrefix(t, "AML.") {
			chain = "mitre-atlas"
		}
		out = append(out, stixKillChainPhase{KillChainName: chain, PhaseName: t})
	}
	return out
}

// STIX returns a STIX 2.1 bundle of the indicators, with created and
// modified at, and valid_from each indicator's first_seen.
func STIX(in []Indicator, at time.Time) ([]byte, error) {
	ts := at.UTC().Format("2006-01-02T15:04:05.000Z")
	b := stixBundle{Type: "bundle", Objects: []stixIndicator{}}
	ids := make([]string, 0, len(in))
	for _, x := range in {
		hashes := []string{x.SHA256}
		if x.Kind == KindInjectionText {
			hashes = x.Shingles
		}
		from := ts
		if d, err := time.Parse(time.DateOnly, x.FirstSeen); err == nil {
			from = d.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		for _, h := range hashes {
			id := stixID("indicator", x.ID, h)
			ids = append(ids, id)
			b.Objects = append(b.Objects, stixIndicator{
				Type: "indicator", SpecVersion: "2.1", ID: id, Created: ts, Modified: ts,
				Name: x.ID, Description: x.Summary, IndicatorTypes: []string{"malicious-activity"},
				Pattern:     "[x-pantherclaw-indicator:sha256 = '" + h + "']",
				PatternType: "stix", ValidFrom: from,
				Labels:          []string{"pantherclaw-" + strings.ReplaceAll(string(x.Kind), "_", "-"), "severity-" + strings.ToLower(string(x.Severity))},
				KillChainPhases: killChain(x.Techniques),
			})
		}
	}
	b.ID = stixID("bundle", ids...)
	return json.Marshal(b, json.Deterministic(true))
}
