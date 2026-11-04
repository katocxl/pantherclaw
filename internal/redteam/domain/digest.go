// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"sort"
	"strings"
)

// runs is what a scenario's digest covers: only what runs (ADR-0051,
// HR-661), under the scenario file's own JSON names. The id, title,
// category, suite, tier, attacker, threats, rules, asi, asi_why and the
// technique tags (atlas, attack, technique_why, techniques_none; G0 M28
// D714c L2) describe the scenario and are left out, so a tag or wording
// change keeps the digest.
type runs struct {
	APIVersion  string   `json:"apiVersion"`
	Requires    []string `json:"requires,omitempty"`
	HarnessOnly bool     `json:"harness_only,omitzero"`
	Steps       []Step   `json:"steps"`
}

// Digest returns 64 lowercase hex, no prefix, of the RFC 8785 canonical JSON
// of what the parsed scenario runs: apiVersion, requires, harness_only and
// every step whole (id, do, with, save, expect). Spelling and defaults in
// the YAML do not change it, and neither does a field that only describes
// the scenario (ADR-0051).
func Digest(s *Scenario) (string, error) {
	raw, err := json.Marshal(runs{APIVersion: s.APIVersion, Requires: s.Requires, HarnessOnly: s.HarnessOnly, Steps: s.Steps})
	if err != nil {
		return "", invalid("%v", err)
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return "", invalid("%v", err)
	}
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:]), nil
}

// SetDigest returns 64 lowercase hex, no prefix, over the sorted "id:digest" lines of a
// scenario set (id to scenario digest).
func SetDigest(digests map[string]string) string {
	ids := make([]string, 0, len(digests))
	for id := range digests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&b, "%s:%s\n", id, digests[id])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
