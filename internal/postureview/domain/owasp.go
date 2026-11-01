// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
)

// owaspByKind maps a finding kind to its OWASP Top 10 for Agentic
// Applications (2026) risks (D205). Every value is known to the detection
// rules' closed list; a test holds to that.
var owaspByKind = map[string][]string{
	// Posture.
	"excessive_grant":           {"ASI03"},
	"uncovered_path":            {"ASI02"},
	"unowned_agent":             {"ASI03", "ASI10"},
	"unsafe_delegation":         {"ASI03", "ASI07"},
	"stale_credential":          {"ASI03"},
	"unused_authority":          {"ASI03"},
	"unverified_sensitive_tool": {"ASI02"},
	"credential_overreach":      {"ASI03"},
	"unconfirmed_rotation":      {"ASI03"},
	// Suggestions, discovery and inventory.
	KindUnusedSuggestion:  {"ASI03"},
	KindDiscoveryVanished: {"ASI10"},
	KindDiscoveryChanged:  {"ASI10"},
	KindNewTool:           {"ASI02", "ASI04"},
	KindNewResource:       {"ASI04"},
	KindNewResourceTmpl:   {"ASI04"},
	// Supply chain and catalog.
	"hidden_instruction": {"ASI01", "ASI04"},
	"injection_pattern":  {"ASI01", "ASI04"},
	"tool_shadowing":     {"ASI02", "ASI04"},
	"overbroad_schema":   {"ASI02"},
	"rug_pull":           {"ASI04"},
	"provenance_unknown": {"ASI04"},
	"schema_unavailable": {"ASI04"},
	KindUnapprovedServer: {"ASI04"},
}

// OWASP lists kind's risks. An identity recommendation is about who an agent
// is; no other recommendation maps to a risk.
func OWASP(kind string) []string {
	if strings.HasPrefix(kind, "identity.") {
		return []string{"ASI03"}
	}
	return slices.Clone(owaspByKind[kind])
}

// OWASPKinds lists every mapped kind, sorted.
func OWASPKinds() []string {
	out := make([]string, 0, len(owaspByKind))
	for k := range owaspByKind {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
