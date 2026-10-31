// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
)

// Finding kinds of the sources that have no kind of their own.
const (
	KindDiscoveryVanished = "discovery_vanished"
	KindDiscoveryChanged  = "discovery_changed"
	KindNewTool           = "new_tool"
	KindNewResource       = "new_resource"
	KindNewResourceTmpl   = "new_resource_template"
	KindUnusedSuggestion  = "UNUSED_AUTHORITY"
	KindUnapprovedServer  = "UNAPPROVED_SERVER"
)

// severityByKind is the fixed table for sources that state no severity
// (D203). A kind that is not here is MEDIUM.
var severityByKind = map[string]Severity{
	KindDiscoveryVanished: SeverityMedium,
	KindDiscoveryChanged:  SeverityMedium,
	KindNewTool:           SeverityMedium,
	KindNewResource:       SeverityLow,
	KindNewResourceTmpl:   SeverityLow,
	KindUnusedSuggestion:  SeverityLow,
	KindUnapprovedServer:  SeverityHigh,
}

// recommendationPrefixes are the families of recommendation ids: a
// recommendation is advice, never a risk found.
var recommendationPrefixes = []string{"identity.", "classification.", "approval.", "incident.", "export.", "unsupported."}

// KindSeverity is kind's severity in the fixed table.
func KindSeverity(kind string) Severity {
	if s, ok := severityByKind[kind]; ok {
		return s
	}
	if slices.ContainsFunc(recommendationPrefixes, func(p string) bool { return strings.HasPrefix(kind, p) }) {
		return SeverityInfo
	}
	return SeverityMedium
}

var severities = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Rank orders severities, INFO lowest; an unknown one is below INFO.
func (s Severity) Rank() int { return slices.Index(severities, s) }

// Normalize fills a finding's severity and its basis: a stated severity in
// the API's upper case, or the table's. A source's text that is no severity
// counts as not stated. A finding with no fix goes to review, so every
// finding has one.
func (f Finding) Normalize() Finding {
	if f.Fix.Kind == "" {
		f.Fix = Fix{Kind: FixReviewFinding, TargetID: f.Key(), Label: "Review the finding"}
	}
	s := Severity(strings.ToUpper(string(f.Severity)))
	if s.Rank() >= 0 {
		f.Severity, f.SeverityBasis = s, BasisStated
		return f
	}
	f.Severity, f.SeverityBasis = KindSeverity(f.Kind), BasisByKind
	return f
}
