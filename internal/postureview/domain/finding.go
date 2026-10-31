// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the ranked posture queue (G0 M24 D200-D205; HR-580):
// findings from every source joined into one list, each with a fix. The
// queue has no number of any kind for a finding's risk (D203, F797): it is
// ordered by a tuple of plain facts and says which of them applied. A finding
// belongs to its source: it clears when its source clears, and dismissing it
// goes to the source (D207). Everything here is pure.
package domain

import (
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Source names where a finding comes from.
type Source string

// Sources (D204). Supply-chain flags and unapproved servers arrive through
// the same port as the rest.
const (
	SourcePosture         Source = "posture"
	SourceCoverage        Source = "coverage"
	SourceSuggestions     Source = "suggestions"
	SourceDiscovery       Source = "discovery"
	SourceRecommendations Source = "recommendations"
	SourceInventory       Source = "inventory"
	SourceSupplyChain     Source = "supply_chain"
	SourceCatalog         Source = "catalog"
)

// MaxPerSource is how many findings one source returns (D204). A source
// with more reports that it truncated, and the read says so.
const MaxPerSource = 1000

// Severity is a finding's severity, in the API's upper case.
type Severity string

// Severities, least to most.
const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// SeverityBasis says where a finding's severity came from (D202).
type SeverityBasis string

// Bases.
const (
	// BasisStated: the source stated it.
	BasisStated SeverityBasis = "STATED"
	// BasisByKind: the source has no severity; it comes from the fixed table
	// in severity.go.
	BasisByKind SeverityBasis = "BY_KIND"
)

// FixKind is what a finding's fix asks for; each names where the viewer
// acts, and nothing here acts.
type FixKind string

// Fix kinds.
const (
	FixReviewFinding   FixKind = "REVIEW_FINDING"
	FixReviewGrant     FixKind = "REVIEW_GRANT"
	FixAssignOwner     FixKind = "ASSIGN_OWNER"
	FixRotateSecret    FixKind = "ROTATE_CREDENTIAL" //nolint:gosec // G101: a fix kind, not a credential
	FixEnforcePath     FixKind = "ENFORCE_PATH"
	FixNarrowScopes    FixKind = "NARROW_SCOPES"
	FixAddVerifier     FixKind = "ADD_VERIFIER"
	FixReviewCoverage  FixKind = "REVIEW_COVERAGE"
	FixReviewSuggested FixKind = "REVIEW_SUGGESTION"
	FixClaimAgent      FixKind = "CLAIM_AGENT"
	FixConnect         FixKind = "CONNECT_INTEGRATION"
	FixReviewTool      FixKind = "REVIEW_TOOL"
	FixReviewServer    FixKind = "REVIEW_SERVER"
)

// Fix says what would close a finding: every finding has one (D202).
// TargetID names the record the fix acts on, in "<type>:<id>" form.
type Fix struct {
	Kind     FixKind
	TargetID string
	Label    string
}

// Finding is one finding as a source reports it. A source fills what it
// knows: AgentLabel, TeamID, ReachesProduction and Unowned are read from the
// agent by the service, and an empty Severity is filled from the fixed table
// (Normalize).
type Finding struct {
	Source Source
	// SourceID is the finding's id inside its source.
	SourceID string
	// Kind is the source's own kind, a closed list per source.
	Kind string
	// RootCause groups findings with the same cause; empty when the source
	// has none.
	RootCause    string
	AgentID      *ids.UUID
	AgentLabel   string
	ConnectionID *ids.UUID
	TeamID       *ids.UUID
	// Title is the source's text, shown as plain text.
	Title         string
	Severity      Severity
	SeverityBasis SeverityBasis
	// State is the source's state.
	State string
	// Since is when the finding first showed.
	Since time.Time
	Fix   Fix
	// ReachesProduction: its agent is in a production environment.
	ReachesProduction bool
	// Unowned: its agent has no owner, or it has no agent.
	Unowned bool
}

// Key is the finding's stable id across sources.
func (f Finding) Key() string { return string(f.Source) + ":" + f.SourceID }

// RankedFinding is a finding in the queue (D202). It has no score field and
// never gets one (HR-580).
type RankedFinding struct {
	Finding
	// OWASP lists the ASI risks of its kind (D205).
	OWASP []string
	// RankReasons state, in order, which sort keys applied (D203).
	RankReasons []string
}

// Filter narrows a read; a zero field keeps everything. A source may apply
// it or leave it to the service, which applies it to everything a source
// returns.
type Filter struct {
	Source     Source
	Kind       string
	Severity   Severity
	Team       *ids.UUID
	Agent      *ids.UUID
	Connection *ids.UUID
}

// Match reports whether f passes the filter.
func (x Filter) Match(f Finding) bool {
	switch {
	case x.Source != "" && f.Source != x.Source:
		return false
	case x.Kind != "" && f.Kind != x.Kind:
		return false
	case x.Severity != "" && f.Severity != x.Severity:
		return false
	case x.Team != nil && (f.TeamID == nil || *f.TeamID != *x.Team):
		return false
	case x.Agent != nil && (f.AgentID == nil || *f.AgentID != *x.Agent):
		return false
	case x.Connection != nil && (f.ConnectionID == nil || *f.ConnectionID != *x.Connection):
		return false
	}
	return true
}
