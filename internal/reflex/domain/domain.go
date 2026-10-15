// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the Reflex contracts every M10 stream codes against
// (G0 M10 D1): signals, their subjects, attention and basis, and the ports
// one stream implements for the others (Raiser, CaseOpener, FailureSink,
// Container, ReachPreviewer). Implementations are wired in internal/server;
// packages never import each other's adapters.
//
// Import it as reflexdomain. It imports nothing beyond ids, pgx and the
// standard library.
package domain

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// SubjectType names what a signal, case or failure is about.
type SubjectType string

// Subject types.
const (
	SubjectAgent          SubjectType = "agent"
	SubjectInstance       SubjectType = "instance"
	SubjectRun            SubjectType = "run"
	SubjectTransaction    SubjectType = "transaction"
	SubjectGrant          SubjectType = "grant"
	SubjectConnection     SubjectType = "connection"
	SubjectCredential     SubjectType = "credential"
	SubjectGateway        SubjectType = "gateway"
	SubjectPackage        SubjectType = "package"
	SubjectUser           SubjectType = "user"
	SubjectServiceAccount SubjectType = "service_account"
	SubjectResource       SubjectType = "resource"
	SubjectPolicyVersion  SubjectType = "policy_version"
	SubjectAlert          SubjectType = "alert"
	SubjectIncident       SubjectType = "incident"
	SubjectCase           SubjectType = "case"
	SubjectFinding        SubjectType = "finding"
	// SubjectSystem is PantherClaw acting by itself (D51), as the actor of
	// automated containment. Its ids are fixed lowercase names:
	// identity_playbook, detection, sweeper.
	SubjectSystem SubjectType = "system"
)

var subjectTypes = []SubjectType{
	SubjectAgent, SubjectInstance, SubjectRun, SubjectTransaction, SubjectGrant, SubjectConnection, SubjectCredential,
	SubjectGateway, SubjectPackage, SubjectUser, SubjectServiceAccount, SubjectResource, SubjectPolicyVersion,
	SubjectAlert, SubjectIncident, SubjectCase, SubjectFinding, SubjectSystem,
}

// Valid reports whether t is a known subject type.
func (t SubjectType) Valid() bool { return slices.Contains(subjectTypes, t) }

// SubjectTypes returns every subject type in a stable order.
func SubjectTypes() []SubjectType { return slices.Clone(subjectTypes) }

// Subject is one thing a signal is about.
type Subject struct {
	Type SubjectType `json:"type"`
	ID   string      `json:"id"`
}

// String is "type:id".
func (s Subject) String() string { return string(s.Type) + ":" + s.ID }

// Valid reports whether s has a known type and a 1..256 byte id.
func (s Subject) Valid() bool { return s.Type.Valid() && s.ID != "" && len(s.ID) <= 256 }

// Attention is how much attention a signal asks for (F607), ordered
// TELEMETRY < LIVE < FINDING < ALERT < INCIDENT < PAGE.
type Attention string

// Attention levels.
const (
	AttentionTelemetry Attention = "TELEMETRY"
	AttentionLive      Attention = "LIVE"
	AttentionFinding   Attention = "FINDING"
	AttentionAlert     Attention = "ALERT"
	AttentionIncident  Attention = "INCIDENT"
	AttentionPage      Attention = "PAGE"
)

var attentions = []Attention{AttentionTelemetry, AttentionLive, AttentionFinding, AttentionAlert, AttentionIncident, AttentionPage}

// Rank orders attention levels; an unknown level ranks -1.
func (a Attention) Rank() int { return slices.Index(attentions, a) }

// Valid reports whether a is a known level.
func (a Attention) Valid() bool { return a.Rank() >= 0 }

// AtLeast reports whether a ranks at or above b.
func (a Attention) AtLeast(b Attention) bool { return a.Valid() && a.Rank() >= b.Rank() }

// Severity of a signal.
type Severity string

// Severities.
const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

var severities = []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Rank orders severities; an unknown severity ranks -1.
func (s Severity) Rank() int { return slices.Index(severities, s) }

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return s.Rank() >= 0 }

// Basis says how a signal knows what it says (F648): what was observed is
// kept apart from what a rule matched, what was inferred and what is only
// a hypothesis.
type Basis string

// Bases.
const (
	BasisObserved   Basis = "OBSERVED"
	BasisRuleMatch  Basis = "RULE_MATCH"
	BasisInferred   Basis = "INFERRED"
	BasisHypothesis Basis = "HYPOTHESIS"
)

// Valid reports whether b is a known basis.
func (b Basis) Valid() bool {
	return b == BasisObserved || b == BasisRuleMatch || b == BasisInferred || b == BasisHypothesis
}

// Evidence reference kinds.
const (
	EvidenceLedger      = "ledger"
	EvidenceTransaction = "transaction"
	EvidenceRun         = "run"
	EvidenceReceipt     = "receipt"
	EvidenceCaseEntry   = "case_entry"
)

// EvidenceRef points at a recorded fact a signal rests on.
type EvidenceRef struct {
	Kind string   `json:"kind"`
	ID   ids.UUID `json:"id"`
}

// Valid reports whether r has a known kind and an id.
func (r EvidenceRef) Valid() bool {
	switch r.Kind {
	case EvidenceLedger, EvidenceTransaction, EvidenceRun, EvidenceReceipt, EvidenceCaseEntry:
		return !r.ID.IsZero()
	}
	return false
}

// Signal sources.
const (
	SourceDetection = "detection"
	SourceResponse  = "response"
	SourceSIEM      = "siem"
	SourceSignals   = "signals"
	SourceCoverage  = "coverage"
	SourceSystem    = "system"
)

var sources = []string{SourceDetection, SourceResponse, SourceSIEM, SourceSignals, SourceCoverage, SourceSystem}

// Signal is something worth attention, raised by a detection rule or by
// another part of the product (response, SIEM delivery, Shared Signals,
// coverage, the system itself). The Raiser turns it into an alert, a live
// event or nothing, by its attention (D14).
type Signal struct {
	Org         ids.OrgID
	Source      string
	RuleID      string
	RuleVersion string
	RuleDigest  string
	PackVersion string
	Title       string
	Summary     string
	Severity    Severity
	Attention   Attention
	Basis       Basis
	Subjects    []Subject
	Evidence    []EvidenceRef
	// GroupKey is the evidence-based grouping key ("run:<id>",
	// "agent:<id>", …; F603); DedupeKey makes a repeat signal count into
	// the same open alert.
	GroupKey, DedupeKey string
	// ATLAS and OWASP are the MITRE ATLAS techniques and OWASP agentic
	// risks the rule maps to.
	ATLAS, OWASP []string
	OccurredAt   time.Time
	// Test marks a signal raised by a rule test or a test event: capped at
	// ALERT and never pages (F616).
	Test bool
	// Facts are small, non-secret context: ≤ 16 keys, ≤ 512 bytes each.
	Facts map[string]string
}

// Signal limits.
const (
	MaxFacts      = 16
	MaxFactValue  = 512
	MaxSubjects   = 32
	MaxEvidence   = 64
	MaxTitle      = 200
	MaxSummary    = 2000
	MaxKey        = 512
	MaxMappings   = 16
	MaxRuleIDSize = 128
)

// ErrInvalidSignal reports a signal the Raiser refuses.
var ErrInvalidSignal = errors.New("reflex: invalid signal")

var factKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Validate checks the signal's shape. The Raiser also refuses secret-like
// fact keys (the audit details validator).
func (s Signal) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidSignal, fmt.Sprintf(format, a...))
	}
	switch {
	case s.Org.IsZero():
		return bad("no org")
	case !slices.Contains(sources, s.Source):
		return bad("unknown source %q", s.Source)
	case s.Source == SourceDetection && (s.RuleID == "" || s.RuleDigest == ""):
		return bad("a detection names its rule and digest")
	case len(s.RuleID) > MaxRuleIDSize || len(s.RuleVersion) > 64 || len(s.RuleDigest) > 128 || len(s.PackVersion) > 64:
		return bad("rule reference too long")
	case s.Title == "" || len(s.Title) > MaxTitle || len(s.Summary) > MaxSummary:
		return bad("title 1..%d bytes, summary ≤ %d", MaxTitle, MaxSummary)
	case !s.Severity.Valid():
		return bad("unknown severity %q", s.Severity)
	case !s.Attention.Valid():
		return bad("unknown attention %q", s.Attention)
	case !s.Basis.Valid():
		return bad("unknown basis %q", s.Basis)
	case len(s.Subjects) > MaxSubjects || len(s.Evidence) > MaxEvidence:
		return bad("at most %d subjects and %d evidence references", MaxSubjects, MaxEvidence)
	case len(s.GroupKey) > MaxKey || len(s.DedupeKey) > MaxKey:
		return bad("keys ≤ %d bytes", MaxKey)
	case len(s.ATLAS) > MaxMappings || len(s.OWASP) > MaxMappings:
		return bad("at most %d mappings each", MaxMappings)
	case s.OccurredAt.IsZero():
		return bad("no time")
	case len(s.Facts) > MaxFacts:
		return bad("at most %d facts", MaxFacts)
	}
	for _, sub := range s.Subjects {
		if !sub.Valid() {
			return bad("invalid subject %q", sub.String())
		}
	}
	for _, e := range s.Evidence {
		if !e.Valid() {
			return bad("invalid evidence reference %q", e.Kind)
		}
	}
	for k, v := range s.Facts {
		if !factKey.MatchString(k) || len(v) > MaxFactValue {
			return bad("fact %q", k)
		}
	}
	return nil
}

// Raiser records signals (core, D14): an alert, a live ledger entry or
// nothing, by attention, in the caller's transaction. It returns the alert
// id, or the zero id when no alert was written.
type Raiser interface {
	Raise(ctx context.Context, tx pgx.Tx, s Signal) (ids.UUID, error)
}

// CaseSeed is what a new case starts from (cases, D19).
type CaseSeed struct {
	Org        ids.OrgID
	Title      string
	Source     string
	Subjects   []Subject
	Evidence   []EvidenceRef
	Questions  []string
	AlertID    *ids.UUID
	IncidentID *ids.UUID
	Opener     Subject
}

// CaseOpener opens a case (cases, D19).
type CaseOpener interface {
	Open(ctx context.Context, tx pgx.Tx, seed CaseSeed) (ids.UUID, error)
}

// Failure is an owned operational failure (F641): what broke, where, who
// owns it, by when and what to do next.
type Failure struct {
	Org       ids.OrgID
	Kind      string
	Summary   string
	NextStep  string
	Scope     []Subject
	Owner     *Subject
	Deadline  time.Time
	DedupeKey string
}

// FailureSink records owned failures (core, D18). A repeat with the same
// dedupe key while the failure is open returns the open failure.
type FailureSink interface {
	Report(ctx context.Context, tx pgx.Tx, f Failure) (ids.UUID, error)
}

// Containment controls (response, D21).
const (
	ControlDenyAll       = "DENY_ALL"
	ControlHoldWrites    = "HOLD_WRITES"
	ControlDenyOperation = "DENY_OPERATION"
)

// ContainRequest asks for one containment control (response, D21).
type ContainRequest struct {
	Org        ids.OrgID
	Scope      Subject
	Control    string
	Operation  string
	Reason     string
	CaseID     *ids.UUID
	IncidentID *ids.UUID
	Actor      Subject
	// PreviewDigest is the SHA-256 of the canonical preview a wider control
	// was confirmed against (D23).
	PreviewDigest []byte
	Idempotency   string
}

// ContainResult is the response action a request created and its status
// (REQUESTED|PARTIAL|CONFIRMED|FAILED|UNSUPPORTED).
type ContainResult struct {
	ActionID ids.UUID
	Status   string
}

// Container applies containment controls (response, D21).
type Container interface {
	Contain(ctx context.Context, tx pgx.Tx, r ContainRequest) (ContainResult, error)
}

// ReductionChange is an authority reduction to preview (exposure, D27):
// containing, revoking or narrowing the listed subjects.
type ReductionChange struct {
	// Kind is what the change does, for example "contain", "revoke_grant"
	// or "narrow_grant".
	Kind      string
	Subjects  []Subject
	Control   string
	Operation string
}

// Reach is how much one side of a preview can reach.
type Reach struct {
	// Resources counts reachable resource groups; Usable, Conditional and
	// Uncertain split the rights by label (D27).
	Resources   int
	Usable      int
	Conditional int
	Uncertain   int
}

// ReachDiff is the before and after of a reduction and what it would
// disrupt (F259).
type ReachDiff struct {
	Before, After Reach
	// Disruption lists the runs, agents or workloads the change would stop.
	Disruption []Subject
	// Stale marks a diff computed from a snapshot older than the last
	// relevant change.
	Stale bool
	Note  string
}

// ReachPreviewer previews an authority reduction (exposure, D27).
type ReachPreviewer interface {
	PreviewReduction(ctx context.Context, org ids.OrgID, c ReductionChange) (ReachDiff, error)
}
