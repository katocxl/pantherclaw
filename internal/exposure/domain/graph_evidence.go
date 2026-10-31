// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Causal edge kinds (G0 M22 D12; F279–F281). A causal link exists only
// with its evidence (HR-551); without it the graph holds a gap edge.
const (
	EdgeAuthorized = "authorized" // grant -> transaction
	EdgeApproved   = "approved"   // approval -> transaction
	EdgeCustody    = "custody"    // permit -> transaction it dispatched
	EdgeEffect     = "effect"     // transaction -> effect
	EdgeTriggered  = "triggered"  // transaction -> consequence
)

// Node types of the causal graph.
const (
	NodeApproval    = "approval"
	NodePermit      = "permit"
	NodeEffect      = "effect"
	NodeConsequence = "consequence"
	NodeOperation   = "operation"
)

// What a gap edge says is missing (D12, D13).
const (
	GapNoGrant       = "NO_GRANT_RECORDED"
	GapNoApproval    = "NO_APPROVAL_EVIDENCE"
	GapNoExecution   = "NO_EXECUTION_RECEIPT"
	GapNoEffect      = "NO_EFFECT_RECEIPT"
	GapConsequence   = "CONSEQUENCE_UNKNOWN"
	GapReachUnknown  = "REACH_UNCERTAIN"
	GapCoverage      = "COVERAGE_UNKNOWN"
	GapBoundsUnknown = "BOUNDS_UNREADABLE"
)

// EdgeStatus is what an edge's evidence says about it (F291), apart from
// whether it still counts as current (EdgeState, F292).
type EdgeStatus string

// Edge statuses.
const (
	StatusEnforced           EdgeStatus = "ENFORCED"
	StatusAllowed            EdgeStatus = "ALLOWED"
	StatusApprovalRequired   EdgeStatus = "APPROVAL_REQUIRED"
	StatusDenied             EdgeStatus = "DENIED"
	StatusObserved           EdgeStatus = "OBSERVED"
	StatusPossibleBypass     EdgeStatus = "POSSIBLE_BYPASS"
	StatusUnknown            EdgeStatus = "UNKNOWN"
	StatusStale              EdgeStatus = "STALE"
	StatusEffectPartial      EdgeStatus = "EFFECT_PARTIAL"
	StatusEffectPending      EdgeStatus = "EFFECT_PENDING"
	StatusEffectConflicting  EdgeStatus = "EFFECT_CONFLICTING"
	StatusEffectUnverifiable EdgeStatus = "EFFECT_UNVERIFIABLE"
)

// ChangeKind says what a change edge did between two revisions (F276).
type ChangeKind string

// Change kinds.
const (
	ChangeAdded   ChangeKind = "ADDED"
	ChangeRemoved ChangeKind = "REMOVED"
	ChangeKept    ChangeKind = "KEPT"
)

// TriggerStage is how far a triggered edge has been shown (D12).
type TriggerStage string

// Trigger stages. A prediction is never a confirmation.
const (
	StagePredicted  TriggerStage = "PREDICTED"
	StageAuthorized TriggerStage = "AUTHORIZED"
	StageConfirmed  TriggerStage = "CONFIRMED"
)

// Assurance values (F297). Staleness is in Freshness.
const (
	AssuranceAuthoritative = "AUTHORITATIVE"
	AssuranceTested        = "TESTED"
	AssuranceDeclared      = "DECLARED"
	AssuranceInferred      = "INFERRED"
	AssuranceUnverified    = "UNVERIFIED"
)

// freshStale is the Freshness of an edge from a snapshot that predates a
// recorded change (app.FreshStale).
const freshStale = "STALE"

// decisionStatus is what a recorded decision says, or "" for none.
func decisionStatus(d string) EdgeStatus {
	switch d {
	case "ALLOW", "ALLOW_WITH_OBLIGATIONS":
		return StatusAllowed
	case "REQUIRE_APPROVAL", "REQUIRE_STEP_UP":
		return StatusApprovalRequired
	case "DENY", "CANNOT_AUTHORIZE":
		return StatusDenied
	default:
		return ""
	}
}

// effectStatus is what a recorded effect state says, or "" when the effect
// is settled and the edge's other fields say more.
func effectStatus(s string) EdgeStatus {
	switch s {
	case "PARTIAL":
		return StatusEffectPartial
	case "PROPAGATION_PENDING":
		return StatusEffectPending
	case "CONFLICTING":
		return StatusEffectConflicting
	case "UNVERIFIABLE":
		return StatusEffectUnverifiable
	case "UNKNOWN":
		return StatusUnknown
	default:
		return ""
	}
}

// status is an activity edge's status: a monitor-mode decision prevented
// nothing, so it reads as observed unless its effect is unsettled.
func (a Activity) status() EdgeStatus {
	if s := effectStatus(a.Effect); s != "" {
		return s
	}
	if a.Execution == "unknown" {
		return StatusUnknown
	}
	if a.Monitor {
		return StatusObserved
	}
	return ""
}

// statusOf derives the status of an edge that was not given one.
func statusOf(e Edge) EdgeStatus {
	if e.Kind == EdgeGap {
		return StatusUnknown
	}
	if e.Freshness == freshStale {
		return StatusStale
	}
	if s := effectStatus(e.Effect); s != "" {
		return s
	}
	if s := decisionStatus(e.Decision); s != "" {
		return s
	}
	switch {
	case e.Basis == "OBSERVED":
		return StatusObserved
	case e.Provenance == string(Credential) && e.Coverage != CoverageEnforced:
		return StatusPossibleBypass
	case e.State == EdgePossible, e.Coverage == CoverageUnknown:
		return StatusUnknown
	case e.Coverage == CoverageEnforced:
		return StatusEnforced
	case e.Coverage == CoverageObserveOnly:
		return StatusObserved
	case e.Basis == "RULE_MATCH":
		return StatusAllowed
	default:
		return StatusUnknown
	}
}

// assuranceOf derives how far an edge is established (F297).
func assuranceOf(e Edge) string {
	switch {
	case e.Kind == EdgeGap, e.Basis == "HYPOTHESIS":
		return AssuranceUnverified
	case e.Basis == "INFERRED":
		return AssuranceInferred
	case e.Basis == "OBSERVED", e.EvidenceRef != "":
		return AssuranceAuthoritative
	case e.Provenance == string(Credential):
		return AssuranceDeclared
	case e.Coverage == CoverageEnforced:
		return AssuranceTested
	case e.Basis == "RULE_MATCH":
		return AssuranceDeclared
	default:
		return AssuranceUnverified
	}
}

// annotate fills in what is derived from the edge's own fields.
func (e *Edge) annotate() {
	if e.Status == "" {
		e.Status = statusOf(*e)
	}
	if e.Assurance == "" {
		e.Assurance = assuranceOf(*e)
	}
}

// ApprovalEvidence is an approved request of a transaction.
type ApprovalEvidence struct {
	ID string
	At *time.Time
}

// ConsequenceEvidence is one consequence a decision recorded (F405), with
// the transaction opened for it, if any.
type ConsequenceEvidence struct {
	Evaluation, Position int
	// Parent is the position it follows from; -1 at depth 1.
	Parent    int
	Operation string
	// State is PREDICTED or UNKNOWN.
	State string
	At    time.Time
	// Transaction is the consequence transaction, Linked the transaction
	// the link names as its parent; both empty until one is opened.
	Transaction, Linked string
	Effect              string
	// EffectSeq is its latest effect receipt; 0 for none.
	EffectSeq int
}

// CausalEvidence is what is recorded about one transaction beyond its
// activity (D12).
type CausalEvidence struct {
	Activity Activity
	Grant    string
	// Consequence marks a transaction the server opened for another: it
	// has no decision of its own to authorize.
	Consequence bool
	Approvals   []ApprovalEvidence
	// Permit is the transaction's current permit: the one lease of the
	// connection's credential for this dispatch. Dispatched says it was
	// used; no per-dispatch credential version is recorded.
	Permit           string
	Dispatched       *time.Time
	Attempt          string
	AttemptAt        *time.Time
	ExecutionReceipt bool
	// EffectSeq is the latest effect receipt; 0 for none.
	EffectSeq    int
	EffectState  string
	EffectBasis  string
	EffectAt     *time.Time
	Downstream   string
	Consequences []ConsequenceEvidence
}

func allowedDecision(d string) bool { return decisionStatus(d) == StatusAllowed }

// CausalLinks are the causal graph's evidenced links (D12): each is emitted
// only with the record that proves it, and anything the record should
// exist for and does not gets a gap edge (HR-551).
func CausalLinks(evidence []CausalEvidence) []Edge {
	var out []Edge
	for _, c := range evidence {
		a := c.Activity
		ctx := a.context()
		at := a.At
		run, txn := Node{Type: "run", ID: a.Run}, Node{Type: "transaction", ID: a.Transaction}
		gap := func(from, to Node, missing string, when *time.Time) {
			out = append(out, Edge{
				From: from, To: to, Context: ctx, Kind: EdgeGap, State: EdgeHistorical, Basis: "OBSERVED", At: when,
				Provenance: missing, Operation: a.Operation,
			})
		}
		if !c.Consequence {
			if a.Missing != "" {
				gap(run, txn, a.Missing, &at)
			}
			approved := len(c.Approvals) > 0
			if allowedDecision(a.Decision) || (a.Decision == "REQUIRE_APPROVAL" && approved) {
				switch {
				case c.Grant == "":
					gap(run, txn, GapNoGrant, &at)
				case a.Missing == "":
					out = append(out, Edge{
						From: Node{Type: "grant", ID: c.Grant}, To: txn, Context: ctx, Kind: EdgeAuthorized, State: EdgeHistorical,
						Decision: a.Decision, Basis: "OBSERVED", At: &at, Operation: a.Operation, Provenance: "decision_receipt",
						EvidenceRef: "decision_receipt:" + a.Transaction, Status: a.status(),
					})
				}
			}
			if a.Decision == "REQUIRE_APPROVAL" && !approved && c.Dispatched != nil {
				gap(run, txn, GapNoApproval, c.Dispatched)
			}
		}
		for _, p := range c.Approvals {
			out = append(out, Edge{
				From: Node{Type: NodeApproval, ID: p.ID}, To: txn, Context: ctx, Kind: EdgeApproved, State: EdgeHistorical,
				Basis: "OBSERVED", At: p.At, Operation: a.Operation, Provenance: "approval_request",
				EvidenceRef: "approval_request:" + p.ID, Status: StatusAllowed,
			})
		}
		if c.Dispatched != nil {
			if c.ExecutionReceipt {
				out = append(out, Edge{
					From: Node{Type: NodePermit, ID: c.Permit}, To: txn, Context: ctx, Kind: EdgeCustody, State: EdgeHistorical,
					Execution: a.Execution, Basis: "OBSERVED", At: c.AttemptAt, Operation: a.Operation, Provenance: "execution_receipt",
					EvidenceRef: "execution_receipt:" + c.Attempt, Status: a.status(),
				})
			} else {
				gap(Node{Type: NodePermit, ID: c.Permit}, txn, GapNoExecution, c.Dispatched)
			}
		}
		switch {
		case c.EffectSeq > 0:
			seq := a.Transaction + "/" + strconv.Itoa(c.EffectSeq)
			out = append(out, Edge{
				From: txn, To: Node{Type: NodeEffect, ID: seq}, Context: ctx, Kind: EdgeEffect, State: EdgeHistorical,
				Effect: c.EffectState, Basis: "OBSERVED", At: c.EffectAt, Operation: a.Operation, Provenance: c.EffectBasis,
				EvidenceRef: "effect_receipt:" + seq, Downstream: c.Downstream,
			})
		case c.Attempt != "":
			gap(txn, Node{Type: NodeEffect, ID: a.Transaction}, GapNoEffect, c.AttemptAt)
		}
		out = append(out, triggered(c, ctx)...)
	}
	return out
}

// triggered are a transaction's consequence edges (D12): predicted by a
// rule, authorized once a consequence transaction is opened and linked,
// confirmed only by that transaction's effect receipt. A consequence the
// rule could not rule out is a gap, never a link.
func triggered(c CausalEvidence, ctx []Node) []Edge {
	root := c.Activity.Transaction
	opened := map[int]string{}
	for _, x := range c.Consequences {
		if x.Transaction != "" {
			opened[x.Position] = x.Transaction
		}
	}
	consequence := func(position int) Node {
		if t, ok := opened[position]; ok {
			return Node{Type: "transaction", ID: t}
		}
		return Node{Type: NodeConsequence, ID: root + "/" + strconv.Itoa(position)}
	}
	var out []Edge
	for _, x := range c.Consequences {
		at := x.At
		from := Node{Type: "transaction", ID: root}
		switch {
		case x.Linked != "":
			from.ID = x.Linked
		case x.Parent >= 0:
			from = consequence(x.Parent)
		}
		e := Edge{
			From: from, To: consequence(x.Position), Context: ctx, Kind: EdgeTriggered, State: EdgeHistorical, At: &at,
			Operation: x.Operation, Provenance: "decision_consequence",
		}
		ref := "decision_consequence:" + root + "/" + strconv.Itoa(x.Evaluation) + "/" + strconv.Itoa(x.Position)
		switch {
		case x.State != "PREDICTED":
			e.Kind, e.Basis, e.Provenance = EdgeGap, "RULE_MATCH", GapConsequence
		case x.Transaction == "":
			// Nothing shows it happened: a possible consequence, by rule.
			e.Stage, e.State, e.Basis, e.EvidenceRef, e.Status = StagePredicted, EdgePossible, "RULE_MATCH", ref, StatusUnknown
		case x.Effect == "CONFIRMED" && x.EffectSeq > 0:
			e.Stage, e.Basis, e.Effect, e.Provenance = StageConfirmed, "OBSERVED", x.Effect, "effect_receipt"
			e.EvidenceRef = "effect_receipt:" + x.Transaction + "/" + strconv.Itoa(x.EffectSeq)
		default:
			e.Stage, e.Basis, e.Effect, e.Provenance = StageAuthorized, "OBSERVED", x.Effect, "transaction_link"
			e.EvidenceRef = "transaction_link:" + from.ID + "/" + x.Transaction
		}
		out = append(out, e)
	}
	return out
}

// ReachGaps are the gaps of an authority or exposure graph (D13): each
// current right whose reach or coverage is not known, once per holder and
// resource group. Observed rights are what happened, and history is no gap.
func ReachGaps(rights []Right) []Edge {
	seen := map[string]bool{}
	var out []Edge
	for _, r := range rights {
		if r.View == Observed || !stateOf(r).Current() {
			continue
		}
		missing := ""
		switch {
		case r.Label == Uncertain:
			missing = GapReachUnknown
		case r.Coverage == CoverageUnknown:
			missing = GapCoverage
		default:
			continue
		}
		from, to := agentNode(r), Node{Type: "resource", ID: r.ResourceGroup}
		if k := from.ID + "|" + to.ID + "|" + missing; seen[k] {
			continue
		} else {
			seen[k] = true
		}
		out = append(out, Edge{
			From: from, To: to, Context: []Node{ownerNode(r)}, Kind: EdgeGap, State: EdgeHistorical, Basis: "RULE_MATCH",
			Coverage: r.Coverage, Provenance: missing, ExpiresAt: r.ExpiresAt,
		})
	}
	return out
}

// BoundsChange is one change to what a grant allows: the operations before
// and after it (nil before a first revision; nil after a revocation).
type BoundsChange struct {
	Grant    Node
	Revision int
	At       time.Time
	Context  []Node
	Current  bool
	Before   []string
	After    []string
	// Unreadable: a side could not be read, so nothing is compared.
	Unreadable bool
	// Ref names the record of the change.
	Ref string
}

// CompareEdges are the before and after of grant changes (F276): one edge
// per operation, ADDED, REMOVED or KEPT. An unreadable side is a gap, never
// a comparison (D13).
func CompareEdges(cs []BoundsChange) []Edge {
	var out []Edge
	for _, c := range cs {
		at := c.At
		if c.Unreadable {
			out = append(out, Edge{
				From: c.Grant, To: c.Grant, Context: c.Context, Kind: EdgeGap, State: EdgeHistorical, Basis: "OBSERVED", At: &at,
				Revision: c.Revision, Provenance: GapBoundsUnknown,
			})
			continue
		}
		add := func(op string, kind ChangeKind) {
			st := EdgeHistorical
			if c.Current && kind != ChangeRemoved {
				st = EdgeActive
			}
			out = append(out, Edge{
				From: c.Grant, To: Node{Type: NodeOperation, ID: op}, Context: c.Context, Kind: EdgeAllows, State: st, Basis: "OBSERVED",
				At: &at, Revision: c.Revision, Operation: op, Provenance: "grant_revision", EvidenceRef: c.Ref, Change: kind,
			})
		}
		for _, op := range c.After {
			if slices.Contains(c.Before, op) {
				add(op, ChangeKept)
			} else {
				add(op, ChangeAdded)
			}
		}
		for _, op := range c.Before {
			if !slices.Contains(c.After, op) {
				add(op, ChangeRemoved)
			}
		}
	}
	return out
}

// MaxLabel is the longest a node label reads, in characters (HR-550).
const MaxLabel = 200

// PlainLabel makes a name a node label: plain text with no control or
// format characters and no markup delimiters, at most MaxLabel characters.
func PlainLabel(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case n == MaxLabel:
			return strings.TrimSpace(b.String())
		case r == '<' || r == '>' || r == unicode.ReplacementChar:
			continue
		case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Co, r), unicode.Is(unicode.Cs, r):
			continue
		case unicode.IsControl(r):
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
