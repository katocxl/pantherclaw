// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the case model (G0 M10 D19; F237, F244, F249, F251,
// F571, F299). A case is what investigators know about an action, a run or
// an alert, kept as an append-only list of entries (HR-245): facts with
// their evidence, hypotheses with confidence and alternatives, questions
// with an owner, answers, notes, impact, links, owner and state changes. A
// later entry may supersede an earlier one; nothing is changed in place.
//
// Each entry is one canonical JSON body. The database derives its columns
// from that body, chains it onto the case's head
// (entry_hash = sha256(prev_hash || body)) and requires the same body as a
// reflex.case ledger entry, so every entry is also in the org's evidence
// chain. The closure rules are enforced in SQL (HR-246); Validate only
// refuses what can never be stored.
package domain

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// LedgerKind is the ledger kind of every case entry (D6).
const LedgerKind = "reflex.case"

// BodyVersion is the version of the canonical entry body.
const BodyVersion = 1

// Bounds of a case and its entries (migration 00122).
const (
	MaxTitle        = 200
	MaxText         = 4000
	MaxReason       = 1000
	MaxEvidence     = 32
	MaxAlternatives = 8
	MaxAlternative  = 500
	MaxBodyBytes    = 8192
	MaxRefID        = 256
)

// State of a case. CONTAINED is the operational close; CLOSED is final.
type State string

// States.
const (
	StateOpen      State = "OPEN"
	StateContained State = "CONTAINED"
	StateClosed    State = "CLOSED"
)

// Kind of a case entry.
type Kind string

// Entry kinds.
const (
	KindFact       Kind = "FACT"
	KindHypothesis Kind = "HYPOTHESIS"
	KindQuestion   Kind = "QUESTION"
	KindAnswer     Kind = "ANSWER"
	KindNote       Kind = "NOTE"
	KindImpact     Kind = "IMPACT"
	KindLink       Kind = "LINK"
	KindOwner      Kind = "OWNER"
	KindState      Kind = "STATE"
	// KindExternal records a change made in an outside ticket system that
	// PantherClaw did not apply (G0 M20 D255, HR-528). Only the ticket sync
	// actor writes it (author type system); it carries a text and moves
	// nothing, and may land on a closed case.
	KindExternal Kind = "EXTERNAL"
)

// Kinds lists every entry kind.
var Kinds = []Kind{KindFact, KindHypothesis, KindQuestion, KindAnswer, KindNote, KindImpact, KindLink, KindOwner, KindState, KindExternal}

// Basis says how a fact or hypothesis is known (F648).
type Basis = reflexdomain.Basis

// Bases.
const (
	BasisObserved   = reflexdomain.BasisObserved
	BasisRuleMatch  = reflexdomain.BasisRuleMatch
	BasisInferred   = reflexdomain.BasisInferred
	BasisHypothesis = reflexdomain.BasisHypothesis
)

// Confidence of a hypothesis.
type Confidence string

// Confidences.
const (
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
)

// Disposition of a closed case.
type Disposition string

// Dispositions.
const (
	DispositionTruePositive  Disposition = "TRUE_POSITIVE"
	DispositionBenign        Disposition = "BENIGN"
	DispositionFalsePositive Disposition = "FALSE_POSITIVE"
	DispositionInconclusive  Disposition = "INCONCLUSIVE"
)

// Impact of a closed case.
type Impact string

// Impacts.
const (
	ImpactConfirmed            Impact = "CONFIRMED"
	ImpactExplicitlyUnresolved Impact = "EXPLICITLY_UNRESOLVED"
	ImpactNoneFound            Impact = "NONE_FOUND"
)

// ImpactKind of an IMPACT entry: what was observed, or what was possible
// (F244, F561).
type ImpactKind string

// Impact kinds.
const (
	ImpactObserved  ImpactKind = "OBSERVED"
	ImpactPotential ImpactKind = "POTENTIAL"
)

// OwnerRole of an OWNER entry.
type OwnerRole string

// Owner roles: the case owner, or the person who owns the questions that
// stay open after containment or closure (F571).
const (
	RoleOwner    OwnerRole = "OWNER"
	RoleFollowUp OwnerRole = "FOLLOW_UP"
)

// Evidence ref kinds (reflexdomain.EvidenceRef, D1).
const (
	EvidenceLedger      = reflexdomain.EvidenceLedger
	EvidenceTransaction = reflexdomain.EvidenceTransaction
	EvidenceRun         = reflexdomain.EvidenceRun
	EvidenceReceipt     = reflexdomain.EvidenceReceipt
	EvidenceCaseEntry   = reflexdomain.EvidenceCaseEntry
)

// RefResponseAction is the LINK kind of a containment action; the closure
// rules read its status (HR-246).
const RefResponseAction = "response_action"

// Link kinds: the reflexdomain subject types plus response actions and
// ledger entries.
var linkKinds = map[string]bool{
	"agent": true, "instance": true, "run": true, "transaction": true, "grant": true, "connection": true,
	"credential": true, "gateway": true, "package": true, "user": true, "service_account": true, "resource": true,
	"policy_version": true, "alert": true, "incident": true, "case": true, "finding": true,
	RefResponseAction: true, "ledger": true,
}

// Sources a case may come from (reflexdomain Signal sources, or a person).
var sources = map[string]bool{
	"detection": true, "response": true, "siem": true, "signals": true, "coverage": true, "system": true, "manual": true,
}

// ErrInvalid is wrapped by every validation error.
var ErrInvalid = errors.New("invalid case entry")

// EvidenceRef points at recorded evidence (reflexdomain.EvidenceRef).
type EvidenceRef = reflexdomain.EvidenceRef

// Ref is what a LINK entry links.
type Ref struct {
	Kind string
	ID   string
}

// Author is who wrote an entry (a ledger actor).
type Author struct {
	Type string
	ID   string
}

// Draft is an entry before it is numbered and chained. Only the fields of
// its kind may be set.
type Draft struct {
	Kind         Kind
	Text         string
	Basis        Basis
	Evidence     []EvidenceRef
	Confidence   Confidence
	Alternatives []string
	Question     *ids.UUID
	Unresolved   bool
	Owner        *ids.UUID
	OwnerRole    OwnerRole
	Impact       ImpactKind
	Ref          *Ref
	// STATE entries.
	State               State
	NoContainmentNeeded bool
	Disposition         Disposition
	CaseImpact          Impact
	// Reason of a STATE or LINK entry.
	Reason     string
	Supersedes *ids.UUID
}

// Entry is a stored entry.
type Entry struct {
	Draft
	Case, ID, LedgerEntry ids.UUID
	Seq                   int64
	Author                Author
	Body                  []byte
	PrevHash, Hash        []byte
	Created               time.Time
}

// Case is a stored case.
type Case struct {
	Org                  ids.OrgID
	ID                   ids.UUID
	Title, Source        string
	OpenedBy             Author
	Alert, Incident      *ids.UUID
	State                State
	Owner, FollowUpOwner *ids.UUID
	Disposition          Disposition
	Impact               Impact
	HeadSeq              int64
	HeadHash             []byte
	Created, Updated     time.Time
	OperationalClosed    *time.Time
	Closed               *time.Time
}

// NewCase is what opening a case needs.
type NewCase struct {
	Title, Source   string
	OpenedBy        Author
	Alert, Incident *ids.UUID
}

// Validate refuses a case that can never be stored.
func (n NewCase) Validate() error {
	t := strings.TrimSpace(n.Title)
	switch {
	case t == "" || utf8.RuneCountInString(n.Title) > MaxTitle:
		return fmt.Errorf("%w: a title of 1 to %d characters", ErrInvalid, MaxTitle)
	case !sources[n.Source]:
		return fmt.Errorf("%w: unknown source %q", ErrInvalid, n.Source)
	}
	return n.OpenedBy.validate()
}

func (a Author) validate() error {
	if a.Type == "" || len(a.Type) > 32 || a.ID == "" || len(a.ID) > 256 {
		return fmt.Errorf("%w: author type (1..32) and id (1..256) are required", ErrInvalid)
	}
	return nil
}

// GenesisHash is a case's head before its first entry.
func GenesisHash(c ids.UUID) []byte {
	h := sha256.Sum256([]byte("pantherclaw/case/v1/" + c.String()))
	return h[:]
}

// ChainHash is an entry's hash: sha256(prev || body).
func ChainHash(prev, body []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(body)
	return h.Sum(nil)
}

func textOK(s string, maxRunes int) bool {
	return strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= maxRunes
}

// Validate refuses a draft that can never be stored. The closure rules and
// the existence of evidence and questions are checked by the database.
func (d Draft) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
	}
	needsText := map[Kind]bool{KindFact: true, KindHypothesis: true, KindQuestion: true, KindAnswer: true, KindNote: true, KindImpact: true, KindExternal: true}
	switch {
	case needsText[d.Kind] && !textOK(d.Text, MaxText):
		return bad("a %s needs a text of 1 to %d characters", d.Kind, MaxText)
	case !needsText[d.Kind] && d.Text != "":
		return bad("a %s has no text", d.Kind)
	case len(d.Evidence) > 0 && d.Kind != KindFact && d.Kind != KindImpact:
		return bad("only facts and impact carry evidence")
	case len(d.Evidence) > MaxEvidence:
		return bad("at most %d evidence refs", MaxEvidence)
	case d.Basis != "" && d.Kind != KindFact && d.Kind != KindHypothesis:
		return bad("only facts and hypotheses have a basis")
	case (d.Confidence != "" || len(d.Alternatives) > 0) && d.Kind != KindHypothesis:
		return bad("only hypotheses have confidence and alternatives")
	case (d.Question != nil || d.Unresolved) && d.Kind != KindAnswer:
		return bad("only answers refer to a question")
	case d.Owner != nil && d.Kind != KindQuestion && d.Kind != KindOwner:
		return bad("only questions and owner entries name an owner")
	case d.OwnerRole != "" && d.Kind != KindOwner:
		return bad("only owner entries have a role")
	case d.Impact != "" && d.Kind != KindImpact:
		return bad("only impact entries have an impact kind")
	case d.Ref != nil && d.Kind != KindLink:
		return bad("only links have a ref")
	case (d.State != "" || d.NoContainmentNeeded || d.Disposition != "" || d.CaseImpact != "") && d.Kind != KindState:
		return bad("only state entries move the case")
	case d.Reason != "" && d.Kind != KindState && d.Kind != KindLink:
		return bad("only state and link entries have a reason")
	case d.Reason != "" && !textOK(d.Reason, MaxReason):
		return bad("a reason of 1 to %d characters", MaxReason)
	case d.Supersedes != nil && (d.Kind == KindState || d.Kind == KindOwner):
		return bad("state and owner entries are never superseded")
	}
	for _, e := range d.Evidence {
		switch e.Kind {
		case EvidenceLedger, EvidenceTransaction, EvidenceRun, EvidenceReceipt, EvidenceCaseEntry:
		default:
			return bad("unknown evidence kind %q", e.Kind)
		}
		if e.ID.IsZero() {
			return bad("an evidence ref needs an id")
		}
	}
	switch d.Kind {
	case KindFact:
		if len(d.Evidence) == 0 {
			return bad("a fact needs at least one evidence ref")
		}
		if d.Basis != BasisObserved && d.Basis != BasisRuleMatch && d.Basis != BasisInferred {
			return bad("a fact is observed, a rule match or inferred")
		}
	case KindHypothesis:
		if d.Basis != BasisHypothesis {
			return bad("a hypothesis has basis HYPOTHESIS")
		}
		switch d.Confidence {
		case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		default:
			return bad("a hypothesis has a confidence")
		}
		if len(d.Alternatives) > MaxAlternatives {
			return bad("at most %d alternatives", MaxAlternatives)
		}
		for _, a := range d.Alternatives {
			if !textOK(a, MaxAlternative) {
				return bad("an alternative of 1 to %d characters", MaxAlternative)
			}
		}
	case KindAnswer:
		if d.Question == nil {
			return bad("an answer refers to a question")
		}
	case KindImpact:
		if d.Impact != ImpactObserved && d.Impact != ImpactPotential {
			return bad("impact is observed or potential")
		}
	case KindLink:
		if d.Supersedes != nil && d.Reason == "" {
			return bad("a link that supersedes another says why")
		}
		if d.Ref == nil || !linkKinds[d.Ref.Kind] || d.Ref.ID == "" || len(d.Ref.ID) > MaxRefID {
			return bad("a link names a known kind and an id")
		}
		if uuidRefKinds[d.Ref.Kind] {
			if _, err := ids.ParseUUID(d.Ref.ID); err != nil {
				return bad("a %s link names a UUID", d.Ref.Kind)
			}
		}
	case KindOwner:
		switch {
		case d.OwnerRole != RoleOwner && d.OwnerRole != RoleFollowUp:
			return bad("an owner entry is for the owner or the follow-up owner")
		case d.Owner == nil:
			return bad("an owner entry names the owner")
		}
	case KindState:
		switch d.State {
		case StateOpen, StateContained:
			if d.Disposition != "" || d.CaseImpact != "" {
				return bad("only closing sets a disposition and an impact")
			}
		case StateClosed:
			switch d.Disposition {
			case DispositionTruePositive, DispositionBenign, DispositionFalsePositive, DispositionInconclusive:
			default:
				return bad("closing needs a disposition")
			}
			switch d.CaseImpact {
			case ImpactConfirmed, ImpactExplicitlyUnresolved, ImpactNoneFound:
			default:
				return bad("closing needs an impact")
			}
		default:
			return bad("unknown state %q", d.State)
		}
		if d.NoContainmentNeeded && (d.State == StateOpen || d.Reason == "") {
			return bad("no containment needed is given with a reason when containing or closing")
		}
	case KindQuestion, KindNote, KindExternal:
	default:
		return bad("unknown kind %q", d.Kind)
	}
	return nil
}

type bodyRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type bodyAuthor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// body is the canonical entry body; migration 00122 reads these names.
type body struct {
	V                   int         `json:"v"`
	Case                string      `json:"case"`
	ID                  string      `json:"id"`
	Seq                 int64       `json:"seq"`
	Kind                Kind        `json:"kind"`
	Author              bodyAuthor  `json:"author"`
	Text                string      `json:"text,omitempty"`
	Basis               Basis       `json:"basis,omitempty"`
	Evidence            []bodyRef   `json:"evidence,omitempty"`
	Confidence          Confidence  `json:"confidence,omitempty"`
	Alternatives        []string    `json:"alternatives,omitempty"`
	Question            string      `json:"question,omitempty"`
	Unresolved          bool        `json:"unresolved,omitzero"`
	Owner               string      `json:"owner,omitempty"`
	OwnerRole           OwnerRole   `json:"owner_role,omitempty"`
	Impact              ImpactKind  `json:"impact,omitempty"`
	Ref                 *bodyRef    `json:"ref,omitzero"`
	State               State       `json:"state,omitempty"`
	NoContainmentNeeded bool        `json:"no_containment_needed,omitzero"`
	Disposition         Disposition `json:"disposition,omitempty"`
	CaseImpact          Impact      `json:"case_impact,omitempty"`
	Reason              string      `json:"reason,omitempty"`
	Supersedes          string      `json:"supersedes,omitempty"`
}

func idString(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// Body returns the canonical JSON of d as entry seq of case c, written by
// author. It validates d first.
func (d Draft) Body(c, id ids.UUID, seq int64, author Author) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if err := author.validate(); err != nil {
		return nil, err
	}
	if d.Kind == KindExternal && author.Type != "system" {
		return nil, fmt.Errorf("%w: only the ticket sync writes external changes", ErrInvalid)
	}
	if seq < 1 {
		return nil, fmt.Errorf("%w: entries are numbered from 1", ErrInvalid)
	}
	b := body{
		V: BodyVersion, Case: c.String(), ID: id.String(), Seq: seq, Kind: d.Kind,
		Author: bodyAuthor(author), Text: d.Text, Basis: d.Basis, Confidence: d.Confidence,
		Alternatives: d.Alternatives, Question: idString(d.Question), Unresolved: d.Unresolved,
		Owner: idString(d.Owner), OwnerRole: d.OwnerRole, Impact: d.Impact, State: d.State,
		NoContainmentNeeded: d.NoContainmentNeeded, Disposition: d.Disposition, CaseImpact: d.CaseImpact,
		Reason: d.Reason, Supersedes: idString(d.Supersedes),
	}
	for _, e := range d.Evidence {
		b.Evidence = append(b.Evidence, bodyRef{e.Kind, e.ID.String()})
	}
	if d.Ref != nil {
		b.Ref = &bodyRef{d.Ref.Kind, canonicalRef(*d.Ref)}
	}
	out, err := evdomain.CanonicalBody(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if len(out) > MaxBodyBytes {
		return nil, fmt.Errorf("%w: an entry body is at most %d bytes", ErrInvalid, MaxBodyBytes)
	}
	return out, nil
}

// uuidRefKinds are the link kinds whose ids are UUIDs: they are stored in
// canonical (lower-case) form, so the database's joins and the case's read
// scope see the same subject the permission check saw (D70).
var uuidRefKinds = map[string]bool{
	"agent": true, "run": true, "transaction": true, RefResponseAction: true, "ledger": true,
}

// canonicalRef is r's id as stored: canonical for UUID kinds.
func canonicalRef(r Ref) string {
	if uuidRefKinds[r.Kind] {
		if u, err := ids.ParseUUID(r.ID); err == nil {
			return u.String()
		}
	}
	return r.ID
}
