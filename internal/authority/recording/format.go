// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package recording keeps the inputs of one evaluation for decision replay
// (G0 M7 design decision 11, founder decision 5, F504–F508). A Recorder
// wraps the pipeline's Reader and keeps the result of every read; a Reader
// serves a recording back to the pipeline, so a replay sees exactly what the
// evaluation saw. The definition and the policy are kept by reference (the
// definition's digest, the policy's version with the fact types and limits
// it was compiled with); everything else by value. The format is versioned
// and its JSON deterministic, and a row holds it compressed and sealed with
// the org's evaluation_inputs key (HR-062).
package recording

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
)

// FormatVersion is the version of the format this code writes and reads.
const FormatVersion = 1

// Outcomes of a read other than a result. A storage error is kept as a
// kind, never as its message, which may describe storage.
const (
	errNotFound = "not_found"
	errFailed   = "error"
)

// Errors of Decode.
var (
	// ErrFormat reports a recording of a format this code does not read.
	ErrFormat = errors.New("recording: unsupported format")
	// ErrInvalid reports a recording that does not decode.
	ErrInvalid = errors.New("recording: invalid")
)

// Recording is everything one evaluation read. Reads lists each read with
// its arguments, in the order the pipeline made them.
type Recording struct {
	Format   int     `json:"format"`
	Pipeline int     `json:"pipeline"`
	Request  Request `json:"request"`
	Reads    Reads   `json:"reads"`
	// Tampered is set when the finalization answered before the pipeline
	// ran, because the run and action ids were already used for another
	// action (HR-006); Reads is then empty.
	Tampered *Tampered `json:"tampered,omitzero"`
}

// Request is the request the pipeline decided: the canonical action, the
// identity the Authority verified, and the gateway from its certificate.
type Request struct {
	Action      jsontext.Value `json:"action"`
	Instance    string         `json:"instance"`
	Agent       string         `json:"agent"`
	Attestation int            `json:"attestation"`
	JKT         string         `json:"jkt,omitzero"`
	Gateway     string         `json:"gateway"`
}

// Tampered is what the finalization compared: the action hash stored for
// the run and action ids.
type Tampered struct {
	StoredActionHash string `json:"stored_action_hash"`
}

// Reads are the reads of one evaluation, by kind.
type Reads struct {
	Containment  *Containment  `json:"containment,omitzero"`
	Definitions  []Definition  `json:"definitions,omitzero"`
	Policy       *Policy       `json:"policy,omitzero"`
	Runs         []Run         `json:"runs,omitzero"`
	Agents       []Agent       `json:"agents,omitzero"`
	Chains       []Chain       `json:"chains,omitzero"`
	Envelopes    []Envelopes   `json:"envelopes,omitzero"`
	Facts        []Facts       `json:"facts,omitzero"`
	Usage        []Usage       `json:"usage,omitzero"`
	Claims       []Claim       `json:"claims,omitzero"`
	Connections  []Connection  `json:"connections,omitzero"`
	Holds        []Hold        `json:"holds,omitzero"`
	Variants     []Variants    `json:"variants,omitzero"`
	HoldSettings *HoldSettings `json:"hold_settings,omitzero"`
}

// Containment is the org's containment state and the database time: the
// time the evaluation decided at.
type Containment struct {
	Epoch      int64     `json:"epoch"`
	KillSwitch bool      `json:"kill_switch"`
	Now        time.Time `json:"now"`
	Err        string    `json:"err,omitzero"`
}

// Definition is a definition read: the pin asked for, and the digest and
// lifecycle state of the definition returned. The definition itself is kept
// by reference: replay loads it again by its pin.
type Definition struct {
	Pin    actionir.Definition `json:"pin"`
	Digest string              `json:"digest,omitzero"`
	State  string              `json:"state,omitzero"`
	Err    string              `json:"err,omitzero"`
}

// Policy is the published policy read, by reference: the bundle and its
// version, with the per-evaluation cost budget, the CEL limits and the fact
// types it was compiled with. None reports that no policy was published.
type Policy struct {
	None    bool              `json:"none,omitzero"`
	Ref     string            `json:"ref,omitzero"`
	Bundle  string            `json:"bundle,omitzero"`
	Version int               `json:"version,omitzero"`
	Budget  uint64            `json:"budget,omitzero"`
	Limits  Limits            `json:"limits,omitzero"`
	Catalog map[string]string `json:"catalog,omitzero"`
	Err     string            `json:"err,omitzero"`
}

// Limits are celenv.Limits.
type Limits struct {
	MaxExpressionBytes      int    `json:"max_expression_bytes,omitzero"`
	MaxCost                 uint64 `json:"max_cost,omitzero"`
	MaxComprehensionNesting int    `json:"max_comprehension_nesting,omitzero"`
	EstimatedCollectionSize uint64 `json:"estimated_collection_size,omitzero"`
}

// Run is a run read.
type Run struct {
	ID          string   `json:"id"`
	Agent       string   `json:"agent,omitzero"`
	Instance    string   `json:"instance,omitzero"`
	Launcher    string   `json:"launcher,omitzero"`
	Principal   string   `json:"principal,omitzero"`
	Environment string   `json:"environment,omitzero"`
	Grant       string   `json:"grant,omitzero"`
	Active      bool     `json:"active,omitzero"`
	TaskRef     string   `json:"task_ref,omitzero"`
	Ancestors   []string `json:"ancestors,omitzero"`
	Err         string   `json:"err,omitzero"`
}

// Agent is an agent read.
type Agent struct {
	ID           string `json:"id"`
	State        string `json:"state,omitzero"`
	BusinessUnit string `json:"business_unit,omitzero"`
	Team         string `json:"team,omitzero"`
	Err          string `json:"err,omitzero"`
}

// Chain is a grant chain read, root first.
type Chain struct {
	Grant  string  `json:"grant"`
	Grants []Grant `json:"grants,omitzero"`
	Err    string  `json:"err,omitzero"`
}

// Grant is a grant revision as the pipeline read it. Bounds, requirements
// and limits are in the canonical JSON the grant store keeps.
type Grant struct {
	ID              string         `json:"id"`
	Revision        int            `json:"revision"`
	State           string         `json:"state"`
	Agent           string         `json:"agent"`
	Instance        string         `json:"instance,omitzero"`
	Principal       string         `json:"principal,omitzero"`
	Environment     string         `json:"environment,omitzero"`
	TaskRef         string         `json:"task_ref,omitzero"`
	NotBefore       time.Time      `json:"not_before"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Bounds          jsontext.Value `json:"bounds"`
	Requirements    jsontext.Value `json:"requirements"`
	Limits          jsontext.Value `json:"limits"`
	DelegationDepth int            `json:"delegation_depth,omitzero"`
	MaxChildren     int            `json:"max_children,omitzero"`
	MinAttestation  int            `json:"min_attestation,omitzero"`
	Parent          string         `json:"parent,omitzero"`
	Depth           int            `json:"depth,omitzero"`
	Grantor         string         `json:"grantor,omitzero"`
	Basis           string         `json:"basis,omitzero"`
	RevisedAt       time.Time      `json:"revised_at,omitzero"`
}

// Envelopes is a guardrails read for the scopes asked for.
type Envelopes struct {
	Scopes    []Scope    `json:"scopes"`
	Envelopes []Envelope `json:"envelopes,omitzero"`
	Err       string     `json:"err,omitzero"`
}

// Scope is a guardrail scope.
type Scope struct {
	Kind      string `json:"kind"`
	ID        string `json:"id,omitzero"`
	Principal string `json:"principal,omitzero"`
}

// Envelope is a guardrail revision as the pipeline read it.
type Envelope struct {
	ID                string         `json:"id"`
	Revision          int            `json:"revision"`
	Scope             Scope          `json:"scope"`
	Name              string         `json:"name,omitzero"`
	Bounds            jsontext.Value `json:"bounds"`
	Requirements      jsontext.Value `json:"requirements"`
	Limits            jsontext.Value `json:"limits"`
	MaxDepth          *int           `json:"max_depth,omitzero"`
	MaxChildren       *int           `json:"max_children,omitzero"`
	MaxRootLifetimeNS *int64         `json:"max_root_lifetime_ns,omitzero"`
	RepeatWindowNS    *int64         `json:"repeat_window_ns,omitzero"`
	MinAttestation    int            `json:"min_attestation,omitzero"`
	ChangedBy         string         `json:"changed_by,omitzero"`
	RevisedAt         time.Time      `json:"revised_at,omitzero"`
}

// Facts is a facts read about one subject: the names asked for and the
// facts found, by name.
type Facts struct {
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	Names       []string `json:"names"`
	Facts       []Fact   `json:"facts,omitzero"`
	Err         string   `json:"err,omitzero"`
}

// Fact is one current fact; Value is the fact store's wire form.
type Fact struct {
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Value      jsontext.Value `json:"value"`
	ObservedAt time.Time      `json:"observed_at"`
	RecordedAt time.Time      `json:"recorded_at,omitzero"`
	Provider   string         `json:"provider,omitzero"`
}

// Usage is a budget and counter read: the refs of the plan asked for, and
// what is reserved and spent on the rows that exist.
type Usage struct {
	Budgets     []Ref          `json:"budgets,omitzero"`
	Counters    []Ref          `json:"counters,omitzero"`
	Accounts    []AccountUsage `json:"accounts,omitzero"`
	CounterUse  []CounterUsage `json:"counter_use,omitzero"`
	CounterRows []RowCount     `json:"counter_rows,omitzero"`
	Err         string         `json:"err,omitzero"`
}

// Ref is a budget account or counter ref.
type Ref struct {
	OwnerKind string    `json:"owner_kind"`
	OwnerID   string    `json:"owner_id"`
	OwnerRank int       `json:"owner_rank,omitzero"`
	Rule      string    `json:"rule"`
	Key       string    `json:"key"`
	Start     time.Time `json:"start"`
}

// AccountUsage is one budget account's row.
type AccountUsage struct {
	Ref           Ref     `json:"ref"`
	ID            string  `json:"id,omitzero"`
	Rank          int     `json:"rank,omitzero"`
	Currency      string  `json:"currency,omitzero"`
	Limit         *string `json:"limit,omitzero"`
	Reserved      string  `json:"reserved"`
	Spent         string  `json:"spent"`
	MaxCount      *int64  `json:"max_count,omitzero"`
	ReservedCount int64   `json:"reserved_count,omitzero"`
	SpentCount    int64   `json:"spent_count,omitzero"`
}

// CounterUsage is one counter's row.
type CounterUsage struct {
	Ref            Ref    `json:"ref"`
	ID             string `json:"id,omitzero"`
	Rank           int    `json:"rank,omitzero"`
	Max            int64  `json:"max,omitzero"`
	MaxOutstanding *int64 `json:"max_outstanding,omitzero"`
	Reserved       int64  `json:"reserved,omitzero"`
	Spent          int64  `json:"spent,omitzero"`
}

// RowCount is how many rows a counter rule and window has (T-023).
type RowCount struct {
	Ref  Ref `json:"ref"`
	Rows int `json:"rows"`
}

// Claim is a dedupe-key read (HR-007).
type Claim struct {
	Key         string     `json:"key"`
	Transaction string     `json:"transaction,omitzero"`
	State       string     `json:"state,omitzero"`
	At          *time.Time `json:"at,omitzero"`
	Err         string     `json:"err,omitzero"`
}

// Connection is a connection read with its route modes.
type Connection struct {
	ID               string            `json:"id"`
	Gateway          string            `json:"gateway,omitzero"`
	Kind             string            `json:"kind,omitzero"`
	Package          string            `json:"package,omitzero"`
	State            string            `json:"state,omitzero"`
	AccessMode       string            `json:"access_mode,omitzero"`
	DefaultMode      string            `json:"default_mode,omitzero"`
	DestinationClass string            `json:"destination_class,omitzero"`
	Modes            map[string]string `json:"modes,omitzero"`
	Err              string            `json:"err,omitzero"`
}

// Hold is the read of a transaction's latest approval request.
type Hold struct {
	Run     string       `json:"run"`
	Action  string       `json:"action"`
	Request *HoldRequest `json:"request,omitzero"`
	Err     string       `json:"err,omitzero"`
}

// HoldRequest is pipeline.HoldRequest.
type HoldRequest struct {
	ID               string                 `json:"id"`
	State            string                 `json:"state"`
	EndReason        string                 `json:"end_reason,omitzero"`
	Binding          string                 `json:"binding"`
	Deadline         time.Time              `json:"deadline"`
	EvidenceDeadline *time.Time             `json:"evidence_deadline,omitzero"`
	ConsumeBy        *time.Time             `json:"consume_by,omitzero"`
	Variants         []apdomain.VariantLine `json:"variants,omitzero"`
	Context          []apdomain.ContextLine `json:"context,omitzero"`
	Question         string                 `json:"question,omitzero"`
	ProposedParams   []byte                 `json:"proposed_params,omitzero"`
}

// Variants is the read of earlier requests with the same variant key and of
// recent approved requests for the same operation and target (HR-037).
type Variants struct {
	Key       string                 `json:"key"`
	Operation string                 `json:"operation"`
	Target    actionir.Target        `json:"target"`
	Now       time.Time              `json:"now"`
	Variants  []apdomain.VariantLine `json:"variants,omitzero"`
	Context   []apdomain.ContextLine `json:"context,omitzero"`
	Err       string                 `json:"err,omitzero"`
}

// HoldSettings is the read of the org's hold settings.
type HoldSettings struct {
	HoldDeadlineNS int64  `json:"hold_deadline_ns,omitzero"`
	Err            string `json:"err,omitzero"`
}

// Encode returns the recording's deterministic JSON: members in a fixed
// order and maps sorted by key, so the same reads give the same bytes.
func Encode(r *Recording) ([]byte, error) {
	return json.Marshal(r, json.Deterministic(true))
}

// Decode strictly decodes a recording (duplicate or unknown members are
// refused) and checks that every value converts back. A recording of
// another format is ErrFormat.
func Decode(raw []byte) (*Recording, error) {
	var head struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err) //nolint:errorlint // one wrapped error
	}
	if head.Format != FormatVersion {
		return nil, fmt.Errorf("%w: %d", ErrFormat, head.Format)
	}
	var r Recording
	if err := json.Unmarshal(raw, &r, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err) //nolint:errorlint // one wrapped error
	}
	if err := r.check(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err) //nolint:errorlint // one wrapped error
	}
	return &r, nil
}

// check converts every recorded value back, so a recording that decodes
// serves every read it holds.
func (r *Recording) check() error {
	if r.Pipeline < 1 {
		return errors.New("no pipeline version")
	}
	if _, err := actionir.Parse(bytes.Clone(r.Request.Action)); err != nil {
		return fmt.Errorf("action: %w", err)
	}
	if t := r.Tampered; t != nil && (len(t.StoredActionHash) != 64 || r.Reads.any()) {
		return errors.New("tampered recording")
	}
	if _, err := r.identity(); err != nil {
		return err
	}
	return r.Reads.check()
}
