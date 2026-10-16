// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"time"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Port errors. Adapters map them to API errors.
var (
	// ErrConcurrency: the automation already runs its ceiling's
	// concurrency of executions (Starter).
	ErrConcurrency = errors.New("automation: concurrency limit reached")
	// ErrNotActive: the automation is not ACTIVE with that version enabled
	// (Starter).
	ErrNotActive = errors.New("automation: not active")
)

// MaxAncestry and MaxDepth bound trigger ancestry (D23, HR-278): depth ≥
// MaxDepth is refused. The ports that take a transaction are in
// internal/automations/ports.
const (
	MaxAncestry = 8
	MaxDepth    = 4
)

// TriggerRef is an accepted trigger handed to the engine (D11).
type TriggerRef struct {
	ID         ids.UUID
	Org        ids.OrgID
	Automation ids.UUID
	Version    ids.UUID
	Kind       TriggerKind
	Mode       Mode
	Params     map[string]Value
	Subjects   []reflexdomain.Subject
	Evidence   []reflexdomain.EvidenceRef
	// Root is the first trigger of the chain (itself when Depth is 0);
	// Ancestry lists the automations upstream of this one.
	Root       ids.UUID
	Ancestry   []ids.UUID
	Depth      int
	OccurredAt time.Time
}

// PauseSelector chooses the automations a Pause affects.
type PauseSelector struct {
	All                bool
	Automations        []ids.UUID
	AffectingAgent     *ids.UUID
	AffectingOperation string
}

// DeliveryKind is what a delivery carries (D22).
type DeliveryKind string

// Delivery kinds (also destination purposes).
const (
	DeliveryLaunch DeliveryKind = "LAUNCH"
	DeliveryDigest DeliveryKind = "DIGEST"
	DeliveryNotice DeliveryKind = "NOTICE"
)

// Delivery is one webhook to an automation destination.
type Delivery struct {
	Org         ids.OrgID
	Destination ids.UUID
	Execution   ids.UUID
	Kind        DeliveryKind
	Body        []byte
}

// DeliveryState is a delivery's state.
type DeliveryState string

// Delivery states.
const (
	DeliveryPending   DeliveryState = "PENDING"
	DeliveryDelivered DeliveryState = "DELIVERED"
	DeliveryFailed    DeliveryState = "FAILED"
)

// DeliveryStatus is a delivery's current state.
type DeliveryStatus struct {
	ID          ids.UUID
	State       DeliveryState
	Attempts    int
	LastStatus  int
	LastError   string
	DeliveredAt time.Time
}

// CeilingCheck is what CeilingChecker needs about a ceiling.
type CeilingCheck struct {
	Org        ids.OrgID
	Automation ids.UUID
	Ceiling    ids.UUID
	Approvers  []ids.UUID
	// Agents and Kinds are kept for callers built against core-A; Check
	// reads what the approvers must hold from the ceiling's version (its
	// ceiling agents, authority.revocable and evidence scopes, D65, D85).
	Agents []ids.UUID
	Kinds  []string
}

// ExecutionView is what a step sees of its execution.
type ExecutionView struct {
	ID             ids.UUID
	Automation     ids.UUID
	AutomationName string
	Version        ids.UUID
	Trigger        TriggerRef
	Mode           Mode
	// Ceiling is the execution's authority row: every enabling, SHADOW
	// included, creates one (D54).
	Ceiling        ids.UUID
	ServiceAccount ids.UUID
	Owner          ids.UUID
	Principal      gdomain.Principal
	Confirmers     []ids.UUID
	StartedAt      time.Time
	DeadlineAt     time.Time
}

// StepContext is one step attempt's input (D11).
type StepContext struct {
	Org       ids.OrgID
	Execution ExecutionView
	Def       *Definition
	Spec      StepSpec
	// With is the decoded `with` of Spec, templates already rendered.
	With    any
	Index   int
	Attempt int
	Params  map[string]Value
	// Outputs are earlier steps' outputs by step id.
	Outputs map[string]map[string]string
	Mode    Mode
	Now     time.Time
}

// Output bounds (D11).
const (
	MaxOutputKeys  = 16
	MaxOutputValue = 512
)

// StepResult is one step attempt's outcome (D11). Reason is a stable code.
type StepResult struct {
	State  StepState
	Output map[string]string
	Refs   []reflexdomain.EvidenceRef
	Effect Effect
	WakeAt time.Time
	Reason string
}

// Valid reports whether the output fits its bounds.
func (r StepResult) Valid() bool {
	if len(r.Output) > MaxOutputKeys {
		return false
	}
	for k, v := range r.Output {
		if len(k) > 64 || len(v) > MaxOutputValue {
			return false
		}
	}
	return true
}
