// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

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
// MaxDepth is refused.
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

// Starter starts an execution for an accepted trigger in the caller's
// transaction (engine, D24). It returns the execution id, or ErrConcurrency
// or ErrNotActive.
type Starter interface {
	Start(ctx context.Context, tx pgx.Tx, t TriggerRef) (ids.UUID, error)
}

// TriggerActivator materializes and retires an automation's triggers
// (triggers, D17, D23).
type TriggerActivator interface {
	Activate(ctx context.Context, tx pgx.Tx, automation, version ids.UUID) error
	Deactivate(ctx context.Context, tx pgx.Tx, automation ids.UUID, policy PausedTriggers) error
	// Resume replays unexpired queued triggers through Starter (which
	// revalidates); never a missed schedule occurrence whose policy is SKIP.
	Resume(ctx context.Context, tx pgx.Tx, automation ids.UUID) (replayed int, err error)
}

// PauseSelector chooses the automations a Pause affects.
type PauseSelector struct {
	All                bool
	Automations        []ids.UUID
	AffectingAgent     *ids.UUID
	AffectingOperation string
}

// Pauser pauses ACTIVE automations in the caller's transaction and returns
// the ones it paused (core, D14, D31).
type Pauser interface {
	Pause(ctx context.Context, tx pgx.Tx, org ids.OrgID, sel PauseSelector, reason PauseReason) ([]ids.UUID, error)
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

// Deliverer queues and reports webhook deliveries (triggers, D22).
type Deliverer interface {
	Deliver(ctx context.Context, tx pgx.Tx, d Delivery) (ids.UUID, error)
	Status(ctx context.Context, tx pgx.Tx, id ids.UUID) (DeliveryStatus, error)
}

// TestGate reports whether a version passed its scenario tests for this
// digest (assurance, D34). A nil TestGate passes nothing.
type TestGate interface {
	Passed(ctx context.Context, tx pgx.Tx, version ids.UUID, digest []byte) (run ids.UUID, ok bool, err error)
}

// RolloutEvidence reports whether a COHORT stage may widen to FULL
// (assurance, D36). A nil RolloutEvidence verifies nothing.
type RolloutEvidence interface {
	Verified(ctx context.Context, tx pgx.Tx, automation, version ids.UUID) (bool, []string, error)
}

// CeilingCheck is what CeilingChecker needs about a ceiling.
type CeilingCheck struct {
	Org        ids.OrgID
	Automation ids.UUID
	Ceiling    ids.UUID
	Approvers  []ids.UUID
	// Agents are the ceiling agents whose paths the approvers must still
	// cover; Kinds the step kinds the version uses.
	Agents []ids.UUID
	Kinds  []string
}

// CeilingChecker revalidates a ceiling's approvers: each active, still
// holding automation.publish and every confirmer permission at every scope
// it covers, and not compromised (core, D9, HR-273). It returns a stable
// reason when the ceiling no longer holds.
type CeilingChecker interface {
	Check(ctx context.Context, tx pgx.Tx, c CeilingCheck) (ok bool, reason string, err error)
}

// CompromiseChecker reports whether a person is marked compromised
// (protect, D43). A nil CompromiseChecker reports nobody.
type CompromiseChecker interface {
	Compromised(ctx context.Context, tx pgx.Tx, org ids.OrgID, user ids.UUID) (bool, error)
}

// ExecutionView is what a step sees of its execution.
type ExecutionView struct {
	ID             ids.UUID
	Automation     ids.UUID
	AutomationName string
	Version        ids.UUID
	Trigger        TriggerRef
	Mode           Mode
	Ceiling        ids.UUID // zero when the version has none
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

// Step is one catalogue kind's runtime (D11). Run starts an attempt, Poll
// re-checks a WAITING one, Preview returns the would-be result without
// effects (SHADOW, TEST, simulation; HR-288).
type Step interface {
	Kind() string
	Run(ctx context.Context, tx pgx.Tx, sc StepContext) (StepResult, error)
	Poll(ctx context.Context, tx pgx.Tx, sc StepContext) (StepResult, error)
	Preview(ctx context.Context, tx pgx.Tx, sc StepContext) (StepResult, error)
}

// StepRegistry maps catalogue kinds to their runtimes; built in server
// wiring from the generic and security steps.
type StepRegistry map[string]Step
