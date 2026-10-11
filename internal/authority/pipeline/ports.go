// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pipeline is the Transaction Authority's decision pipeline, steps
// 1–8 of ARCHITECTURE §6.1 (G0 M4 part 2): scope, identity, containment,
// authority, exact meaning, current facts, boundaries and requirements. It
// reads through one port, composes every step deterministically (the
// strictest result wins and a known prohibition is reported as DENY even
// when evidence is also missing), and returns the checklist, the decision
// basis and the reservation plan that the finalization (step 9) binds.
package pipeline

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// ErrNotFound is returned by the Reader for a record that does not exist in
// the org.
var ErrNotFound = errors.New("pipeline: not found")

// Identity is the workload identity the Authority verified itself (M3,
// HR-021): never a value the gateway or the agent asserted.
type Identity struct {
	InstanceID       ids.UUID
	AgentID          ids.UUID
	AttestationLevel int
	// JKT is the thumbprint of the key that signed the request; approvals
	// bind it (HR-030).
	JKT string
}

// Request is one action to decide. Gateway is the id of the gateway asking,
// from its certificate (HR-020): a connection the action names must be one
// it serves.
type Request struct {
	Org      ids.OrgID
	Action   actionir.Parsed
	Identity Identity
	Gateway  string
}

// Pinned is an org's pinned definition with its lifecycle state.
type Pinned struct {
	Definition *defs.Definition
	State      defs.State
}

// Policy is an org's published, compiled policy.
type Policy struct {
	Compiled *papp.Compiled
	// Version names the bundle as id@version for the decision basis.
	Version string
	// Budget is the tenant's CEL cost budget per evaluation (HR-043).
	Budget uint64
}

// Run is what the pipeline needs to know about a run (M3).
type Run struct {
	AgentID       ids.UUID
	InstanceID    ids.UUID
	Launcher      gdomain.Principal
	Principal     gdomain.Principal
	EnvironmentID ids.UUID
	GrantID       gdomain.GrantID
	Active        bool
	// TaskRef is the run's UNTRUSTED task label, shown to approvers only in
	// the untrusted block (HR-034).
	TaskRef string
	// Ancestors are the launchers and principals of every ancestor run,
	// nearest first: none of them may approve the run's actions (HR-036).
	Ancestors []gdomain.Principal
}

// HoldRequest is the latest approval request of a transaction, as step 8
// needs it (G0 M5 part 2).
type HoldRequest struct {
	ID               ids.UUID
	State            apdomain.State
	EndReason        string
	Binding          [32]byte
	Deadline         time.Time
	EvidenceDeadline *time.Time
	ConsumeBy        *time.Time
	// Variants and Context are what its display was rendered with, so a
	// resubmission renders the same display.
	Variants []apdomain.VariantLine
	Context  []apdomain.ContextLine
	// Question is the open evidence question (EVIDENCE_REQUESTED), and
	// ProposedParams the narrower parameters a decider proposed.
	Question       string
	ProposedParams []byte
}

// HoldSettings are an org's settings the hold path applies; zero values
// mean the defaults (decisions 6 and 7).
type HoldSettings struct {
	HoldDeadline time.Duration
}

// Agent is what the pipeline needs to know about an agent (M3).
type Agent struct {
	State          string
	BusinessUnitID ids.UUID
	TeamID         ids.UUID
}

// Containment is the org's containment state and the database time.
type Containment struct {
	Epoch      int64
	KillSwitch bool
	Now        time.Time
}

// Usage is what is already reserved and spent on budget accounts and
// counters. A row that does not exist yet has no usage.
type Usage struct {
	Accounts map[bdomain.Ref]bdomain.Account
	Counters map[bdomain.Ref]bdomain.Counter
	// CounterRows counts the rows of each counter rule and window, for the
	// cardinality cap (T-023); keyed by the ref with a zero key.
	CounterRows map[bdomain.Ref]int
}

// Rows are the ids of existing budget account and counter rows, by ref.
type Rows struct {
	Accounts map[bdomain.Ref]ids.UUID
	Counters map[bdomain.Ref]ids.UUID
}

// ClaimState is the state of an earlier attempt on a dedupe key.
type ClaimState string

// Claim states: HELD while its permit is issued, dispatching or UNKNOWN;
// SUCCEEDED once accepted; RELEASED when it expired unused or failed.
const (
	ClaimHeld      ClaimState = "HELD"
	ClaimSucceeded ClaimState = "SUCCEEDED"
	ClaimReleased  ClaimState = "RELEASED"
)

// Claim is the latest attempt on a dedupe key (HR-007).
type Claim struct {
	TransactionID ids.UUID
	State         ClaimState
	At            time.Time
}

// Dispatch modes of a connection's routes (PN-013, HR-184).
const (
	ModeEnforce = "enforce"
	ModeMonitor = "monitor"
)

// Connection is a registered connection as the Authority checks it (G0 M6,
// PAP-1 §6): the gateway that serves it, its package, its state, how
// credentials reach the target, and each route's mode.
type Connection struct {
	ID          ids.UUID
	Gateway     ids.UUID
	Kind        string // http, mcp or local
	Package     string
	State       string // ACTIVE, QUARANTINED or RETIRED
	AccessMode  string
	DefaultMode string
	// DestinationClass is where the connection sends data: "public" or
	// "internal" (HR-079). Policies see it as action.destination_class.
	DestinationClass string
	// Modes are the explicit route modes; other routes take DefaultMode.
	Modes map[string]string
	// Reads are the read operations the gateway can make through the
	// connection for a verifier: the HTTP GET reads of the package version
	// the org pinned for it (HR-190, G0 M7 design decision 2), sorted.
	Reads []string
}

// Mode is a route's mode on the connection.
func (c Connection) Mode(route string) string {
	if m, ok := c.Modes[route]; ok {
		return m
	}
	return c.DefaultMode
}

// Reader is every read the pipeline makes. Implementations return
// ErrNotFound for missing records; any other error is treated as missing
// evidence (CANNOT_AUTHORIZE), never as a pass.
type Reader interface {
	Containment(ctx context.Context, org ids.OrgID) (Containment, error)
	Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (Pinned, error)
	// Policy returns nil when the org has published no policy.
	Policy(ctx context.Context, org ids.OrgID) (*Policy, error)
	Run(ctx context.Context, org ids.OrgID, id ids.UUID) (Run, error)
	Agent(ctx context.Context, org ids.OrgID, id ids.UUID) (Agent, error)
	// Chain returns the grant and its ancestors, root first.
	Chain(ctx context.Context, org ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error)
	Envelopes(ctx context.Context, org ids.OrgID, scopes []gdomain.Scope) ([]gdomain.Envelope, error)
	// Facts returns the current facts of active providers about one
	// subject, by name.
	Facts(ctx context.Context, org ids.OrgID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error)
	Usage(ctx context.Context, org ids.OrgID, plan gdomain.Plan) (Usage, error)
	// Claim returns the latest attempt on a dedupe key, or nil.
	Claim(ctx context.Context, org ids.OrgID, key string) (*Claim, error)
	// Connection returns a connection with its route modes.
	Connection(ctx context.Context, org ids.OrgID, id ids.UUID) (Connection, error)
	// Hold returns the latest approval request of the transaction for
	// (run, action), or nil (G0 M5 part 2).
	Hold(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*HoldRequest, error)
	// Variants returns the earlier requests with the same variant key
	// (HR-037) and up to five requests for the same operation and target
	// approved in the 30 days before now, newest first.
	Variants(ctx context.Context, org ids.OrgID, key [32]byte, operation string, target actionir.Target, now time.Time) (
		[]apdomain.VariantLine, []apdomain.ContextLine, error)
	// HoldSettings returns the org's hold settings.
	HoldSettings(ctx context.Context, org ids.OrgID) (HoldSettings, error)
}

// Snapshotter is a Reader that can serve every read of one evaluation from
// one snapshot of the org: one read-only transaction instead of one per
// read, and a consistent view. The finalization still re-checks what a
// decision binds (design decision 8).
type Snapshotter interface {
	// Snapshot calls fn with a Reader whose reads all see one snapshot of
	// org. That Reader is valid only during fn, and fn must make every
	// database read through it.
	Snapshot(ctx context.Context, org ids.OrgID, fn func(ctx context.Context, r Reader) error) error
}
