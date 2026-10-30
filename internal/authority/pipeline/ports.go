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
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
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
	// PayloadFindings are the credential-shaped values the gateway found in
	// the action's payload (HR-225): they only ever add a requirement.
	PayloadFindings []PayloadFinding
}

// PayloadFinding is one credential-shaped value in an action's payload: its
// format and where it is, never the value.
type PayloadFinding struct {
	Kind, Location string
}

// Pinned is an org's pinned definition with its lifecycle state, and the
// consequence rules its package version has for its operation (G0 M8,
// HR-206).
type Pinned struct {
	Definition   *defs.Definition
	State        defs.State
	Consequences []consequences.Rule
}

// Policy is the compiled policy selected for an evaluation: the org's
// published version, or a pilot's version for the agents of its cohorts
// (G0 M11.1, D12).
type Policy struct {
	Compiled *papp.Compiled
	// Version names the bundle as id@version for the decision basis.
	Version string
	// Budget is the tenant's CEL cost budget per evaluation (HR-043).
	Budget uint64
	// Rollout is the id of the pilot rollout that selected this agent's
	// version, or that it fell back from; empty otherwise.
	Rollout string
	// Selected is how the version was selected: SelectedDefault (the
	// published version), SelectedPilot (the rollout's version) or
	// SelectedFallback (the published version because the rollout's could
	// not be used). It is recorded, never part of the decision basis, and
	// never comes from the request (HR-234).
	Selected string
	// Exceptions are the agent's active policy exceptions, read by the
	// database clock in the decision's snapshot (G0 M11.1 D14, HR-235).
	// Only rules exceptable in this version whose digest an exception
	// names are waived, and only for the operations it lists.
	Exceptions []pdomain.Exception
}

// How a policy version was selected for an evaluation (D12).
const (
	SelectedDefault  = "DEFAULT"
	SelectedPilot    = "PILOT"
	SelectedFallback = "FALLBACK"
)

// Run is what the pipeline needs to know about a run (M3).
type Run struct {
	AgentID       ids.UUID
	InstanceID    ids.UUID
	Launcher      gdomain.Principal
	Principal     gdomain.Principal
	EnvironmentID ids.UUID
	GrantID       gdomain.GrantID
	Active        bool
	// Simulated: the run belongs to a range agent or descends from one
	// (HR-220). The decision records it; policy never sees it.
	Simulated bool
	// TaskRef is the run's UNTRUSTED task label, shown to approvers only in
	// the untrusted block (HR-034).
	TaskRef string
	// Ancestors are the launchers and principals of every ancestor run,
	// nearest first: none of them may approve the run's actions (HR-036).
	Ancestors []gdomain.Principal
}

// RunConsequenceCounts are how a run's actions stand downstream (G0 M17
// D103): Pending actions still wait for their consequences' verification;
// Unconfirmed actions have a consequence UNCONFIRMED or NOT_VERIFIABLE.
type RunConsequenceCounts struct {
	Pending, Unconfirmed int
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

// ControlKeys are what an action's containment controls can be keyed on (G0
// M10 D21, D53): its run, agent, connection, grant chain, people and target
// type. Empty keys match nothing.
type ControlKeys struct {
	Run, Agent, Connection string
	Grants                 []string
	// Principals are "user:<id>" or "service_account:<id>".
	Principals []string
	TargetType string
}

// MaxControls is how many controls an action's keys may match; more is
// ErrTooManyControls, and the action is denied (fail closed, D53).
const MaxControls = 10000

// ErrTooManyControls reports more than MaxControls matching controls.
var ErrTooManyControls = errors.New("pipeline: too many containment controls match the action")

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
	// Simulated connections point only at simulators (HR-221); a run and
	// a connection must agree on it (HR-220).
	Simulated bool
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
	// Controls returns the org's unlifted containment controls that keys may
	// match (G0 M10 D21, D53): those on its run, agent, connection, grant
	// chain or people, the resource controls of its target type, and any of a
	// scope type this pipeline does not know. Expiry never lifts a control.
	// More than MaxControls is ErrTooManyControls.
	Controls(ctx context.Context, org ids.OrgID, k ControlKeys) ([]Control, error)
	Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (Pinned, error)
	// Policy returns the policy selected for agent, the verified identity's
	// agent (D12): a pilot's version for the agents of its ENFORCE cohorts,
	// else the published one; nil when neither exists.
	Policy(ctx context.Context, org ids.OrgID, agent ids.UUID) (*Policy, error)
	Run(ctx context.Context, org ids.OrgID, id ids.UUID) (Run, error)
	Agent(ctx context.Context, org ids.OrgID, id ids.UUID) (Agent, error)
	// Chain returns the grant and its ancestors, root first.
	Chain(ctx context.Context, org ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error)
	Envelopes(ctx context.Context, org ids.OrgID, scopes []gdomain.Scope) ([]gdomain.Envelope, error)
	// Facts returns the current facts of active providers about one
	// subject, by name.
	// Facts is read for an action through connection (the zero id: none): a
	// gateway-provided name comes only from that connection's row (D43).
	Facts(ctx context.Context, org ids.OrgID, connection ids.UUID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error)
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
	// SensitiveReads returns the pii and secret reads of the run tree that
	// run belongs to (G0 M16 D73, D97): every run sharing its root, newest
	// first, the MaxSensitiveReads most recent plus the most recent of each
	// class not among them, so every class read is there. Classes and ids
	// only, never content (HR-434).
	SensitiveReads(ctx context.Context, org ids.OrgID, run ids.UUID) ([]SensitiveRead, error)
	// RunConsequences returns how the run's actions stand downstream (G0
	// M17 D103). It is read only for a policy that uses
	// run.consequences_pending or run.consequences_unconfirmed.
	RunConsequences(ctx context.Context, org ids.OrgID, run ids.UUID) (RunConsequenceCounts, error)
	// CustomerRules returns the org's ACTIVE customer consequence rules,
	// in rule id order, each with the ACTIVE definition of its consequence
	// operation (G0 M17 D106, D108; nil when the org has none). Step 6
	// evaluates them after the package's rules and only adds them.
	CustomerRules(ctx context.Context, org ids.OrgID) ([]consequences.Rule, error)
}

// SensitiveRead is one allowed pii or secret read of a run tree (D73).
type SensitiveRead struct {
	TransactionID, RunID ids.UUID
	Operation, Class     string
	At                   time.Time
}

// MaxSensitiveReads is how many of the newest sensitive reads
// SensitiveReads returns, and how many transactions the hold names.
const MaxSensitiveReads = 20

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

// PeerCheck decides whether the requester's grant lets a call through an
// a2a connection go to its peer agent (G0 M14 D89): "" allows it, any
// other reason refuses it. It reads through its own store; the pipeline
// holds no transaction.
type PeerCheck func(ctx context.Context, org ids.OrgID, conn Connection, grant gdomain.Grant) (reason string)

// ExternalCheck is the org's ACTIVE external policy checks (G0 M16 D81,
// D96; HR-436..440). An evaluation never calls one inside its snapshot:
//
//   - Preload, before the snapshot opens, puts the org's active checks on
//     the context, from a short in-process cache (a read only on a miss);
//   - pass 1 (inside the snapshot) finds the checks whose operations match
//     the action and returns them with their input (Evaluation.ExternalCalls);
//   - the caller ends the snapshot, Calls them with no database connection
//     held (AskExternal), and runs pass 2 in a new snapshot with the answers;
//   - pass 2 uses the answers only for the same checks and the same input;
//     anything else is CANNOT_AUTHORIZE. There is one round per decision.
//
// Unset (replay and simulation), no check is asked: replay reports
// "external check not evaluated".
type ExternalCheck interface {
	Preload(ctx context.Context, org ids.OrgID) context.Context
	// Matching returns the preloaded active checks whose operations cover the
	// operation; an error (checks not readable, or not preloaded) is
	// CANNOT_AUTHORIZE.
	Matching(ctx context.Context, org ids.OrgID, operation string) ([]ExternalTarget, error)
	// Call asks each check about its input, one verdict per call in order.
	Call(ctx context.Context, org ids.OrgID, calls []ExternalCall) []ExternalVerdict
}

// ExternalTarget names one check.
type ExternalTarget struct {
	ID   ids.UUID
	Name string
}

// ExternalCall is one check to ask and what to ask it; Digest is the
// SHA-256 of the input, which pass 2 compares.
type ExternalCall struct {
	Check  ExternalTarget
	Input  ExternalInput
	Digest string
}

// ExternalInput is what an external check is asked: the action's meaning
// and who stands behind it, never the content of a disclosure-capable
// parameter (HR-439).
type ExternalInput struct {
	Operation        string
	Access           string
	Target           actionir.Target
	Destinations     []actionir.Destination
	DestinationClass string
	Agent, Instance  string
	Run              string
	// RepresentedUser is the run's principal ("user:<id>"), when a person.
	RepresentedUser string
	Mode            string
	// Params are the material params, by name, as ActionIR JSON; each
	// disclosure-capable one is {"bytes": n} instead.
	Params map[string]any
}

// ExternalVerdict is one check's answer. Decision is "allow", "deny" or
// "hold", or "" when the check did not answer (Unavailable says why);
// Reasons are UNTRUSTED text for people only (HR-440).
type ExternalVerdict struct {
	CheckID     ids.UUID
	Check       string
	Decision    string
	Reasons     []string
	Unavailable string
}
