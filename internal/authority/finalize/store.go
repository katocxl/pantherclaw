// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package finalize binds a pipeline evaluation (step 9) and settles what it
// reserved (step 10): idempotency per (org, run, action) (HR-005, HR-006),
// repeat protection by dedupe-key claims (HR-007), all-or-nothing
// reservation of every budget account and counter in the fixed lock order
// (HR-048, HR-049), the single-use permit and the signed decision receipt
// (G0 M4 part 2, design decisions 15–18). The transaction itself is behind
// the Store port: Postgres in production, an in-memory world in tests.
package finalize

import (
	"context"
	"errors"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Store errors. Each one rolls back the whole finalization.
var (
	// ErrConflict: the containment epoch, a grant or guardrail revision,
	// or the idempotency row changed since the evaluation (a lost race,
	// HR-004). The Authority evaluates again.
	ErrConflict = errors.New("finalize: changed since evaluation")
	// ErrExhausted: a budget account or counter had no room left. The
	// Authority evaluates again, which explains the limit.
	ErrExhausted = errors.New("finalize: limit reached")
	// ErrParked: the dedupe key is held by an earlier attempt (HR-007).
	ErrParked = errors.New("finalize: repeat parked")
	// ErrDuplicate: a concurrent request for the same (run, action)
	// committed first. The Authority answers from it.
	ErrDuplicate = errors.New("finalize: transaction already recorded")
	// ErrHoldLimit: the grant or the run has its maximum of pending holds
	// (HR-037). The Authority answers CANNOT_AUTHORIZE HOLD_LIMIT_REACHED.
	ErrHoldLimit = errors.New("finalize: hold limit reached")
	// ErrApprovalNotMet: an approver of the approval being used is no longer
	// eligible (HR-170). The Authority revalidates the request and
	// evaluates again.
	ErrApprovalNotMet = errors.New("finalize: the approval is no longer met")
	// ErrBusy: a budget account or counter row could not be locked within
	// the store's lock timeout (ADR-0015). The Authority answers
	// CANNOT_AUTHORIZE BUDGET_BUSY at once instead of queueing towards the
	// caller's timeout.
	ErrBusy = errors.New("finalize: budget busy")
)

// MaxEvaluations caps how often one OPEN transaction is evaluated (T-023);
// past it the stored decision is returned without a new evaluation.
const MaxEvaluations = 32

// Stored is a recorded transaction for one (org, run, action).
type Stored struct {
	TransactionID ids.UUID
	ActionHash    string
	Decision      adomain.Decision
	Reason        string
	// Final: ALLOW, ALLOW_WITH_OBLIGATIONS or DENY. OPEN transactions
	// (REQUIRE_*, CANNOT_AUTHORIZE) are evaluated again on resubmission.
	Final       bool
	Evaluations int
	Receipt     string
}

// Final reports whether a decision closes its transaction.
func Final(d adomain.Decision) bool {
	return d == adomain.Allow || d == adomain.AllowWithObligations || d == adomain.Deny
}

// Row is a budget account or counter row resolved from a reservation ref.
type Row struct {
	Ref  bdomain.Ref
	Kind bdomain.Kind
	ID   ids.UUID
}

// PermitWrite is the permit an ALLOW issues.
type PermitWrite struct {
	ID        ids.UUID
	JWS       string
	GatewayID string
	Epoch     int64
	ExpiresAt time.Time
}

// ClaimWrite claims a dedupe key for the transaction.
type ClaimWrite struct {
	Key           string
	TransactionID ids.UUID
}

// BudgetState is one account's state after the reservation, for the
// receipt (F113, F119).
type BudgetState struct {
	Level     string `json:"level"`
	Rule      string `json:"rule"`
	Currency  string `json:"currency,omitzero"`
	Available string `json:"available,omitzero"`
	Reserved  string `json:"reserved,omitzero"`
	Spent     string `json:"spent,omitzero"`
	Count     string `json:"count,omitzero"`
}

// Write is everything one finalization records, in one transaction:
//
//  1. for a permit, the containment row FOR SHARE: the epoch must still
//     be Eval.Epoch and the kill switch off;
//  2. for a permit, the grant chain and guardrails: revisions and states
//     as evaluated (a decision that permits nothing binds no authority);
//  3. the idempotency row: inserted, or updated conditionally on Prev;
//  4. the dedupe claim, when Claim is set;
//  5. the counters and budget accounts in Lines, in their lock order, last;
//  6. the permit, the decision receipt and its ledger entry.
type Write struct {
	Eval          *pipeline.Evaluation
	TransactionID ids.UUID
	Evaluation    int
	// Prev is the stored transaction this evaluation follows (OPEN), or
	// nil for a new one.
	Prev   *Stored
	Final  bool
	Reason string
	// Claim, Lines and Permit are set for a decision that permits.
	Claim  *ClaimWrite
	Lines  []bdomain.Line
	Rows   []Row
	Permit *PermitWrite
	// Sign builds and signs the decision receipt once the budget state
	// after the reservation is known.
	Sign func(budgets []BudgetState) (Receipt, error)
	// GatewayID records which gateway asked.
	GatewayID string
	// HoldRequest is the id of the approval request a hold records (G0 M5
	// part 2): set when the decision holds and the evaluation's binding
	// differs from the transaction's live request, if any. The finalization
	// then also checks containment and the grant chain, supersedes the
	// live request, takes the hold slots and opens the waitlist entry
	// (HR-037, HR-171). A permit whose evaluation is Hold.Satisfied
	// consumes the approval; a DENY whose Hold.Expire is set records the
	// expiry.
	HoldRequest ids.UUID
}

// Receipt is a signed decision receipt and the canonical body that the
// ledger entry carries.
type Receipt struct {
	JWS  string
	Body []byte
	// Inputs are what the evaluation read, sealed for replay (G0 M7 design
	// decision 11): a decision receipt's store writes them in the same
	// transaction. Nil when the Authority records none.
	Inputs *recording.Sealed
}

// Outcome of a dispatched permit (PAP-1 §7.4).
type Outcome string

// Outcomes. Delegated: a cooperative channel's agent performs the allowed
// action itself; it settles like accepted (PAP-1 §7.4, HR-186).
const (
	Accepted  Outcome = "accepted"
	Failed    Outcome = "failed"
	Unknown   Outcome = "unknown"
	Delegated Outcome = "delegated"
)

// Access modes recorded on executions (F416).
const (
	AccessPantherClawHeld = "pantherclaw_held"
	AccessAgentHeld       = "agent_held"
)

// Executed is what the store established about a recorded attempt, for
// the execution receipt: the transaction, how the credential reached the
// target (the connection's access mode; agent_held for delegated;
// pantherclaw_held for an action without a connection), and whether the
// permit was a monitor-mode one.
type Executed struct {
	Transaction ids.UUID
	Connection  *ids.UUID
	AccessMode  string
	Monitor     bool
	// EffectiveHash is the hex SHA-256 of the action the permit bound (the
	// effective one, or the requested one when nothing was clamped);
	// DispatchedAt is when the permit moved to DISPATCHING (G0 M7, PAP-1
	// §9.2).
	EffectiveHash string
	DispatchedAt  time.Time
	// RecordedBy is RecordedByGateway, or RecordedBySweeper for a dispatch
	// that never reported (HR-192).
	RecordedBy string
	// TargetRef is the target's reference for what it created, when the
	// gateway read one and it matches the verifier's read.
	TargetRef string
}

// Who recorded an attempt.
const (
	RecordedByGateway = "gateway"
	RecordedBySweeper = "sweeper"
)

// Store is the finalization and settlement port.
type Store interface {
	// Lookup returns the stored transaction for (run, action), or nil.
	Lookup(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*Stored, error)
	// Prepare makes sure the rows of a reservation plan exist, in its own
	// short transaction (never inside Finalize, so Finalize only updates
	// rows and its lock order cannot deadlock), and resolves their ids. The
	// Authority skips it when the evaluation found every row of the plan.
	Prepare(ctx context.Context, org ids.OrgID, plan gdomain.Plan) ([]Row, error)
	// Finalize records w in one transaction (see Write).
	Finalize(ctx context.Context, org ids.OrgID, w Write) error
	// Tamper records a request whose hash differs from the stored one for
	// the same (run, action): an OPEN transaction becomes FINAL with
	// DENY ACTION_TAMPERED and gets receipt; a FINAL one is unchanged.
	// Either way a security.action_tampered audit event is written.
	Tamper(ctx context.Context, org ids.OrgID, prev Stored, receipt *Receipt, gatewayID string) error
	// BeginDispatch moves a permit ISSUED → DISPATCHING if it is unexpired
	// (database clock) and the epoch is current (HR-001), records out, and
	// in the same transaction calls mint with what the permit bound; the id
	// mint returns is recorded as the action token's. A mint error rolls
	// everything back.
	BeginDispatch(ctx context.Context, org ids.OrgID, gatewayID string, permit ids.UUID, epoch int64, out Outbound,
		mint func(Dispatching) (*ids.UUID, error)) error
	// RecordExecution settles every line of the permit's reservation and
	// its claim: accepted and delegated commit (claim SUCCEEDED), failed
	// releases (claim RELEASED), unknown keeps both held (HR-003, F115).
	// Delegated is refused (ErrNotCooperative) unless the transaction's
	// channel is hook or sdk. It records the attempt with its access mode
	// and, in the same transaction, the execution receipt sign returns at
	// the database time.
	RecordExecution(ctx context.Context, org ids.OrgID, gatewayID string, e Execution, sign func(x Executed, now time.Time) (Receipt, error)) (string, error)
	// Sweep releases expired ISSUED permits (and their claims) and marks
	// stale DISPATCHING ones UNKNOWN, never releasing them (HR-003). Each
	// swept permit gets, in the same transaction, the attempt, the
	// execution receipt sign returns for it and an open reconciliation task
	// (HR-192), as an unknown outcome a gateway reported would.
	Sweep(ctx context.Context, org ids.OrgID, staleAfter time.Duration,
		sign func(gatewayID string, e Execution, x Executed, now time.Time) (Receipt, error)) (released, unknown int, err error)
	// ApplySettlements applies the outcomes RecordExecution and Sweep
	// recorded to the budget account and counter rows, in batches, off the
	// decision path (ADR-0015), and returns how many it applied. A store
	// that settles the rows at once applies nothing.
	ApplySettlements(ctx context.Context, org ids.OrgID) (int, error)
	// Revalidate voids the responses of an approval request whose people
	// are no longer eligible and returns an approved request that is no
	// longer met to PENDING (HR-170), in its own transaction.
	Revalidate(ctx context.Context, org ids.OrgID, request ids.UUID) error
}

// Dispatch errors: the gateway must not dispatch on any of them (HR-001).
var (
	ErrPermitUnknown  = pcerr.New(pcerr.FailedPrecondition, "PERMIT_UNKNOWN", "permit not found")
	ErrPermitUsed     = pcerr.New(pcerr.FailedPrecondition, "PERMIT_ALREADY_USED", "permit already used")
	ErrPermitExpired  = pcerr.New(pcerr.FailedPrecondition, "PERMIT_EXPIRED", "permit expired")
	ErrEpochStale     = pcerr.New(pcerr.FailedPrecondition, "EPOCH_STALE", "containment changed since the permit was issued")
	ErrKillSwitch     = pcerr.New(pcerr.Deny, "KILL_SWITCH_ENGAGED", "kill switch engaged")
	ErrNotDispatching = pcerr.New(pcerr.FailedPrecondition, "PERMIT_NOT_DISPATCHING", "permit is not dispatching")
)
