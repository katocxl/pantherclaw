// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// What happens after a dispatch (G0 M7 track A, HR-190..192): every
// recorded outcome keeps its signed execution receipt; an unknown one, from
// the gateway or the sweeper, opens a reconciliation task that keeps its
// reservations held; and the verification the definition's verifier
// allows is scheduled for the gateway serving the connection.

// verifyDelay is how long after an outcome the first verification read is
// due: the target gets a moment to settle.
const verifyDelay = 5 * time.Second

// Verification request modes: read the object the target named, or look it
// up in a listing of the write's target by the idempotency key.
const (
	modeReference = "reference"
	modeLookup    = "lookup"
)

// verifyRequest is the read a verification task asks the gateway to make
// (HR-190): built here from the stored action and the target's reference,
// never from what an agent sent.
type verifyRequest struct {
	Mode   string            `json:"mode"`
	Target actionir.Target   `json:"target"`
	Params map[string]string `json:"params"`
}

// verifyPlan copies a permit's verify plan into its insert (HR-191).
func verifyPlan(ins *dbq.InsertPermitForTransactionParams, p *pipeline.VerifyPlan) error {
	if p == nil || p.DefinitionDigest == "" {
		return nil
	}
	d := p.DefinitionDigest
	ins.DefinitionDigest = &d
	if p.Expected != nil {
		b, err := json.Marshal(p.Expected, json.Deterministic(true))
		if err != nil {
			return err
		}
		ins.VerifyExpect = b
	}
	return nil
}

// executed is what an execution receipt states about the permit in c.
func executed(c dbq.ExecutionContextRow, recordedBy string) finalize.Executed {
	x := finalize.Executed{
		Transaction: c.TransactionID, Connection: c.ConnectionID, AccessMode: finalize.AccessPantherClawHeld,
		Monitor: c.Mode == pipeline.ModeMonitor, RecordedBy: recordedBy, EffectiveHash: hex.EncodeToString(c.ActionHash),
	}
	if c.AccessMode != nil {
		x.AccessMode = *c.AccessMode
	}
	if len(c.EffectiveHash) > 0 && c.Mode != pipeline.ModeMonitor {
		x.EffectiveHash = hex.EncodeToString(c.EffectiveHash)
	}
	if c.DispatchingAt != nil {
		x.DispatchedAt = *c.DispatchingAt
	}
	return x
}

// keepReceipt appends an attempt's receipt to the ledger and keeps its JWS
// beside the attempt (PAP-1 §9.2).
func keepReceipt(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, attempt, txn, permit ids.UUID,
	actor evdomain.Actor, r finalize.Receipt,
) error {
	e, err := ledger.Append(ctx, tx, receiptKindExecution, actor, r.Body)
	if err != nil {
		return err
	}
	return q.InsertExecutionReceipt(ctx, dbq.InsertExecutionReceiptParams{
		OrgID: org, AttemptID: attempt, TransactionID: txn, PermitID: permit, ReceiptJws: r.JWS, LedgerEntryID: e.ID,
	})
}

// openReconciliation opens the transaction's unknown-outcome task, which
// keeps its reservations and dedupe claim held until it is resolved
// (HR-192, HR-003).
func openReconciliation(ctx context.Context, q *dbq.Queries, org ids.OrgID, txn ids.UUID) error {
	return q.OpenReconciliation(ctx, dbq.OpenReconciliationParams{
		OrgID: org, ID: ids.NewV7(), TransactionID: txn, Kind: string(tdomain.KindUnknownOutcome),
	})
}

// definition decodes a stored canonical definition.
func definition(raw []byte) (*defs.Definition, error) {
	var d defs.Definition
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("pgauthority: stored definition: %w", err)
	}
	return &d, nil
}

// scheduleVerification records the level the permit's definition requires
// and schedules the verification its verifier allows for outcome o
// (HR-190, G0 M7 design decision 1): after an accepted dispatch, a read of
// the object the target named (ref, kept only when it matches the read's
// target pattern) or else a lookup; after an unknown one, a lookup. It
// returns the reference it kept. A definition without an extended verifier
// schedules nothing: its effects are UNVERIFIABLE.
func scheduleVerification(ctx context.Context, q *dbq.Queries, org ids.OrgID, c dbq.ExecutionContextRow, o finalize.Outcome,
	ref string,
) (string, error) {
	if c.DefinitionDigest == nil {
		return "", nil // a permit issued before M7
	}
	raw, err := q.DefinitionCanonical(ctx, org, *c.DefinitionDigest)
	if db.IsNoRows(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	d, err := definition(raw)
	if err != nil {
		return "", err
	}
	v := d.Verifier
	level := string(defs.LevelAcceptance)
	if v != nil && v.Extended() {
		level = string(v.RequiredLevel())
	}
	if err := q.SetEffectRequired(ctx, &level, org, c.TransactionID); err != nil {
		return "", err
	}
	if v == nil || !v.Extended() || c.ConnectionID == nil || c.DispatchingAt == nil || (o != finalize.Accepted && o != finalize.Unknown) {
		return "", nil
	}
	readRaw, err := q.SiblingDefinition(ctx, org, *c.DefinitionDigest, v.Operation)
	if err != nil && !db.IsNoRows(err) {
		return "", err
	}
	kept := ""
	var read *defs.Definition
	if err == nil {
		if read, err = definition(readRaw); err != nil {
			return "", err
		}
		switch {
		case ref != "" && v.Reference != nil && read.Target.MatchID(ref):
			kept = ref
		case v.Reference == nil && read.Target.Type == d.Target.Type && c.TargetID != nil:
			kept = *c.TargetID // the verifier reads the write's own target
		}
	}
	req := verifyRequest{Params: map[string]string{}}
	purpose, op := tdomain.PurposeFollowUp, v.Operation
	switch {
	case o == finalize.Accepted && kept != "":
		req.Mode, req.Target = modeReference, actionir.Target{Type: read.Target.Type, ID: kept}
	case v.Lookup != nil && c.TargetType != nil && c.TargetID != nil:
		req.Mode, req.Target, op = modeLookup, actionir.Target{Type: *c.TargetType, ID: *c.TargetID}, v.Lookup.Operation
		if o == finalize.Unknown {
			purpose = tdomain.PurposeReconcile
		}
	default:
		return kept, nil
	}
	body, err := json.Marshal(req, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	txn := c.TransactionID
	return kept, q.ScheduleVerification(ctx, dbq.ScheduleVerificationParams{
		OrgID: org, ID: ids.NewV7(), Purpose: string(purpose), TransactionID: &txn, ConnectionID: *c.ConnectionID,
		Operation: op, Request: body, DelaySeconds: verifyDelay.Seconds(),
		DeadlineAt: c.DispatchingAt.Add(time.Duration(v.WithinSeconds) * time.Second),
	})
}

// lateReport handles a gateway's RecordExecution for a permit the sweeper
// already marked UNKNOWN (PAP-1 §7.4): the report is kept as an
// observation; accepted resolves the reconciliation as occurred (evidence
// only ever resolves that way, HR-192), commits the reservations, closes
// the RECONCILIATION waitlist entry and schedules the follow-up read; any
// other outcome resolves nothing. It returns the sweeper's execution
// receipt.
func lateReport(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gatewayID string, e finalize.Execution,
	c dbq.ExecutionContextRow,
) (string, error) {
	rec, err := q.RecordedExecution(ctx, org, e.Permit, gatewayID)
	if db.IsNoRows(err) {
		return "", finalize.ErrNotDispatching
	} else if err != nil {
		return "", err
	}
	gw, perr := ids.ParseUUID(gatewayID)
	if rec.State != "UNKNOWN" || rec.RecordedBy != finalize.RecordedBySweeper || perr != nil ||
		(e.Outcome != finalize.Accepted && e.Outcome != finalize.Failed && e.Outcome != finalize.Unknown) {
		return "", finalize.ErrNotDispatching
	}
	obs, outcome, txn := ids.NewV7(), string(e.Outcome), c.TransactionID
	o := dbq.InsertObservationParams{
		OrgID: org, ID: obs, Source: string(tdomain.ViaLateReport), TransactionID: &txn, GatewayID: gw, Outcome: &outcome,
		Found: pgtype.Bool{Bool: e.Outcome == finalize.Accepted, Valid: e.Outcome == finalize.Accepted},
	}
	if e.TargetStatus >= 100 && e.TargetStatus <= 599 {
		o.HttpStatus = &e.TargetStatus
	}
	if len(e.ResponseDigest) == 32 {
		o.ResponseDigest = e.ResponseDigest
	}
	if err := q.InsertObservation(ctx, o); err != nil {
		return "", err
	}
	if e.Outcome != finalize.Accepted {
		return rec.ReceiptJws, nil
	}
	via := string(tdomain.ViaLateReport)
	n, err := q.ResolveReconciliationOccurred(ctx, dbq.ResolveReconciliationOccurredParams{
		Via: &via, ObservationID: &obs, OrgID: org, TransactionID: txn,
	})
	if err != nil {
		return "", err
	}
	if n == 1 {
		if err := pgbudgets.Settle(ctx, q, org, e.Permit, bdomain.Commit); err != nil {
			return "", err
		}
		if err := q.SettleDedupeClaim(ctx, string(pipeline.ClaimSucceeded), org, txn); err != nil {
			return "", err
		}
		if err := pgwaitlist.CloseReconciliation(ctx, tx, org, txn, pgwaitlist.ResolvedOccurred,
			evdomain.Actor{Type: "gateway", ID: gatewayID}); err != nil {
			return "", err
		}
	}
	if _, err := scheduleVerification(ctx, q, org, c, finalize.Accepted, e.TargetRef); err != nil {
		return "", err
	}
	return rec.ReceiptJws, nil
}

// sweptEvidence leaves, for a permit the sweeper just marked UNKNOWN, what
// an unknown outcome reported by its gateway leaves (HR-192): the attempt
// recorded by the sweeper, its signed execution receipt, the open
// reconciliation task and the lookup that may find its effect.
func sweptEvidence(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, p dbq.MarkStaleDispatchingRow,
	sign func(gatewayID string, e finalize.Execution, x finalize.Executed, now time.Time) (finalize.Receipt, error),
) error {
	c, err := q.ExecutionContext(ctx, org, p.ID, p.GatewayID)
	if err != nil {
		return err
	}
	x := executed(c, finalize.RecordedBySweeper)
	attempt := ids.NewV7()
	if err := q.InsertExecutionAttempt(ctx, dbq.InsertExecutionAttemptParams{
		OrgID: org, ID: attempt, PermitID: p.ID, TransactionID: p.TransactionID, Outcome: string(finalize.Unknown),
		AccessMode: &x.AccessMode, RecordedBy: finalize.RecordedBySweeper,
	}); err != nil {
		return err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	r, err := sign(p.GatewayID, finalize.Execution{Permit: p.ID, Outcome: finalize.Unknown, DispatchMS: -1}, x, now)
	if err != nil {
		return err
	}
	if err := keepReceipt(ctx, tx, q, org, attempt, p.TransactionID, p.ID, evdomain.Actor{Type: "system", ID: "sweeper"}, r); err != nil {
		return err
	}
	if err := openReconciliation(ctx, q, org, p.TransactionID); err != nil {
		return err
	}
	_, err = scheduleVerification(ctx, q, org, c, finalize.Unknown, "")
	return err
}
