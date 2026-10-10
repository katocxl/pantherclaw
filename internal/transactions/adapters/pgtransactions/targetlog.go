// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// Target-log reconciliation (HR-112, G0 M7 design decision 6): the gateway
// lists what the target created in a window; each object whose
// idempotency key names a transaction dispatched through the connection
// is matched to its receipt, and every other object is an effect without a
// receipt: a finding for people, never an automatic response.

// targetLogRequest is the read a target-log task names.
type targetLogRequest struct {
	Mode     string            `json:"mode"`
	Target   actionir.Target   `json:"target"`
	Params   map[string]string `json:"params"`
	EffectOf string            `json:"effect_of"`
}

// ScheduleTargetLogs implements app.Store.
func (s *Store) ScheduleTargetLogs(ctx context.Context, org ids.OrgID, overlap time.Duration) (int, error) {
	scheduled := 0
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.TargetLogConnections(ctx, org)
		if err != nil {
			return err
		}
		for _, c := range rows {
			if c.Open {
				continue
			}
			p, err := manifest.Decode(c.Raw)
			if err != nil || len(p.TargetLogs) == 0 {
				continue // verified at import; a package that no longer decodes has no target log to read
			}
			start, end := c.LastEnd.Add(-overlap), c.Now
			if c.LastEnd.Unix() <= 0 {
				start = c.Now.Add(-app.TargetLogEvery)
			}
			for _, tl := range p.TargetLogs {
				body, err := json.Marshal(targetLogRequest{
					Mode: "target_log", Target: actionir.Target{Type: defs.ConnectionTarget, ID: c.ID.String()},
					Params: map[string]string{tl.SinceParam: strconv.FormatInt(start.Unix(), 10)}, EffectOf: tl.EffectOf,
				}, json.Deterministic(true))
				if err != nil {
					return err
				}
				if err := q.ScheduleTargetLog(ctx, dbq.ScheduleTargetLogParams{
					OrgID: org, ID: ids.NewV7(), ConnectionID: c.ID, Operation: tl.Operation, Request: body,
					WindowStart: &start, WindowEnd: &end,
				}); err != nil {
					return err
				}
				scheduled++
			}
		}
		return nil
	})
	return scheduled, err
}

// targetLog applies a target-log report. New effects without a receipt are
// told to admins once per run.
func (s *Store) targetLog(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gateway ids.UUID, task dbq.LeasedTargetLogRow,
	r app.Report, sign app.Sign,
) (app.Applied, error) {
	var req targetLogRequest
	if err := json.Unmarshal(task.Request, &req); err != nil {
		return app.Applied{}, fmt.Errorf("pgtransactions: target-log task: %w", err)
	}
	if task.WindowStart == nil || task.WindowEnd == nil {
		return app.Applied{}, errors.New("pgtransactions: target-log task without a window")
	}
	obs, id := ids.NewV7(), task.ID
	o := dbq.InsertObservationParams{
		OrgID: org, ID: obs, Source: "target_log", VerificationID: &id, GatewayID: gateway,
		Found: pgtype.Bool{Bool: len(r.Items) > 0, Valid: true}, Complete: pgtype.Bool{Bool: r.Complete, Valid: true},
	}
	if r.HTTPStatus >= 100 && r.HTTPStatus <= 599 {
		st := int32(r.HTTPStatus)
		o.HttpStatus = &st
	}
	if len(r.ResponseDigest) == 32 {
		o.ResponseDigest = r.ResponseDigest
	}
	if err := q.InsertObservation(ctx, o); err != nil {
		return app.Applied{}, err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return app.Applied{}, err
	}
	matched, unmatched, found := 0, 0, 0
	for _, it := range r.Items {
		ok, err := matchItem(ctx, tx, q, org, task.ConnectionID, it, obs, sign, now)
		if err != nil {
			return app.Applied{}, err
		}
		if ok {
			matched++
			continue
		}
		unmatched++
		added, err := unreceipted(ctx, tx, q, org, task, req.EffectOf, it)
		if err != nil {
			return app.Applied{}, err
		}
		if added {
			found++
		}
	}
	if found > 0 && s.Notify != nil {
		if _, err := s.Notify.Enqueue(ctx, tx, napp.Message{
			Org: org, Type: "security.effect_without_receipt",
			Params:    map[string]string{"connection": task.ConnectionID.String(), "count": strconv.Itoa(found)},
			Subject:   &napp.Subject{Type: "connection", ID: task.ConnectionID},
			DedupeKey: "effect_without_receipt:" + task.ID.String(),
		}); err != nil {
			return app.Applied{}, err
		}
	}
	if err := q.InsertTargetLogRun(ctx, dbq.InsertTargetLogRunParams{
		OrgID: org, VerificationID: task.ID, ConnectionID: task.ConnectionID, WindowStart: *task.WindowStart,
		WindowEnd: *task.WindowEnd, ItemsSeen: int32(len(r.Items)), Matched: int32(matched), Unmatched: int32(unmatched), //nolint:gosec // G115: at most MaxTargetLogItems
		Complete: r.Complete && r.HTTPStatus >= 200 && r.HTTPStatus <= 299,
	}); err != nil {
		return app.Applied{}, err
	}
	return app.Applied{Observation: obs, Done: true}, q.FinishVerification(ctx, "DONE", org, task.ID)
}

// matchItem matches one listed object to the transaction its idempotency
// key names. An unknown outcome is resolved as occurred (evidence only ever
// resolves that way, HR-192); a failed one becomes CONFLICTING.
func matchItem(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, conn ids.UUID, it app.TargetLogItem, obs ids.UUID,
	sign app.Sign, now time.Time,
) (bool, error) {
	raw, ok := strings.CutPrefix(it.Correlation, "pc-")
	if !ok {
		return false, nil
	}
	txn, err := ids.ParseUUID(raw)
	if err != nil {
		return false, nil //nolint:nilerr // a key PantherClaw did not make names no transaction
	}
	rec, err := q.ReceiptOfCorrelation(ctx, org, txn, &conn)
	if db.IsNoRows(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	switch {
	case rec.PermitState == "UNKNOWN":
		via := string(domain.ViaTargetLog)
		n, err := q.ResolveReconciliationOccurred(ctx, dbq.ResolveReconciliationOccurredParams{
			Via: &via, ObservationID: &obs, OrgID: org, TransactionID: txn,
		})
		if err != nil || n != 1 {
			return true, err
		}
		if err := pgbudgets.Settle(ctx, q, org, rec.PermitID, bdomain.Commit); err != nil {
			return true, err
		}
		if err := q.SettleDedupeClaim(ctx, claimSucceeded, org, txn); err != nil {
			return true, err
		}
		return true, pgwaitlist.CloseReconciliation(ctx, tx, org, txn, pgwaitlist.ResolvedOccurred,
			evdomain.Actor{Type: "system", ID: "target_log"})
	case rec.Outcome != nil && *rec.Outcome == "failed" && deref(rec.EffectState, "") != string(domain.Conflicting):
		// The target refused, yet the object exists.
		e := app.Effect{
			Org: org, Transaction: txn, State: domain.Conflicting, Basis: "target_log", Observations: []ids.UUID{obs},
			Required: defs.Level(deref(rec.EffectLevelRequired, string(defs.LevelAcceptance))), Reason: "LISTED_AFTER_FAILURE", At: now,
		}
		if err := appendEffect(ctx, tx, q, e, evdomain.Actor{Type: "system", ID: "target_log"}, sign); err != nil {
			return true, err
		}
		return true, q.OpenReconciliation(ctx, dbq.OpenReconciliationParams{
			OrgID: org, ID: ids.NewV7(), TransactionID: txn, Kind: string(domain.KindConflictingEffect),
		})
	}
	return true, nil
}

// unreceipted records an object no receipt accounts for, once, with a
// security audit event (HR-112), and reports whether it was new.
func unreceipted(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, task dbq.LeasedTargetLogRow, effectOf string,
	it app.TargetLogItem,
) (bool, error) {
	p := dbq.InsertUnreceiptedEffectParams{
		OrgID: org, ID: ids.NewV7(), ConnectionID: task.ConnectionID, Operation: effectOf, ObjectRef: it.ObjectRef,
		VerificationID: task.ID,
	}
	if it.Correlation != "" {
		c := it.Correlation
		p.Correlation = &c
	}
	if !it.Created.IsZero() {
		c := it.Created
		p.TargetCreatedAt = &c
	}
	n, err := q.InsertUnreceiptedEffect(ctx, p)
	if err != nil || n != 1 {
		return false, err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "security.effect_without_receipt", Actor: evdomain.Actor{Type: "system", ID: "target_log"}, Outcome: audit.Failure,
		ReasonCode: "EFFECT_WITHOUT_RECEIPT", Object: &audit.Object{Type: "connection", ID: task.ConnectionID.String()},
		Details: map[string]string{"operation": effectOf, "object_ref": it.ObjectRef},
	})
	return err == nil, err
}
