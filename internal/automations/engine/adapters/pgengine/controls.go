// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"context"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/automations/automationctx"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrCancelReason refuses an over-long cancellation note.
var ErrCancelReason = pcerr.New(pcerr.InvalidArgument, "REASON_INVALID", "the reason is at most 500 characters")

// CancelEffect is what a cancellation verifiably did (HR-283): read back
// from the executions' cleanup, never assumed.
type CancelEffect struct {
	Executions  []ids.UUID
	Grants      []ids.UUID
	Runs        []ids.UUID
	Launches    []ids.UUID
	Gates       []ids.UUID
	Deliveries  []ids.UUID
	StillActive []ids.UUID
}

// maxCancelBatch bounds CancelActiveExecutions; a kill switch pauses the
// automation first, so nothing new starts meanwhile.
const maxCancelBatch = 200

func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHumanOnly
	}
	if !c.Can(td.PermAutomationManage, td.OrgPath(c.Org)) {
		return c, td.ErrPermissionDenied(td.PermAutomationManage)
	}
	return c, nil
}

// CancelExecution stops an active execution (automation.manage, a person,
// D28, HR-283). In one transaction the request is recorded and the
// execution is advanced to its boundary, so the effect its cleanup records
// is returned verified. An unknown outcome of an irreversible operation
// still ends it in NEEDS_RECONCILIATION (D84 E1).
func (e *Engine) CancelExecution(ctx context.Context, id ids.UUID, note string) (Summary, CancelEffect, error) {
	c, err := manager(ctx)
	if err != nil {
		return Summary{}, CancelEffect{}, err
	}
	if utf8.RuneCountInString(note) > 500 {
		return Summary{}, CancelEffect{}, ErrCancelReason
	}
	var eff CancelEffect
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		eff, err = e.CancelTx(ctx, tx, []ids.UUID{id}, c.Principal.String(), autodomain.ReasonCancelledByUser, c.Actor(), note)
		return err
	})
	if err != nil {
		return Summary{}, eff, err
	}
	s, err := e.summary(ctx, c.Org, id)
	return s, eff, err
}

// CancelActiveExecutions cancels every active execution of an automation
// (automation.manage, a person, D28).
func (e *Engine) CancelActiveExecutions(ctx context.Context, automation ids.UUID, note string) (CancelEffect, error) {
	c, err := manager(ctx)
	if err != nil {
		return CancelEffect{}, err
	}
	if utf8.RuneCountInString(note) > 500 {
		return CancelEffect{}, ErrCancelReason
	}
	var eff CancelEffect
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		eff, err = e.CancelAutomationTx(ctx, tx, automation, c.Principal.String(), autodomain.ReasonCancelledByUser, c.Actor(), note)
		return err
	})
	return eff, err
}

// CancelAutomationTx cancels an automation's active executions in the
// caller's transaction: core's pause with cancel_active, retirement and
// RevokeAuthority (D28) call it inside their own change.
func (e *Engine) CancelAutomationTx(ctx context.Context, tx db.TenantTx, automation ids.UUID, by, reason string,
	actor evdomain.Actor, note string,
) (CancelEffect, error) {
	active, err := dbq.New(tx).ActiveAutomationExecutions(ctx, tx.OrgID(), automation)
	if err != nil {
		return CancelEffect{}, err
	}
	if len(active) > maxCancelBatch {
		active = active[:maxCancelBatch]
	}
	return e.CancelTx(ctx, tx, active, by, reason, actor, note)
}

// CancelTx records the cancellation of each execution, audited, and
// advances it to its boundary in tx (HR-283): its cleanup revokes its
// grants, ends its runs and cancels its launches, gates and deliveries;
// the effect is read back from what the cleanup recorded.
func (e *Engine) CancelTx(ctx context.Context, tx db.TenantTx, executions []ids.UUID, by, reason string,
	actor evdomain.Actor, note string,
) (CancelEffect, error) {
	var eff CancelEffect
	org := tx.OrgID()
	q := dbq.New(tx)
	now, err := q.DBNow(ctx)
	if err != nil {
		return eff, err
	}
	for _, id := range executions {
		row, err := q.GetAutomationExecution(ctx, org, id)
		if db.IsNoRows(err) {
			return eff, ErrNotFound
		} else if err != nil {
			return eff, err
		}
		if !autodomain.ExecutionState(row.State).Active() {
			// Already ended: this call affects nothing.
			continue
		}
		n, err := q.RequestAutomationExecutionCancel(ctx, dbq.RequestAutomationExecutionCancelParams{
			RequestedBy: nonEmpty(by), Reason: nonEmpty(reason), OrgID: org, ID: id,
		})
		if err != nil {
			return eff, err
		}
		details := map[string]string{"automation": row.AutomationID.String(), "execution": id.String()}
		if note != "" {
			details["note_chars"] = strconv.Itoa(utf8.RuneCountInString(note))
		}
		if n == 1 {
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "automation.execution_cancel_requested", Actor: actor, Outcome: audit.Success, ReasonCode: reason,
				Object: &audit.Object{Type: "automation_execution", ID: id.String()}, Details: details,
			}); err != nil {
				return eff, err
			}
		}
		x, err := e.load(ctx, q, org, id)
		if err != nil {
			return eff, err
		}
		if x.Active() {
			m := *e.Machine
			m.Now = func() time.Time { return now }
			before := x.State
			actx := automationctx.With(ctx, refOf(x))
			if _, err := m.Advance(actx, tx.Pgx(), x); err != nil {
				return eff, err
			}
			if err := e.audit(actx, tx, x, before); err != nil {
				return eff, err
			}
			if err := e.save(ctx, q, x); err != nil {
				return eff, err
			}
		}
		if x.Active() {
			eff.StillActive = append(eff.StillActive, id)
			continue
		}
		eff.Executions = append(eff.Executions, id)
		if x.Result == nil {
			continue
		}
		for _, r := range x.Result.Cleanup {
			switch r.Kind {
			case steps.RefGrant:
				eff.Grants = append(eff.Grants, r.ID)
			case reflexdomain.EvidenceRun:
				eff.Runs = append(eff.Runs, r.ID)
			case steps.RefLaunch:
				eff.Launches = append(eff.Launches, r.ID)
			case steps.RefApprovalRequest:
				eff.Gates = append(eff.Gates, r.ID)
			case steps.RefDelivery:
				eff.Deliveries = append(eff.Deliveries, r.ID)
			}
		}
	}
	return eff, nil
}

// summary reads one execution as a summary, outside the caller's
// transaction.
func (e *Engine) summary(ctx context.Context, org ids.OrgID, id ids.UUID) (Summary, error) {
	var out Summary
	err := e.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetAutomationExecution(ctx, org, id)
		if err != nil {
			return err
		}
		out, err = e.summarize(ctx, q, row)
		return err
	}, db.ReadOnly())
	return out, err
}

// GrantRevoker revokes an execution's grants (core's
// RevokeForAutomationTx with scope EXECUTION, D9).
type GrantRevoker interface {
	RevokeExecutionGrants(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error)
}

// RunEnder ends an execution's runs (core's EndForAutomationTx, D10).
type RunEnder interface {
	EndExecutionRuns(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error)
}

// GateCloser ends an execution's open gates (approvals, D25).
type GateCloser interface {
	OpenAutomationGatesTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, execution ids.UUID) ([]ids.UUID, error)
	EndAutomationGateTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID, reason string) error
}

// Cleanup is the engine's Cleaner (D24): at a terminal state of a LIVE
// execution its open launches are canceled, its open gates ended, its
// still-active grants revoked and its runs ended, all in the driver's
// transaction; the refs say what each did.
type Cleanup struct {
	Grants GrantRevoker
	Runs   RunEnder
	Gates  GateCloser
	// Deliveries cancels pending webhooks (triggers' Deliverer.Cancel, D89).
	Deliveries DeliveryCanceler
}

// DeliveryCanceler cancels a pending delivery (PENDING → FAILED).
type DeliveryCanceler interface {
	Cancel(ctx context.Context, tx pgx.Tx, id ids.UUID) error
}

// Cleanup implements Cleaner.
func (c Cleanup) Cleanup(ctx context.Context, tx pgx.Tx, x *engine.Exec) ([]reflexdomain.EvidenceRef, error) {
	reason := x.Reason
	if reason == "" {
		reason = "EXECUTION_ENDED"
	}
	var refs []reflexdomain.EvidenceRef
	q := dbq.New(tx)
	launches, err := q.OpenAutomationLaunches(ctx, x.Org, x.ID)
	if err != nil {
		return nil, err
	}
	for _, l := range launches {
		n, err := q.EndAutomationLaunch(ctx, "CANCELLED", x.Org, l.ID) //nolint:misspell // stored state
		if err != nil {
			return nil, err
		}
		if n == 1 {
			refs = append(refs, reflexdomain.EvidenceRef{Kind: steps.RefLaunch, ID: l.ID})
		}
	}
	if c.Gates != nil {
		gates, err := c.Gates.OpenAutomationGatesTx(ctx, tx, x.Org, x.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range gates {
			if err := c.Gates.EndAutomationGateTx(ctx, tx, x.Org, g, "EXECUTION_ENDED"); err != nil {
				return nil, err
			}
			refs = append(refs, reflexdomain.EvidenceRef{Kind: steps.RefApprovalRequest, ID: g})
		}
	}
	if c.Deliveries != nil {
		pending, err := q.PendingExecutionDeliveries(ctx, x.Org, x.ID)
		if err != nil {
			return nil, err
		}
		for _, d := range pending {
			if err := c.Deliveries.Cancel(ctx, tx, d); err != nil {
				if notPending(err) {
					continue
				}
				return nil, err
			}
			refs = append(refs, reflexdomain.EvidenceRef{Kind: steps.RefDelivery, ID: d})
		}
	}
	if c.Grants != nil {
		revoked, err := c.Grants.RevokeExecutionGrants(ctx, tx, x, reason)
		if err != nil {
			return nil, err
		}
		for _, g := range revoked {
			refs = append(refs, reflexdomain.EvidenceRef{Kind: steps.RefGrant, ID: g})
		}
	}
	if c.Runs != nil {
		ended, err := c.Runs.EndExecutionRuns(ctx, tx, x, reason)
		if err != nil {
			return nil, err
		}
		for _, r := range ended {
			refs = append(refs, reflexdomain.EvidenceRef{Kind: reflexdomain.EvidenceRun, ID: r})
		}
	}
	return refs, nil
}

// notPending reports a delivery that left PENDING meanwhile (delivered or
// failed by its sender): there is nothing left to cancel.
func notPending(err error) bool { return pcerr.ReasonOf(err) == "DELIVERY_NOT_PENDING" }
