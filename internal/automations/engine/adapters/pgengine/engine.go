// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/automations/automationctx"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Cleaner undoes nothing: at a terminal state of a LIVE execution it
// revokes the grants the execution issued that are still active, ends its
// runs and cancels its pending launches, deliveries and gates (D24). It
// returns refs of what it did.
type Cleaner interface {
	Cleanup(ctx context.Context, tx pgx.Tx, x *engine.Exec) ([]reflexdomain.EvidenceRef, error)
}

// Reconciler reports whether an execution's unknown outcomes are resolved
// (M7 reconciliation, D27).
type Reconciler interface {
	Reconciled(ctx context.Context, tx pgx.Tx, x *engine.Exec) (resolved, changed bool, err error)
}

// CeilingVoider voids a ceiling whose approvers no longer hold (core's
// Automations.VoidCeiling, D57), in its own transaction.
type CeilingVoider interface {
	VoidCeiling(ctx context.Context, org ids.OrgID, ceiling ids.UUID, reason string) error
}

// Engine runs executions in the database.
type Engine struct {
	Pool    *db.Pool
	Machine *engine.Machine
	// Client enqueues driver jobs in the caller's transaction; set once
	// the River client exists.
	Client *jobs.Client
	Log    *slog.Logger

	Ceilings   autoports.CeilingChecker
	Pauser     autoports.Pauser
	Failures   reflexports.FailureSink
	Editions   Editions
	Cleaner    Cleaner
	Reconciler Reconciler
	Voider     CeilingVoider

	defs   definitions
	voided sync.Map
}

// New returns an engine whose Machine runs steps; set the ports before use.
func New(pool *db.Pool, steps autoports.StepRegistry, log *slog.Logger) (*Engine, error) {
	e := &Engine{Pool: pool, Log: log}
	m, err := engine.NewMachine(steps, hooks{e}, time.Now)
	if err != nil {
		return nil, err
	}
	e.Machine = m
	return e, nil
}

// The engine's audit actor: the automation's own service account (D8).
func actorOf(x *engine.Exec) evdomain.Actor {
	return evdomain.Actor{Type: "service_account", ID: x.View.ServiceAccount.String()}
}

func refOf(x *engine.Exec) automationctx.Ref {
	return automationctx.Ref{Automation: x.Automation, Version: x.Version, Execution: x.ID, Trigger: x.View.Trigger.ID}
}

// Start implements autoports.Starter (D24): in the trigger's transaction
// it locks the automation, checks it is ACTIVE with this version enabled
// and under its concurrency, records a PENDING execution and enqueues its
// driver. A SHADOW rollout runs SHADOW executions.
func (e *Engine) Start(ctx context.Context, tx pgx.Tx, t autodomain.TriggerRef) (ids.UUID, error) {
	q := dbq.New(tx)
	a, err := q.LockAutomation(ctx, t.Org, t.Automation)
	if db.IsNoRows(err) {
		return ids.UUID{}, autodomain.ErrNotActive
	} else if err != nil {
		return ids.UUID{}, err
	}
	if a.State != string(autodomain.StateActive) || a.EnabledVersionID == nil || *a.EnabledVersionID != t.Version {
		return ids.UUID{}, autodomain.ErrNotActive
	}
	mode := t.Mode
	switch {
	case a.Rollout != nil && *a.Rollout == string(autodomain.RolloutShadow):
		mode = autodomain.ModeShadow
	case mode == "":
		mode = autodomain.ModeLive
	case mode == autodomain.ModeTest:
		return ids.UUID{}, fmt.Errorf("pgengine: TEST executions run only in Simulate")
	}
	def, err := e.defs.get(ctx, q, t.Org, t.Version)
	if err != nil {
		return ids.UUID{}, err
	}
	limit := 1
	if def.Authority.Ceiling != nil {
		limit = def.Authority.Ceiling.ConcurrencyOrDefault()
	}
	n, err := q.CountActiveAutomationExecutions(ctx, t.Org, t.Automation)
	if err != nil {
		return ids.UUID{}, err
	}
	if int(n) >= limit {
		return ids.UUID{}, autodomain.ErrConcurrency
	}
	var ceiling *ids.UUID
	if c, err := q.GetActiveAutomationCeiling(ctx, t.Org, t.Automation); err == nil {
		if c.VersionID != t.Version {
			return ids.UUID{}, autodomain.ErrNotActive
		}
		ceiling = &c.ID
	} else if !db.IsNoRows(err) {
		return ids.UUID{}, err
	}
	if ceiling == nil && mode == autodomain.ModeLive {
		return ids.UUID{}, autodomain.ErrNotActive
	}
	var principalUser, principalSA *ids.UUID
	if u, ok := def.Authority.PrincipalUser(); ok {
		id := u.UUID()
		principalUser = &id
	} else {
		principalSA = &a.ServiceAccountID
	}
	params, err := encodeParams(t.Params)
	if err != nil {
		return ids.UUID{}, err
	}
	subjects, err := encodeSubjects(t.Subjects)
	if err != nil {
		return ids.UUID{}, err
	}
	evidence, err := EncodeRefs(t.Evidence)
	if err != nil {
		return ids.UUID{}, err
	}
	root := t.Root
	if root.IsZero() || t.Depth == 0 {
		root = t.ID
	}
	ancestry := t.Ancestry
	if ancestry == nil {
		ancestry = []ids.UUID{}
	}
	occurred := t.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	id := ids.NewV7()
	if err := q.InsertAutomationExecution(ctx, dbq.InsertAutomationExecutionParams{
		OrgID: t.Org, ID: id, AutomationID: t.Automation, VersionID: t.Version, TriggerID: t.ID, Mode: string(mode),
		CeilingID: ceiling, ServiceAccountID: a.ServiceAccountID, PrincipalUserID: principalUser, PrincipalSaID: principalSA,
		TriggerKind: string(t.Kind), Params: params, Subjects: subjects, Evidence: evidence, OccurredAt: occurred,
		RootTriggerID: root, Ancestry: ancestry, Depth: int16(t.Depth), //nolint:gosec // 0..3, CHECK
		DeadlineS: int64(def.Limits.DeadlineOrDefault() / time.Second),
	}); err != nil {
		return ids.UUID{}, err
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, t.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	actx := automationctx.With(ctx, automationctx.Ref{Automation: t.Automation, Version: t.Version, Execution: id, Trigger: t.ID})
	if _, err := audit.Record(actx, ttx, audit.Event{
		Name: "automation.execution_started", Actor: evdomain.Actor{Type: "service_account", ID: a.ServiceAccountID.String()},
		Outcome: audit.Success, Object: &audit.Object{Type: "automation_execution", ID: id.String()},
		Details: automationctx.Annotate(actx, map[string]string{"mode": string(mode), "trigger_kind": string(t.Kind)}),
	}); err != nil {
		return ids.UUID{}, err
	}
	if err := e.enqueue(ctx, tx, t.Org, id); err != nil {
		return ids.UUID{}, err
	}
	return id, nil
}

// enqueue asks the driver to advance an execution, in tx.
func (e *Engine) enqueue(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) error {
	if e.Client == nil {
		return nil // the wake sweep picks it up
	}
	if _, err := e.Client.InsertTx(ctx, tx, ExecutionArgs{Org: org, Execution: id}, nil); err != nil {
		return fmt.Errorf("pgengine: enqueue %s: %w", id, err)
	}
	return nil
}

// ErrNotFound reports an execution of another org or none.
var ErrNotFound = pcerr.New(pcerr.NotFound, "EXECUTION_NOT_FOUND", "execution not found")

// Advance works one execution until it waits or ends, in rounds of at most
// engine.MaxTransitions, each in its own tenant transaction (D24). It
// records the audit events of what changed.
func (e *Engine) Advance(ctx context.Context, org ids.OrgID, id ids.UUID) error {
	for range 5 {
		again := false
		var void ids.UUID
		err := e.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			x, err := e.load(ctx, q, org, id)
			if db.IsNoRows(err) {
				return ErrNotFound
			} else if err != nil {
				return err
			}
			if !x.Active() && x.State != autodomain.ExecNeedsReconciliation {
				return nil
			}
			if x.State == autodomain.ExecNeedsReconciliation && x.WakeAt.After(time.Now()) {
				return nil
			}
			now, err := q.DBNow(ctx)
			if err != nil {
				return err
			}
			m := *e.Machine
			m.Now = func() time.Time { return now }
			before := x.State
			ctx = automationctx.With(ctx, refOf(x))
			again, err = m.Advance(ctx, tx.Pgx(), x)
			if err != nil {
				return err
			}
			if err := e.audit(ctx, tx, x, before); err != nil {
				return err
			}
			void = voidedCeiling(x)
			return e.save(ctx, q, x)
		})
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			if ctx.Err() == nil {
				if ferr := e.countError(ctx, org, id, err); ferr != nil {
					return errors.Join(err, ferr)
				}
			}
			return err
		}
		if !void.IsZero() {
			if err := e.voidCeiling(ctx, org, void); err != nil {
				return err
			}
		}
		if !again {
			return nil
		}
	}
	return nil
}

// audit records the steps that finished and the execution's end (D24).
func (e *Engine) audit(ctx context.Context, tx db.TenantTx, x *engine.Exec, before autodomain.ExecutionState) error {
	actor := actorOf(x)
	obj := &audit.Object{Type: "automation_execution", ID: x.ID.String()}
	for _, a := range x.Attempts {
		if !a.Dirty && !a.New || !a.Terminal() {
			continue
		}
		outcome := audit.Success
		if a.State == autodomain.StepFailed || a.State == autodomain.StepUnknown {
			outcome = audit.Failure
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "automation.step_finished", Actor: actor, Outcome: outcome, ReasonCode: a.Reason, Object: obj,
			Details: automationctx.Annotate(ctx, map[string]string{
				"step": a.StepID, "kind": a.Kind, "attempt": strconv.Itoa(a.Number), "state": string(a.State),
				"effect": string(effectOr(a.Effect)), "compensation": strconv.FormatBool(a.Compensation),
			}),
		}); err != nil {
			return err
		}
	}
	if before != x.State && !x.Active() {
		outcome := audit.Success
		if x.State != autodomain.ExecSucceeded {
			outcome = audit.Failure
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "automation.execution_finished", Actor: actor, Outcome: outcome, ReasonCode: x.Reason, Object: obj,
			Details: automationctx.Annotate(ctx, map[string]string{"state": string(x.State), "mode": string(x.Mode)}),
		}); err != nil {
			return err
		}
	}
	return nil
}

// voidedCeiling is the ceiling a LIVE execution found void in this pass
// (revalidation or issuance refused CEILING_VOID), else zero.
func voidedCeiling(x *engine.Exec) ids.UUID {
	if x.Mode != autodomain.ModeLive || x.View.Ceiling.IsZero() {
		return ids.UUID{}
	}
	if !x.Active() && x.Reason == autodomain.ReasonCeilingVoid {
		return x.View.Ceiling
	}
	for _, a := range x.Attempts {
		if (a.New || a.Dirty) && a.Reason == autodomain.ReasonCeilingVoid {
			return x.View.Ceiling
		}
	}
	return ids.UUID{}
}

// voidCeiling asks core to void a ceiling whose approvers no longer hold,
// in its own transaction (D57, D84 E4), once per ceiling per process.
func (e *Engine) voidCeiling(ctx context.Context, org ids.OrgID, ceiling ids.UUID) error {
	if e.Voider == nil {
		return nil
	}
	if _, done := e.voided.LoadOrStore(ceiling, true); done {
		return nil
	}
	if err := e.Voider.VoidCeiling(ctx, org, ceiling, autodomain.ReasonCeilingVoid); err != nil {
		e.voided.Delete(ceiling)
		return err
	}
	return nil
}

// MaxEngineErrors is how many consecutive driver errors fail an execution
// (D84): a definition that no longer decodes, for example, never loops
// forever.
const MaxEngineErrors = 5

// ReasonEngineError ends an execution the driver cannot work.
const ReasonEngineError = "ENGINE_ERROR"

// countError records a driver error in its own transaction; the fifth in
// a row fails the execution with an owned failure for its owner.
func (e *Engine) countError(ctx context.Context, org ids.OrgID, id ids.UUID, cause error) error {
	return e.Pool.InTenantTx(context.WithoutCancel(ctx), org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.CountAutomationExecutionError(ctx, org, id)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		if int(r.EngineErrors) < MaxEngineErrors {
			return nil
		}
		res, err := encodeResult(engine.Result{
			State: autodomain.ExecFailed, Reason: ReasonEngineError, Changed: []string{}, Unchanged: []string{},
			Unknown: []string{}, Unresolved: []engine.Unresolved{{Kind: ReasonEngineError, Detail: errText(cause)}},
		})
		if err != nil {
			return err
		}
		if _, err := q.FailAutomationExecution(ctx, dbq.FailAutomationExecutionParams{
			OrgID: org, ID: id, Reason: nonEmpty(ReasonEngineError), Result: res,
		}); err != nil {
			return err
		}
		actx := automationctx.With(ctx, automationctx.Ref{
			Automation: r.AutomationID, Version: r.VersionID, Execution: id,
			Trigger: r.TriggerID,
		})
		if _, err := audit.Record(actx, tx, audit.Event{
			Name: "automation.execution_finished", Actor: evdomain.Actor{Type: "service_account", ID: r.ServiceAccountID.String()},
			Outcome: audit.Failure, ReasonCode: ReasonEngineError, Object: &audit.Object{Type: "automation_execution", ID: id.String()},
			Details: automationctx.Annotate(actx, map[string]string{"state": string(autodomain.ExecFailed), "mode": r.Mode}),
		}); err != nil {
			return err
		}
		if e.Failures == nil {
			return nil
		}
		_, err = e.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
			Org: org, Kind: FailureEngineError,
			Summary:  "Automation " + r.Name + " execution " + id.String() + " could not be worked and was stopped",
			NextStep: "Check the automation's enabled version and the server logs, then retry the execution.",
			Scope: []reflexdomain.Subject{
				{Type: reflexdomain.SubjectAutomation, ID: r.AutomationID.String()},
				{Type: reflexdomain.SubjectAutomationExecution, ID: id.String()},
			},
			Owner:    &reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: r.OwnerUserID.String()},
			Deadline: time.Now().Add(escalationWindow).UTC(), DedupeKey: FailureEngineError + ":" + id.String(),
		})
		return err
	})
}

// FailureEngineError is the owned failure of an execution the driver
// stopped (D38).
const FailureEngineError = "automation.engine_error"

// errText is a short, non-secret error class for the result.
func errText(err error) string {
	if r := pcerr.ReasonOf(err); r != "" {
		return r
	}
	return "INTERNAL"
}
