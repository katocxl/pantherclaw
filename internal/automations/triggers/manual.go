// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"encoding/json/v2"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the trigger use cases.
var (
	ErrEdition    = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "automations need the Team edition or above")
	ErrHuman      = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrNotFound   = pcerr.New(pcerr.NotFound, "AUTOMATION_NOT_FOUND", "automation not found")
	ErrNotManual  = pcerr.New(pcerr.FailedPrecondition, "NOT_MANUAL", "this automation's enabled version is not started by hand")
	ErrInvalid    = pcerr.New(pcerr.InvalidArgument, "INVALID_TRIGGER", "the start request is not valid")
	ErrNotRetry   = pcerr.New(pcerr.FailedPrecondition, "NOT_RETRYABLE", "only a failed, partially completed or cancelled execution of the enabled version with no unknown irreversible effect can be retried") //nolint:misspell // the stored state is CANCELLED
	ErrNoEngine   = pcerr.New(pcerr.FailedPrecondition, "ENGINE_UNAVAILABLE", "executions cannot be looked up on this server")
	ErrIdemKey    = pcerr.New(pcerr.InvalidArgument, "IDEMPOTENCY_KEY", "an idempotency key is 1 to 128 printable characters")
	ErrStepUpNeed = stepup.ErrStepUp
)

// ExecutionInfo is what a retry needs to know about an execution (engine).
type ExecutionInfo struct {
	Automation ids.UUID
	Version    ids.UUID
	State      autodomain.ExecutionState
	// UnknownIrreversible: a step of an irreversible operation ended with
	// an UNKNOWN effect (HR-280): it is reconciled, never retried.
	UnknownIrreversible bool
	Trigger             ids.UUID
}

// ExecutionLookup reads executions (implemented by the engine).
type ExecutionLookup interface {
	Execution(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) (ExecutionInfo, error)
}

// ManualStart is a person's start request (D20).
type ManualStart struct {
	Automation     ids.UUID
	Params         map[string]string
	IdempotencyKey string
}

// MaxIdempotencyKey bounds an idempotency key.
const MaxIdempotencyKey = 128

func validIdemKey(k string) bool {
	if k == "" || utf8.RuneCountInString(k) > MaxIdempotencyKey {
		return false
	}
	return !strings.ContainsFunc(k, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func (s *Service) entitled(ctx context.Context) error {
	if s.d.Editions == nil {
		return ErrEdition
	}
	e, err := s.d.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.Automations() {
		return ErrEdition
	}
	return nil
}

func (s *Service) runner(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermAutomationRun, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHuman
	}
	return c, s.entitled(ctx)
}

// requiresStepUp reports whether starting the version by hand needs a
// step-up (D2, D20, D87 P3): it asks for one, its ceiling spends budget, or
// its ceiling has an irreversible operation (a prefix counts as one, and
// so does every operation when operations cannot be looked up).
func (s *Service) requiresStepUp(ctx context.Context, org ids.OrgID, def *autodomain.Definition) (bool, error) {
	if m := def.When.Manual; m != nil && m.StepUp {
		return true, nil
	}
	c := def.Authority.Ceiling
	if c == nil {
		return false, nil
	}
	if len(c.PerDay.Budget) > 0 {
		return true, nil
	}
	if c.Bounds.Operations == nil {
		return false, nil
	}
	for _, op := range *c.Bounds.Operations {
		if strings.HasSuffix(op, ".*") || s.d.Operations == nil {
			return true, nil
		}
		d, err := s.d.Operations.Active(ctx, org, op)
		if err != nil {
			return false, err
		}
		if d == nil || d.Reversibility == defs.Irreversible {
			return true, nil
		}
	}
	return false, nil
}

// StartExecution starts an automation by hand (D20): automation.run, a
// person, and — when the version requires it — a fresh step-up of this
// browser session (D53: su is nil over the API, which then refuses with
// STEP_UP_REQUIRED). Dedupe `manual:<idempotency key>`.
func (s *Service) StartExecution(ctx context.Context, in ManualStart, su *stepup.StepUp) (Outcome, error) {
	c, err := s.runner(ctx)
	if err != nil {
		return Outcome{}, err
	}
	if !validIdemKey(in.IdempotencyKey) {
		return Outcome{}, ErrIdemKey
	}
	var out Outcome
	err = s.d.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := s.loadAutomation(ctx, q, c.Org, in.Automation)
		if err != nil {
			return err
		}
		m := a.Def.When.Manual
		if m == nil {
			return ErrNotManual
		}
		auth, detail, err := s.checkStepUp(ctx, tx, c, a.Def, su)
		if err != nil {
			return err
		}
		key := ManualKey(c.Principal.ID, in.IdempotencyKey)
		if prior, ok, err := s.repeat(ctx, q, c.Org, a.ID, key); err != nil || ok {
			out = prior
			return err
		}
		params, perr := ExtractManual(manualSpecs(m.Params), in.Params)
		out, err = s.Fire(ctx, tx, Candidate{
			Automation: a, Kind: autodomain.TriggerManual, Authenticity: auth, Detail: detail,
			SourceRef: "user:" + c.Principal.ID.String(), Params: params, ParamErr: perr,
			BaseKey: key, QueueOK: true,
		})
		return err
	})
	return out, err
}

func (s *Service) checkStepUp(ctx context.Context, tx db.TenantTx, c tenancy.Caller, def *autodomain.Definition, su *stepup.StepUp) (autodomain.Authenticity, map[string]string, error) {
	detail := map[string]string{"user": c.Principal.ID.String()}
	need, err := s.requiresStepUp(ctx, c.Org, def)
	if err != nil {
		return "", nil, err
	}
	if !need && su == nil {
		return autodomain.AuthUserSession, detail, nil
	}
	if su == nil {
		return "", nil, ErrStepUpNeed
	}
	now, err := dbq.New(tx).DBNow(ctx)
	if err != nil {
		return "", nil, err
	}
	if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
		return "", nil, err
	}
	detail["credential"] = su.Credential.String()
	return autodomain.AuthUserStepUp, detail, nil
}

// RetryExecution starts a new manual trigger with an earlier execution's
// parameters (D59, F283): automation.run, a person; only for an execution
// of the enabled version that failed, partially completed or was stopped
// by a person, with no UNKNOWN irreversible effect. Dedupe `retry:<execution>:<key>`. The
// engine revalidates everything at start.
func (s *Service) RetryExecution(ctx context.Context, execution ids.UUID, idem string, su *stepup.StepUp) (Outcome, error) {
	c, err := s.runner(ctx)
	if err != nil {
		return Outcome{}, err
	}
	if !validIdemKey(idem) {
		return Outcome{}, ErrIdemKey
	}
	if s.d.Executions == nil {
		return Outcome{}, ErrNoEngine
	}
	var out Outcome
	err = s.d.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		x, err := s.d.Executions.Execution(ctx, tx.Pgx(), c.Org, execution)
		if err != nil {
			return err
		}
		switch x.State { //nolint:exhaustive // only these ended without success
		case autodomain.ExecFailed, autodomain.ExecPartiallyCompleted, autodomain.ExecCancelled:
		default:
			return ErrNotRetry
		}
		if x.UnknownIrreversible {
			return ErrNotRetry
		}
		a, err := s.loadAutomation(ctx, q, c.Org, x.Automation)
		if err != nil {
			return err
		}
		if a.Version != x.Version {
			return ErrNotRetry
		}
		orig, err := q.TriggerOfExecution(ctx, c.Org, &execution)
		if db.IsNoRows(err) {
			return ErrNotRetry
		} else if err != nil {
			return err
		}
		// Only LIVE work is retried: a SHADOW or TEST execution never
		// becomes a LIVE one (D87 P2, T-127).
		if orig.Mode != string(autodomain.ModeLive) {
			return ErrNotRetry
		}
		key := RetryKey(execution, c.Principal.ID, idem)
		if prior, ok, err := s.repeat(ctx, q, c.Org, a.ID, key); err != nil || ok {
			out = prior
			return err
		}
		var params map[string]autodomain.Value
		if err := json.Unmarshal(orig.Params, &params); err != nil {
			return err
		}
		auth, detail, err := s.checkStepUp(ctx, tx, c, a.Def, su)
		if err != nil {
			return err
		}
		detail["retried_from"] = execution.String()
		// A retry is a new start, not a continuation: its lineage is the
		// original trigger's, so a retry never escapes a loop refusal.
		lin := Lineage{Root: orig.RootTriggerID, Ancestry: orig.Ancestry, Depth: int(orig.Depth)}
		if lin.Depth == 0 {
			lin = Lineage{}
		}
		out, err = s.Fire(ctx, tx, Candidate{
			Automation: a, Kind: autodomain.TriggerManual, Authenticity: auth, Detail: detail,
			SourceRef: "user:" + c.Principal.ID.String(), Params: params, Lineage: lin,
			BaseKey: key, RetriedFrom: &execution, QueueOK: false,
		})
		return err
	})
	return out, err
}

func (s *Service) loadAutomation(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Automation, error) {
	r, err := q.AutomationForTrigger(ctx, org, id)
	if db.IsNoRows(err) {
		return Automation{}, ErrNotFound
	} else if err != nil {
		return Automation{}, err
	}
	return automationOf(r.ID, r.Name, r.State, r.Rollout, r.ServiceAccountID, r.OwnerUserID, r.VersionID, r.Definition)
}

// ManualForm is what the start page shows: the automation, its declared
// parameters and whether starting needs a step-up.
type ManualForm struct {
	Automation ids.UUID
	Name       string
	Params     map[string]autodomain.ParamSpec
	StepUp     bool
}

// Form returns the manual start form of an automation (automation.run).
func (s *Service) Form(ctx context.Context, automation ids.UUID) (ManualForm, error) {
	c, err := s.runner(ctx)
	if err != nil {
		return ManualForm{}, err
	}
	var out ManualForm
	err = s.d.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		a, err := s.loadAutomation(ctx, dbq.New(tx), c.Org, automation)
		if err != nil {
			return err
		}
		if a.Def.When.Manual == nil {
			return ErrNotManual
		}
		need, err := s.requiresStepUp(ctx, c.Org, a.Def)
		if err != nil {
			return err
		}
		out = ManualForm{Automation: a.ID, Name: a.Name, Params: a.Def.When.Manual.Params, StepUp: need}
		return nil
	}, db.ReadOnly())
	return out, err
}

// repeat returns the trigger a person's earlier start with the same key
// recorded (D87 L7): a repeat answers with the original, never a refusal.
func (s *Service) repeat(ctx context.Context, q *dbq.Queries, org ids.OrgID, automation ids.UUID, key string) (Outcome, bool, error) {
	id, err := q.DedupeClaim(ctx, org, automation, key)
	if db.IsNoRows(err) {
		return Outcome{}, false, nil
	} else if err != nil {
		return Outcome{}, false, err
	}
	t, err := q.GetAutomationTrigger(ctx, org, id)
	if err != nil {
		return Outcome{}, false, err
	}
	out := Outcome{Trigger: t.ID, State: State(t.State)}
	if t.Reason != nil {
		out.Reason = *t.Reason
	}
	if t.ExecutionID != nil {
		out.Execution = *t.ExecutionID
	}
	return out, true, nil
}
