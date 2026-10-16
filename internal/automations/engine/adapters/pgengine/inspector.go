// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// ErrHumanOnly refuses a control made by anything but a person.
var ErrHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person controls executions")

// Summary is an execution as lists and lookups show it (D29).
type Summary struct {
	Row            dbq.PcAutomationExecution
	AutomationName string
	Owner          ids.UUID
	VersionNumber  int32
	VersionDigest  string
	VersionSummary string
	Trigger        TriggerView
	Ceiling        *CeilingView
	Result         *engine.Result
}

// TriggerView is how an execution's trigger was established.
type TriggerView struct {
	Kind         string
	Authenticity string
	Detail       map[string]string
	SourceRef    string
}

// CeilingView is the authority an execution issued under.
type CeilingView struct {
	ID         ids.UUID
	ApprovedBy []ids.UUID
	ReviewBy   time.Time
	State      string
}

// GrantView is a grant an execution issued, with its budgets: the limit
// of each budget rule and what its accounts spent, as "<rule> <currency>
// <amount>".
type GrantView struct {
	ID          ids.UUID
	Agent       ids.UUID
	State       string
	ExpiresAt   time.Time
	BudgetLimit []string
	BudgetUsed  []string
}

// GateView is a gate of an execution.
type GateView struct {
	Request   ids.UUID
	Step      string
	State     string
	Deadline  time.Time
	Needed    int
	Approvals int
}

// Inspection is everything an execution caused (D29, F715–F722).
type Inspection struct {
	Summary
	Attempts   []engine.Attempt
	Grants     []GrantView
	Runs       []dbq.ExecutionRunsRow
	Launches   []dbq.PcAutomationLaunch
	Gates      []GateView
	Deliveries []dbq.ExecutionDeliveriesRow
}

// ExecutionFilter narrows ListExecutions.
type ExecutionFilter struct {
	Automation   ids.UUID
	States       []autodomain.ExecutionState
	Mode         autodomain.Mode
	Since, Until time.Time
}

func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Can(td.PermAutomationRead, td.OrgPath(c.Org)) {
		return c, td.ErrPermissionDenied(td.PermAutomationRead)
	}
	return c, nil
}

// GetExecution returns one execution with what it caused (automation.read).
// Grants and runs are listed for the agents the caller may read, so
// transaction details follow the viewer's agent scope.
func (e *Engine) GetExecution(ctx context.Context, id ids.UUID) (Inspection, error) {
	c, err := reader(ctx)
	if err != nil {
		return Inspection{}, err
	}
	var out Inspection
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetAutomationExecution(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if out.Summary, err = e.summarize(ctx, q, row); err != nil {
			return err
		}
		attempts, err := q.ListAutomationStepAttempts(ctx, c.Org, id)
		if err != nil {
			return err
		}
		for _, s := range attempts {
			a, err := attemptOf(s)
			if err != nil {
				return err
			}
			out.Attempts = append(out.Attempts, *a)
		}
		scope := txapp.NewAgentScope(c, q, td.PermAgentRead)
		grants, err := q.ExecutionGrants(ctx, c.Org, &id)
		if err != nil {
			return err
		}
		for _, g := range grants {
			if ok, err := scope.Can(ctx, g.AgentID); err != nil {
				return err
			} else if ok {
				out.Grants = append(out.Grants, grantView(g))
			}
		}
		runs, err := q.ExecutionRuns(ctx, c.Org, &id)
		if err != nil {
			return err
		}
		for _, r := range runs {
			if ok, err := scope.Can(ctx, r.AgentID); err != nil {
				return err
			} else if ok {
				out.Runs = append(out.Runs, r)
			}
		}
		if out.Launches, err = q.ExecutionLaunches(ctx, c.Org, id); err != nil {
			return err
		}
		gates, err := q.ExecutionGates(ctx, c.Org, &id)
		if err != nil {
			return err
		}
		for _, g := range gates {
			out.Gates = append(out.Gates, gateView(g))
		}
		out.Deliveries, err = q.ExecutionDeliveries(ctx, c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListExecutions lists executions newest first (automation.read).
func (e *Engine) ListExecutions(ctx context.Context, pr page.Request, f ExecutionFilter) ([]Summary, string, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, "", err
	}
	p := dbq.ListAutomationExecutionsParams{OrgID: c.Org, States: []string{}, PageLimit: pr.Limit()}
	if !f.Automation.IsZero() {
		p.AutomationID = &f.Automation
	}
	for _, s := range f.States {
		p.States = append(p.States, string(s))
	}
	if f.Mode != "" {
		m := string(f.Mode)
		p.Mode = &m
	}
	if !f.Since.IsZero() {
		p.Since = &f.Since
	}
	if !f.Until.IsZero() {
		p.Until = &f.Until
	}
	if !pr.After.IsZero() {
		p.Before = &pr.After
	}
	var out []Summary
	var next string
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListAutomationExecutions(ctx, p)
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.PcAutomationExecution) ids.UUID { return r.ID })
		for _, r := range rows {
			s, err := e.summarize(ctx, q, r)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

// Lookup kinds of LookupExecution.
const (
	LookupRun         = "run"
	LookupGrant       = "grant"
	LookupTransaction = "transaction"
)

// LookupExecution finds the execution that caused a run, a grant or a
// transaction (automation.read), for drill-down from investigations and
// search (D29, F222).
func (e *Engine) LookupExecution(ctx context.Context, kind string, id ids.UUID) (Summary, error) {
	c, err := reader(ctx)
	if err != nil {
		return Summary{}, err
	}
	var out Summary
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var exec ids.UUID
		switch kind {
		case LookupRun:
			exec, err = q.ExecutionOfRun(ctx, c.Org, id)
		case LookupGrant:
			exec, err = q.ExecutionOfGrant(ctx, c.Org, id)
		case LookupTransaction:
			exec, err = q.ExecutionOfTransaction(ctx, c.Org, id)
		default:
			return ErrNotFound
		}
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		row, err := q.GetAutomationExecution(ctx, c.Org, exec)
		if err != nil {
			return err
		}
		out, err = e.summarize(ctx, q, row)
		out.Result = nil
		return err
	}, db.ReadOnly())
	return out, err
}

// summarize adds the automation, version, trigger and ceiling.
func (e *Engine) summarize(ctx context.Context, q *dbq.Queries, row dbq.PcAutomationExecution) (Summary, error) {
	s := Summary{Row: row}
	a, err := q.GetAutomation(ctx, row.OrgID, row.AutomationID)
	if err != nil {
		return s, err
	}
	s.AutomationName, s.Owner = a.Name, a.OwnerUserID
	v, err := q.GetAutomationVersion(ctx, row.OrgID, row.VersionID)
	if err != nil {
		return s, err
	}
	s.VersionNumber, s.VersionDigest, s.VersionSummary = v.Number, hex.EncodeToString(v.Digest), v.Summary
	t, err := q.ExecutionTrigger(ctx, row.OrgID, row.TriggerID)
	if err != nil {
		return s, err
	}
	s.Trigger = TriggerView{Kind: t.Kind, Authenticity: t.Authenticity, SourceRef: t.SourceRef, Detail: map[string]string{}}
	var detail map[string]any
	if json.Unmarshal(t.AuthenticityDetail, &detail) == nil {
		for k, v := range detail {
			if str, ok := v.(string); ok {
				s.Trigger.Detail[k] = str
			}
		}
	}
	if row.CeilingID != nil {
		c, err := q.GetAutomationCeiling(ctx, row.OrgID, *row.CeilingID)
		if err != nil {
			return s, err
		}
		s.Ceiling = &CeilingView{ID: c.ID, ApprovedBy: c.ApprovedBy, ReviewBy: c.ReviewBy, State: c.State}
	}
	if row.Result != nil {
		r, err := decodeResult(row.Result)
		if err != nil {
			return s, err
		}
		s.Result = &r
	}
	return s, nil
}

func grantView(g dbq.ExecutionGrantsRow) GrantView {
	out := GrantView{ID: g.ID, Agent: g.AgentID, State: g.State, ExpiresAt: g.ExpiresAt}
	var limits gdomain.Limits
	if json.Unmarshal(g.Limits, &limits) == nil {
		for _, b := range limits.Budgets {
			if b.Limit != "" {
				out.BudgetLimit = append(out.BudgetLimit, b.ID+" "+b.Currency+" "+b.Limit)
			}
		}
	}
	var spent map[string]string
	if json.Unmarshal(g.Spent, &spent) == nil {
		for k, v := range spent {
			out.BudgetUsed = append(out.BudgetUsed, k+" "+v)
		}
		slices.Sort(out.BudgetUsed)
	}
	return out
}

func gateView(g dbq.ExecutionGatesRow) GateView {
	out := GateView{Request: g.ID, State: g.State, Deadline: g.DeadlineAt, Approvals: int(g.Approvals)}
	if g.StepID != nil {
		out.Step = *g.StepID
	}
	var reqs []apdomain.Requirement
	if json.Unmarshal(g.Requirements, &reqs) == nil {
		for _, r := range reqs {
			out.Needed += r.Needed()
		}
	}
	return out
}
