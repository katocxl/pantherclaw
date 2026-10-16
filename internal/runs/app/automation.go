// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/automationctx"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Runs for automations (G0 M11 part 2 D10, HR-271, HR-274). The engine
// starts a run of a ceiling agent in its own transaction, launched by the
// automation's identity, for the principal the version declares, bound to
// the grant the execution was just issued. Only the engine calls these:
// never an RPC handler, never a role check.

// AutomationRuns counts an automation's runs against its daily cap (the
// automations app); dryRun only checks.
type AutomationRuns interface {
	ReserveRun(ctx context.Context, tx db.TenantTx, org ids.OrgID, automation ids.UUID, dryRun bool) error
}

// ErrNotAutomationRun refuses ending a run that is not the execution's.
var ErrNotAutomationRun = pcerr.New(pcerr.FailedPrecondition, "NOT_AUTOMATION_RUN", "the run was not started by this execution")

// AutomationStart starts one run for an execution.
type AutomationStart struct {
	Org            ids.OrgID
	Automation     ids.UUID
	Version        ids.UUID
	Execution      ids.UUID
	Trigger        ids.UUID
	ServiceAccount ids.UUID
	AgentID        ids.UUID
	InstanceID     *ids.UUID
	GrantID        ids.UUID
	Principal      gdomain.Principal
	TaskRef        string
	TTL            time.Duration
	// DryRun checks the agent, instance and daily cap and writes nothing
	// (shadow, previews).
	DryRun bool
}

// StartForAutomationTx starts the run in the caller's transaction.
func (s *Service) StartForAutomationTx(ctx context.Context, tx db.TenantTx, in AutomationStart) (Run, error) {
	if in.TTL == 0 {
		in.TTL = DefaultTTL
	}
	minutes, err := checkLabel(in.TaskRef, in.TTL)
	if err != nil {
		return Run{}, err
	}
	if in.Org != tx.OrgID() || in.ServiceAccount.IsZero() || in.Execution.IsZero() {
		return Run{}, ErrLauncher
	}
	q := dbq.New(tx)
	a, err := usableAgent(ctx, q, in.Org, in.AgentID)
	if err != nil {
		return Run{}, err
	}
	if in.InstanceID != nil {
		if err := admittedInstance(ctx, q, in.Org, a.ID, *in.InstanceID); err != nil {
			return Run{}, err
		}
	}
	if s.automationRuns != nil {
		if err := s.automationRuns.ReserveRun(ctx, tx, in.Org, in.Automation, true); err != nil {
			return Run{}, err
		}
	}
	if in.DryRun {
		return Run{AgentID: a.ID, InstanceID: in.InstanceID, EnvironmentID: *a.EnvironmentID, PrincipalSource: SourceAutomation}, nil
	}
	sa := in.ServiceAccount
	exec := in.Execution
	launcher := Actor{Kind: string(td.KindServiceAccount), ID: sa.String()}
	p := dbq.InsertRunParams{
		OrgID: in.Org, ID: ids.NewV7(), AgentID: a.ID, InstanceID: in.InstanceID, EnvironmentID: *a.EnvironmentID,
		PrincipalSource: SourceAutomation, TaskRef: in.TaskRef, TtlMinutes: minutes, Simulated: a.RangeAgent,
		LauncherSaID: &sa, AutomationExecutionID: &exec,
	}
	principal := in.Principal.ID
	switch in.Principal.Kind {
	case gdomain.PrincipalUser:
		p.PrincipalUserID = &principal
	case gdomain.PrincipalServiceAccount:
		p.PrincipalSaID = &principal
	case gdomain.PrincipalInstance:
		return Run{}, ErrLauncher
	}
	chain := []Actor{{Kind: string(in.Principal.Kind), ID: principal.String()}}
	if principal != sa {
		chain = append(chain, launcher)
	}
	if p.ActorChain, err = json.Marshal(chain); err != nil {
		return Run{}, err
	}
	if err := s.bindGrant(ctx, tx, in.Org, in.GrantID, &p); err != nil {
		return Run{}, err
	}
	ctx = automationctx.With(ctx, automationctx.Ref{Automation: in.Automation, Version: in.Version, Execution: in.Execution, Trigger: in.Trigger})
	var out Run
	err = tx.Savepoint(ctx, "automation_run", func() error {
		if s.automationRuns != nil {
			if err := s.automationRuns.ReserveRun(ctx, tx, in.Org, in.Automation, false); err != nil {
				return err
			}
		}
		r, err := q.InsertRun(ctx, p)
		if err != nil {
			return err
		}
		if out, err = view(r, r.State); err != nil {
			return err
		}
		return record(ctx, tx, evdomain.Actor{Type: launcher.Kind, ID: launcher.ID}, "run.started", out)
	})
	return out, err
}

// EndForAutomationTx ends a run the execution started, and its child runs,
// in the caller's transaction (cleanup, cancellation, RevokeAuthority). A
// run that already ended is left as it is.
func (s *Service) EndForAutomationTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, execution, serviceAccount, run ids.UUID, reason string) (Run, error) {
	if reason == "" || len(reason) > 64 {
		return Run{}, ErrReason
	}
	q := dbq.New(tx)
	r, err := q.GetRun(ctx, org, run)
	if db.IsNoRows(err) {
		return Run{}, ErrRunNotFound
	} else if err != nil {
		return Run{}, err
	}
	if r.PcRun.AutomationExecutionID == nil || *r.PcRun.AutomationExecutionID != execution {
		return Run{}, ErrNotAutomationRun
	}
	if r.EffectiveState != "ACTIVE" {
		return view(r.PcRun, r.EffectiveState)
	}
	rows, err := q.EndRunTree(ctx, dbq.EndRunTreeParams{OrgID: org, ID: run, State: "ENDED", Reason: reason})
	if err != nil {
		return Run{}, err
	}
	var out Run
	for _, x := range rows {
		if x.ID == run {
			if out, err = view(x, x.State); err != nil {
				return Run{}, err
			}
		}
	}
	return out, recordEnd(ctx, tx, evdomain.Actor{Type: string(td.KindServiceAccount), ID: serviceAccount.String()}, out, len(rows)-1)
}

// WithAutomationRuns counts automation runs against their daily cap (G0
// M11 part 2 D9).
func (s *Service) WithAutomationRuns(r AutomationRuns) *Service {
	s.automationRuns = r
	return s
}
