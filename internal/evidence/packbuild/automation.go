// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// CodeExecutionUnavailable marks a pack of an automation execution the
// creator cannot read (automation.read), or that is gone.
const CodeExecutionUnavailable = "EXECUTION_UNAVAILABLE"

var errExecution = errors.New("packbuild: the execution is not one the creator may read")

// Executions reads an execution as its caller may see it (the engine's
// inspector, D29): grants and runs follow the caller's agent scope.
type Executions interface {
	GetExecution(ctx context.Context, id ids.UUID) (pgengine.Inspection, error)
}

// execData is the execution a pack of scope automation_execution reports.
type execData struct {
	in            pgengine.Inspection
	confirmations []dbq.ListChangeConfirmationsRow
	transactions  []ids.UUID
}

// loadExecution reads the execution as the creator (automation.read).
func (b *builder) loadExecution() (*execData, error) {
	if b.s.Executions == nil {
		return nil, errExecution
	}
	id, err := ids.ParseUUID(b.r.scope.Execution)
	if err != nil {
		return nil, errExecution
	}
	in, err := b.s.Executions.GetExecution(b.ctx, id)
	if err != nil {
		return nil, errExecution
	}
	out := &execData{in: in}
	err = b.s.Pool.InTenantTx(b.ctx, b.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, err := q.GetAutomationVersion(ctx, b.org, in.Row.VersionID)
		if err != nil {
			return err
		}
		if v.ChangeRequestID != nil {
			if out.confirmations, err = q.ListChangeConfirmations(ctx, b.org, *v.ChangeRequestID); err != nil {
				return err
			}
		}
		out.transactions, err = q.ExecutionTransactions(ctx, b.org, &id)
		return err
	}, db.ReadOnly())
	return out, err
}

// The files of an execution pack (D30). Completion statements reference
// their evidence: the transactions with effect receipts and the deliveries
// a finish condition names.
type (
	automationRecord struct {
		Format       string             `json:"format"`
		Execution    automationExec     `json:"execution"`
		Trigger      automationTrigger  `json:"trigger"`
		Version      automationVersion  `json:"version"`
		Ceiling      *automationCeiling `json:"ceiling,omitzero"`
		Steps        []automationStep   `json:"steps"`
		Result       *automationResult  `json:"result,omitzero"`
		Grants       []automationGrant  `json:"grants"`
		Runs         []automationRun    `json:"runs"`
		Launches     []automationLaunch `json:"launches"`
		Gates        []automationGate   `json:"gates"`
		Deliveries   []automationDeliv  `json:"deliveries"`
		Transactions []string           `json:"transactions"`
	}
	automationExec struct {
		ID             string `json:"id"`
		Automation     string `json:"automation"`
		Name           string `json:"name"`
		Owner          string `json:"owner"`
		Mode           string `json:"mode"`
		State          string `json:"state"`
		Reason         string `json:"reason,omitzero"`
		ServiceAccount string `json:"service_account"`
		Principal      string `json:"principal"`
		Created        string `json:"created"`
		Started        string `json:"started,omitzero"`
		Deadline       string `json:"deadline"`
		Ended          string `json:"ended,omitzero"`
	}
	automationTrigger struct {
		ID           string            `json:"id"`
		Kind         string            `json:"kind"`
		Authenticity string            `json:"authenticity"`
		SourceRef    string            `json:"source_ref"`
		Detail       map[string]string `json:"authenticity_detail"`
		Params       map[string]string `json:"params"`
		Root         string            `json:"root"`
		Ancestry     []string          `json:"ancestry"`
		Depth        int               `json:"depth"`
	}
	automationVersion struct {
		ID            string                   `json:"id"`
		Number        int32                    `json:"number"`
		Digest        string                   `json:"digest"`
		Summary       string                   `json:"summary"`
		Confirmations []automationConfirmation `json:"confirmations"`
	}
	automationConfirmation struct {
		User       string `json:"user"`
		Credential string `json:"credential"`
		At         string `json:"at"`
	}
	automationCeiling struct {
		ID         string   `json:"id"`
		ApprovedBy []string `json:"approved_by"`
		ReviewBy   string   `json:"review_by"`
		State      string   `json:"state"`
	}
	automationStep struct {
		Step         string          `json:"step"`
		Kind         string          `json:"kind"`
		Attempt      int             `json:"attempt"`
		Compensation bool            `json:"compensation"`
		State        string          `json:"state"`
		Decision     string          `json:"decision"`
		Reason       string          `json:"reason,omitzero"`
		Effect       string          `json:"effect"`
		Started      string          `json:"started"`
		Ended        string          `json:"ended,omitzero"`
		Refs         []automationRef `json:"refs"`
	}
	automationRef struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	automationResult struct {
		State       string             `json:"state"`
		Reason      string             `json:"reason,omitzero"`
		Changed     []string           `json:"changed"`
		Unchanged   []string           `json:"unchanged"`
		Unknown     []string           `json:"unknown"`
		Compensated []string           `json:"compensated,omitzero"`
		Finish      []automationFinish `json:"finish"`
		Unresolved  []string           `json:"unresolved,omitzero"`
		Cleanup     []automationRef    `json:"cleanup,omitzero"`
	}
	automationFinish struct {
		Step      string          `json:"step"`
		Condition string          `json:"condition"`
		Met       bool            `json:"met"`
		Refs      []automationRef `json:"refs,omitzero"`
	}
	automationGrant struct {
		ID          string   `json:"id"`
		Agent       string   `json:"agent"`
		State       string   `json:"state"`
		Expires     string   `json:"expires"`
		BudgetLimit []string `json:"budget_limit,omitzero"`
		BudgetUsed  []string `json:"budget_used,omitzero"`
	}
	automationRun struct {
		ID           string `json:"id"`
		Agent        string `json:"agent"`
		State        string `json:"state"`
		Expires      string `json:"expires"`
		Transactions int32  `json:"transactions"`
		Unknown      int32  `json:"unknown_transactions"`
	}
	automationLaunch struct {
		ID       string `json:"id"`
		Agent    string `json:"agent"`
		Run      string `json:"run"`
		Grant    string `json:"grant"`
		State    string `json:"state"`
		Delivery string `json:"delivery"`
	}
	automationGate struct {
		Request   string `json:"request"`
		Step      string `json:"step"`
		State     string `json:"state"`
		Deadline  string `json:"deadline"`
		Needed    int    `json:"approvals_needed"`
		Approvals int    `json:"approvals"`
	}
	automationDeliv struct {
		ID          string `json:"id"`
		Destination string `json:"destination"`
		Kind        string `json:"kind"`
		State       string `json:"state"`
	}
)

// AutomationFormat is the format of automation/execution.json.
const AutomationFormat = "pantherclaw.automation-execution/v1"

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func refsOf(rs []reflexdomain.EvidenceRef) []automationRef {
	out := make([]automationRef, 0, len(rs))
	for _, r := range rs {
		out = append(out, automationRef{Kind: r.Kind, ID: r.ID.String()})
	}
	return out
}

func strs(us []ids.UUID) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.String())
	}
	return out
}

// automation adds automation/execution.json (D30).
func (b *builder) automation() error {
	d := b.execData
	in, r := d.in, d.in.Row
	rec := automationRecord{
		Format: AutomationFormat,
		Execution: automationExec{
			ID: r.ID.String(), Automation: r.AutomationID.String(), Name: in.AutomationName, Owner: in.Owner.String(),
			Mode: r.Mode, State: r.State, ServiceAccount: r.ServiceAccountID.String(), Created: rfc3339(r.CreatedAt),
			Deadline: rfc3339(r.DeadlineAt),
		},
		Trigger: automationTrigger{
			ID: r.TriggerID.String(), Kind: in.Trigger.Kind, Authenticity: in.Trigger.Authenticity,
			SourceRef: in.Trigger.SourceRef, Detail: in.Trigger.Detail, Root: r.RootTriggerID.String(),
			Ancestry: strs(r.Ancestry), Depth: int(r.Depth), Params: map[string]string{},
		},
		Version: automationVersion{
			ID: r.VersionID.String(), Number: in.VersionNumber, Digest: in.VersionDigest, Summary: in.VersionSummary,
			Confirmations: []automationConfirmation{},
		},
		Steps: []automationStep{}, Grants: []automationGrant{}, Runs: []automationRun{}, Launches: []automationLaunch{},
		Gates: []automationGate{}, Deliveries: []automationDeliv{}, Transactions: strs(d.transactions),
	}
	if r.Reason != nil {
		rec.Execution.Reason = *r.Reason
	}
	if r.StartedAt != nil {
		rec.Execution.Started = rfc3339(*r.StartedAt)
	}
	if r.EndedAt != nil {
		rec.Execution.Ended = rfc3339(*r.EndedAt)
	}
	switch {
	case r.PrincipalUserID != nil:
		rec.Execution.Principal = "user:" + r.PrincipalUserID.String()
	case r.PrincipalSaID != nil:
		rec.Execution.Principal = "service_account:" + r.PrincipalSaID.String()
	}
	if params, err := pgengine.DecodeParams(r.Params); err == nil {
		for k, v := range params {
			rec.Trigger.Params[k] = v.Text()
		}
	}
	for _, c := range d.confirmations {
		rec.Version.Confirmations = append(rec.Version.Confirmations, automationConfirmation{
			User: c.UserID.String(), Credential: c.CredentialID.String(), At: rfc3339(c.ConfirmedAt),
		})
	}
	if c := in.Ceiling; c != nil {
		rec.Ceiling = &automationCeiling{ID: c.ID.String(), ReviewBy: rfc3339(c.ReviewBy), State: c.State, ApprovedBy: strs(c.ApprovedBy)}
	}
	for _, a := range in.Attempts {
		decision := "ALLOWED"
		if a.Refused {
			decision = "REFUSED"
		}
		rec.Steps = append(rec.Steps, automationStep{
			Step: a.StepID, Kind: a.Kind, State: string(a.State), Decision: decision, Reason: a.Reason,
			Effect: string(a.Effect), Started: rfc3339(a.StartedAt), Ended: rfc3339(a.EndedAt), Attempt: a.Number,
			Compensation: a.Compensation, Refs: refsOf(a.Refs),
		})
	}
	if res := in.Result; res != nil {
		out := &automationResult{
			State: string(res.State), Reason: res.Reason, Changed: res.Changed, Unchanged: res.Unchanged,
			Unknown: res.Unknown, Compensated: res.Compensated, Cleanup: refsOf(res.Cleanup),
		}
		for _, f := range res.Finish {
			out.Finish = append(out.Finish, automationFinish{Step: f.Step, Condition: string(f.Condition), Met: f.Met, Refs: refsOf(f.Refs)})
		}
		for _, u := range res.Unresolved {
			out.Unresolved = append(out.Unresolved, u.Step+" "+u.Kind)
		}
		rec.Result = out
	}
	for _, g := range in.Grants {
		rec.Grants = append(rec.Grants, automationGrant{
			ID: g.ID.String(), Agent: g.Agent.String(), State: g.State, Expires: rfc3339(g.ExpiresAt),
			BudgetLimit: g.BudgetLimit, BudgetUsed: g.BudgetUsed,
		})
	}
	for _, x := range in.Runs {
		rec.Runs = append(rec.Runs, automationRun{
			ID: x.ID.String(), Agent: x.AgentID.String(), State: x.EffectiveState, Expires: rfc3339(x.ExpiresAt),
			Transactions: x.Transactions, Unknown: x.Unknown,
		})
	}
	for _, l := range in.Launches {
		rec.Launches = append(rec.Launches, automationLaunch{
			ID: l.ID.String(), Agent: l.AgentID.String(), Run: l.RunID.String(), Grant: l.GrantID.String(), State: l.State,
			Delivery: l.Delivery,
		})
	}
	for _, g := range in.Gates {
		rec.Gates = append(rec.Gates, automationGate{
			Request: g.Request.String(), Step: g.Step, State: g.State, Deadline: rfc3339(g.Deadline), Needed: g.Needed,
			Approvals: g.Approvals,
		})
	}
	for _, x := range in.Deliveries {
		rec.Deliveries = append(rec.Deliveries, automationDeliv{
			ID: x.ID.String(), Destination: x.DestinationID.String(), Kind: x.Kind, State: x.State,
		})
	}
	return b.add("automation/execution.json", pack.KindAutomation, rec)
}
