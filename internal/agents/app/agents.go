// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Agent is one agent record.
type Agent struct {
	ID                ids.UUID
	Name, Purpose     string
	TeamID            ids.UUID
	EnvironmentID     ids.UUID
	OwnerUserID       ids.UUID
	BackupOwnerUserID ids.UUID
	Context           domain.ExecutionContext
	State             domain.State
	SuspendedFrom     domain.State
	CreatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ClaimedAt         *time.Time
	RetiredAt         *time.Time
	// RangeAgent: all its runs are simulated (G0 M12, HR-220); immutable.
	RangeAgent bool
	// What people state about the agent's risk (G0 M24 D230).
	RiskTier    domain.RiskTier
	DataClasses []string
	AIActRole   domain.AIActRole
	AIActRisk   domain.AIActRisk
	// ScanState is what continuous discovery saw of it; nil when no scan
	// found it (G0 M22 D6).
	ScanState *ScanState
}

// ScanState sums up an agent's scan findings that were not dismissed.
type ScanState struct {
	// MissedScans is the fewest complete scans in a row that missed a finding.
	MissedScans int32
	LastSeenAt  time.Time
	// Vanished: every finding reached the vanish threshold.
	Vanished bool
}

// withScanStates fills in the scan states of agents, which the caller may
// already read.
func withScanStates(ctx context.Context, q *dbq.Queries, org ids.OrgID, agents []Agent) error {
	if len(agents) == 0 {
		return nil
	}
	list := make([]ids.UUID, len(agents))
	for i := range agents {
		list[i] = agents[i].ID
	}
	rows, err := q.AgentScanStates(ctx, org, list)
	if err != nil {
		return err
	}
	states := make(map[ids.UUID]*ScanState, len(rows))
	for _, r := range rows {
		states[r.AgentID] = &ScanState{MissedScans: r.MissedScans, LastSeenAt: r.LastSeenAt, Vanished: r.Vanished}
	}
	for i := range agents {
		agents[i].ScanState = states[agents[i].ID]
	}
	return nil
}

// Discovery is what was observed about a discovered agent. Observed holds
// untrusted values.
type Discovery struct {
	ID            ids.UUID
	Source        string
	KeyThumbprint string
	State         string
	SeenCount     int64
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	Observed      map[string]string
}

// Summary answers who owns an agent, what it is for and how its identity
// is verified (F017, F031, F624).
type Summary struct {
	Agent
	Activity          domain.ActivityStatus
	NextAction        string
	PendingInstances  int
	AdmittedInstances int
	HighestLevel      int
	LastVerifiedAt    *time.Time
	ActiveRuns        int
	OpenEntries       int
	NeedingReview     int
	Discovery         *Discovery
}

// Change is one history entry.
type Change struct {
	ID        ids.UUID
	AgentID   ids.UUID
	Kind      string
	Actor     string
	Reason    string
	Details   map[string]string
	CreatedAt time.Time
}

// Page is one page of results.
type Page[T any] struct {
	Items []T
	Next  string
}

func agentView(r dbq.PcAgent) Agent {
	a := Agent{
		ID: r.ID, Name: r.Name, Purpose: r.Purpose, State: domain.State(r.State), CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, ClaimedAt: r.ClaimedAt, RetiredAt: r.RetiredAt,
		RangeAgent: r.RangeAgent, RiskTier: domain.RiskTier(r.RiskTier), DataClasses: r.DataClasses,
		AIActRole: domain.AIActRole(r.AiActRole), AIActRisk: domain.AIActRisk(r.AiActRisk),
	}
	for dst, src := range map[*ids.UUID]*ids.UUID{
		&a.TeamID: r.TeamID, &a.EnvironmentID: r.EnvironmentID, &a.OwnerUserID: r.OwnerUserID,
		&a.BackupOwnerUserID: r.BackupOwnerUserID,
	} {
		if src != nil {
			*dst = *src
		}
	}
	if r.ExecutionContext != nil {
		a.Context = domain.ExecutionContext(*r.ExecutionContext)
	}
	if r.SuspendedFrom != nil {
		a.SuspendedFrom = domain.State(*r.SuspendedFrom)
	}
	return a
}

// Create creates a claimed agent (F016), subject to the edition limit.
func (inv *Inventory) Create(ctx context.Context, d domain.Details) (Agent, error) {
	if err := d.Validate(); err != nil {
		return Agent{}, invalid(err)
	}
	var out Agent
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		p, err := place(ctx, q, c.Org, d.TeamID, d.EnvironmentID)
		if err != nil {
			return err
		}
		if err := c.Require(td.PermAgentManage, p.path); err != nil {
			return err
		}
		if err := checkOwners(ctx, q, c.Org, d.OwnerUserID, d.BackupOwnerUserID); err != nil {
			return err
		}
		limit := inv.checkLimit
		if d.RangeAgent {
			limit = inv.checkRangeLimit
		}
		if err := limit(ctx, q, c.Org); err != nil {
			return err
		}
		r, err := q.InsertAgent(ctx, dbq.InsertAgentParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: d.Name, Purpose: d.Purpose, TeamID: &d.TeamID,
			EnvironmentID: &d.EnvironmentID, OwnerUserID: &d.OwnerUserID, BackupOwnerUserID: optUUID(d.BackupOwnerUserID),
			ExecutionContext: ptr(string(d.Context)), CreatedBy: c.Principal.String(), RangeAgent: d.RangeAgent,
		})
		if err != nil {
			return err
		}
		out = agentView(r)
		if err := RecordChange(ctx, q, c.Org, r.ID, domain.Change{
			Kind: domain.ChangeCreated, Actor: actor(c),
			Details: createDetails(d),
		}); err != nil {
			return err
		}
		return record(ctx, tx, c, "agents.agent_created", r.ID, auditDetails(d))
	})
	return out, err
}

// createDetails are the details of the created change; a range agent says so.
func createDetails(d domain.Details) map[string]string {
	m := map[string]string{"owner_user_id": d.OwnerUserID.String(), "execution_context": string(d.Context)}
	if d.RangeAgent {
		m["range_agent"] = "true"
	}
	return m
}

func auditDetails(d domain.Details) map[string]string {
	m := map[string]string{"execution_context": string(d.Context)}
	if d.RangeAgent {
		m["range_agent"] = "true"
	}
	return m
}

// Get returns an agent's summary.
func (inv *Inventory) Get(ctx context.Context, id ids.UUID) (Summary, error) {
	var out Summary
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, _ db.TenantTx) error {
		r, err := load(ctx, c, q, id, td.PermAgentRead, false)
		if err != nil {
			return err
		}
		n, err := q.AgentSummaryCounts(ctx, c.Org, r.ID)
		if err != nil {
			return err
		}
		one := []Agent{agentView(r)}
		if err := withScanStates(ctx, q, c.Org, one); err != nil {
			return err
		}
		a := one[0]
		out = Summary{
			Agent: a, NextAction: a.State.NextAction(),
			Activity:         domain.Activity(n.EverAdmitted > 0, observed(a.State, a.SuspendedFrom)),
			PendingInstances: int(n.Pending), AdmittedInstances: int(n.Admitted), HighestLevel: int(n.HighestLevel),
			ActiveRuns: int(n.ActiveRuns), OpenEntries: int(n.OpenEntries), NeedingReview: int(n.NeedsReview),
		}
		if n.LastSeen.Unix() > 0 {
			t := n.LastSeen
			out.LastVerifiedAt = &t
		}
		d, err := q.GetAgentDiscovery(ctx, c.Org, r.ID)
		if err == nil {
			out.Discovery = discoveryView(d)
		} else if !db.IsNoRows(err) {
			return err
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// observed reports whether an agent in state s has ever made a verified
// request (F624).
func observed(s, suspendedFrom domain.State) bool {
	if s == domain.StateSuspended {
		s = suspendedFrom
	}
	switch s {
	case domain.StateObserved, domain.StatePartiallyProtected, domain.StateProtected:
		return true
	case domain.StateDiscovered, domain.StateClaimed, domain.StateVerified, domain.StateSuspended, domain.StateRetired:
		return false
	}
	return false
}

func discoveryView(d dbq.PcDiscovery) *Discovery {
	out := &Discovery{
		ID: d.ID, Source: d.Source, State: d.State, SeenCount: d.SeenCount,
		FirstSeenAt: d.FirstSeenAt, LastSeenAt: d.LastSeenAt, Observed: map[string]string{},
	}
	if d.KeyJkt != nil {
		out.KeyThumbprint = *d.KeyJkt
	}
	// Observed values are untrusted strings; anything else is dropped.
	var raw map[string]any
	if err := json.Unmarshal(d.Observed, &raw); err == nil {
		for k, v := range raw {
			if s, ok := v.(string); ok {
				out.Observed[k] = s
			}
		}
	}
	return out
}

// List lists the agents the caller may read.
func (inv *Inventory) List(ctx context.Context, pr page.Request, states []domain.State, team ids.UUID) (Page[Agent], bool, error) {
	var out Page[Agent]
	var none bool
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, _ db.TenantTx) error {
		ss := make([]string, len(states))
		for i, s := range states {
			ss[i] = string(s)
		}
		rows, err := q.ListAgents(ctx, dbq.ListAgentsParams{
			OrgID: c.Org, After: pr.After, States: ss, TeamID: optUUID(team), PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcAgent) ids.UUID { return r.ID })
		for _, r := range rows {
			path, err := PathOf(ctx, q, r)
			if err != nil {
				return err
			}
			if c.Can(td.PermAgentRead, path) {
				out.Items = append(out.Items, agentView(r))
			}
		}
		if err := withScanStates(ctx, q, c.Org, out.Items); err != nil {
			return err
		}
		if len(out.Items) == 0 && pr.After.IsZero() {
			has, err := q.OrgHasAgents(ctx, c.Org)
			if err != nil {
				return err
			}
			none = !has
		}
		return nil
	}, db.ReadOnly())
	return out, none, err
}

// Update changes an agent's name, purpose or stated risk (G0 M24 D230). The
// execution context never changes (G0 M3 constraint 16).
func (inv *Inventory) Update(ctx context.Context, id ids.UUID, name, purpose *string, risk domain.RiskPatch) (Agent, error) {
	if name != nil {
		if err := domain.ValidateName(*name); err != nil {
			return Agent{}, invalid(err)
		}
	}
	if purpose != nil {
		if err := domain.ValidatePurpose(*purpose); err != nil {
			return Agent{}, invalid(err)
		}
	}
	if err := risk.Validate(defs.DataClasses); err != nil {
		return Agent{}, invalid(err)
	}
	stated := risk.Details()
	var out Agent
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := load(ctx, c, q, id, td.PermAgentManage, false)
		if err != nil {
			return err
		}
		if len(stated) > 0 {
			if r, err = updateRisk(ctx, tx, q, c, r.ID, risk, stated); err != nil {
				return err
			}
		}
		out = agentView(r)
		if name == nil && purpose == nil && len(stated) > 0 {
			return nil
		}
		r, err = q.UpdateAgentText(ctx, dbq.UpdateAgentTextParams{OrgID: c.Org, ID: r.ID, Name: name, Purpose: purpose})
		if err != nil {
			return notFound(err, ErrState)
		}
		out = agentView(r)
		fields := map[string]string{}
		if name != nil {
			fields["name"] = "changed"
		}
		if purpose != nil {
			fields["purpose"] = "changed"
		}
		if err := RecordChange(ctx, q, c.Org, r.ID, domain.Change{Kind: domain.ChangeUpdated, Actor: actor(c), Details: fields}); err != nil {
			return err
		}
		return record(ctx, tx, c, "agents.agent_updated", r.ID, fields)
	})
	return out, err
}

// updateRisk writes the stated risk fields, with a history entry and an audit
// record.
func updateRisk(ctx context.Context, tx db.TenantTx, q *dbq.Queries, c tenancy.Caller, id ids.UUID, risk domain.RiskPatch, stated map[string]string) (dbq.PcAgent, error) {
	p := dbq.UpdateAgentRiskParams{OrgID: c.Org, ID: id, DataClasses: risk.DataClasses}
	if risk.Tier != nil {
		p.RiskTier = ptr(string(*risk.Tier))
	}
	if risk.Role != nil {
		p.AiActRole = ptr(string(*risk.Role))
	}
	if risk.Risk != nil {
		p.AiActRisk = ptr(string(*risk.Risk))
	}
	r, err := q.UpdateAgentRisk(ctx, p)
	if err != nil {
		return dbq.PcAgent{}, notFound(err, ErrState)
	}
	if err := RecordChange(ctx, q, c.Org, id, domain.Change{Kind: domain.ChangeRiskUpdated, Actor: actor(c), Details: stated}); err != nil {
		return dbq.PcAgent{}, err
	}
	return r, record(ctx, tx, c, "agents.risk_updated", id, stated)
}

// maxCardTools is the most approved tools one card lists.
const maxCardTools = 500

// ApprovedTool is one operation on an agent's card.
type ApprovedTool struct {
	ConnectionID                 ids.UUID
	Connection, Package, Version string
	Operation                    string
}

// Card is the one-page account of an agent (G0 M24 D231).
type Card struct {
	Agent
	Tools []ApprovedTool
	// Truncated says more approved tools exist than Tools lists.
	Truncated bool
}

// Card returns an agent's card, to whoever may read the agent.
func (inv *Inventory) Card(ctx context.Context, id ids.UUID) (Card, error) {
	var out Card
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, _ db.TenantTx) error {
		r, err := load(ctx, c, q, id, td.PermAgentRead, false)
		if err != nil {
			return err
		}
		rows, err := q.ApprovedToolsOfAgent(ctx, c.Org, r.ID, maxCardTools+1)
		if err != nil {
			return err
		}
		out.Agent, out.Truncated = agentView(r), len(rows) > maxCardTools
		for _, t := range rows[:min(len(rows), maxCardTools)] {
			out.Tools = append(out.Tools, ApprovedTool{
				ConnectionID: t.ConnectionID, Connection: t.ConnectionName, Package: t.Package, Version: t.Version, Operation: t.Operation,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// TransferOwnership sets the owner and backup owner. It is recorded and
// moves no runs, instances or grants (F574, HR-147).
func (inv *Inventory) TransferOwnership(ctx context.Context, id, owner, backup ids.UUID, reason string) (Agent, error) {
	if err := domain.ValidateReason(reason); err != nil {
		return Agent{}, invalid(err)
	}
	if owner.IsZero() || owner == backup {
		return Agent{}, ErrOwner
	}
	var out Agent
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := load(ctx, c, q, id, td.PermAgentManage, true)
		if err != nil {
			return err
		}
		if err := checkOwners(ctx, q, c.Org, owner, backup); err != nil {
			return err
		}
		prev := agentView(r)
		r, err = q.TransferAgentOwnership(ctx, dbq.TransferAgentOwnershipParams{
			OrgID: c.Org, ID: r.ID, OwnerUserID: &owner, BackupOwnerUserID: optUUID(backup),
		})
		if err != nil {
			return notFound(err, ErrState)
		}
		out = agentView(r)
		details := map[string]string{"from_owner": prev.OwnerUserID.String(), "to_owner": owner.String()}
		if err := RecordChange(ctx, q, c.Org, r.ID, domain.Change{
			Kind: domain.ChangeOwnershipTransferred, Actor: actor(c), Reason: reason, Details: details,
		}); err != nil {
			return err
		}
		return record(ctx, tx, c, "agents.ownership_transferred", r.ID, details)
	})
	return out, err
}

// ListChanges pages through an agent's history (F024).
func (inv *Inventory) ListChanges(ctx context.Context, id ids.UUID, pr page.Request) (Page[Change], error) {
	var out Page[Change]
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, _ db.TenantTx) error {
		if _, err := load(ctx, c, q, id, td.PermAgentRead, false); err != nil {
			return err
		}
		rows, err := q.ListAgentChanges(ctx, dbq.ListAgentChangesParams{OrgID: c.Org, AgentID: id, After: pr.After, PageLimit: pr.Limit()})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcAgentChange) ids.UUID { return r.ID })
		for _, r := range rows {
			ch := Change{ID: r.ID, AgentID: r.AgentID, Kind: r.Kind, Actor: r.Actor, Reason: r.Reason, CreatedAt: r.CreatedAt}
			if err := json.Unmarshal(r.Details, &ch.Details); err != nil {
				return err
			}
			out.Items = append(out.Items, ch)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
