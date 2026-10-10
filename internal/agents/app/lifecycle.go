// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func invalid(err error) error {
	if errors.Is(err, domain.ErrInvalid) {
		return pcerr.Wrap(err, pcerr.InvalidArgument, "AGENT_INVALID", err.Error())
	}
	return err
}

// transition moves an agent from its current state to `to` with a
// conditional update (HR-004); a lost race is reported, never retried
// blindly.
func transition(ctx context.Context, q *dbq.Queries, r dbq.PcAgent, to domain.State, suspendedFrom *string) (dbq.PcAgent, error) {
	if err := domain.Lifecycle.Check(domain.State(r.State), to); err != nil {
		return r, pcerr.Wrap(err, pcerr.FailedPrecondition, "AGENT_STATE", err.Error())
	}
	out, err := q.SetAgentState(ctx, dbq.SetAgentStateParams{
		OrgID: r.OrgID, ID: r.ID, FromState: r.State, ToState: string(to), SuspendedFrom: suspendedFrom,
	})
	if db.IsNoRows(err) {
		return r, ErrLostRace
	}
	return out, err
}

// Claim claims a discovered agent: as its own agent with accountable
// details, or merged into an existing claimed agent (F035), never by name.
// Claiming grants no authority (F016); it resolves the discovered agent's
// open ADMISSION entry. The caller needs agent.manage where the agent will
// live; a new claimed agent counts against the edition limit.
func (inv *Inventory) Claim(ctx context.Context, id ids.UUID, d *domain.Details, mergeInto ids.UUID, reason string) (Agent, error) {
	if err := domain.ValidateReason(reason); err != nil {
		return Agent{}, invalid(err)
	}
	if (d == nil) == mergeInto.IsZero() {
		return Agent{}, pcerr.New(pcerr.InvalidArgument, "CLAIM_TARGET", "claim as a new agent or merge into one, not both")
	}
	if d != nil {
		if err := d.Validate(); err != nil {
			return Agent{}, invalid(err)
		}
	}
	var out Agent
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		// A discovered agent has no placement yet, so reading it needs
		// agent.read at the org.
		r, err := load(ctx, c, q, id, td.PermAgentRead, true)
		if err != nil {
			return err
		}
		if domain.State(r.State) != domain.StateDiscovered {
			return pcerr.Wrap(domain.ErrNotDiscovered, pcerr.FailedPrecondition, "AGENT_STATE", domain.ErrNotDiscovered.Error())
		}
		decider := ptr(string(actor(c)))
		if d != nil {
			out, err = inv.claimAsNew(ctx, c, q, r, *d, reason)
		} else {
			out, err = mergeDiscovered(ctx, c, q, r, mergeInto, reason)
		}
		if err != nil {
			return err
		}
		if _, err := q.CloseOpenAgentEntries(ctx, dbq.CloseOpenAgentEntriesParams{
			OrgID: c.Org, AgentID: r.ID, State: "APPROVED", DecidedBy: decider, Reason: reason, SubjectType: ptr("agent"),
		}); err != nil {
			return err
		}
		return record(ctx, tx, c, "agents.agent_claimed", r.ID, map[string]string{"agent_id": out.ID.String()})
	})
	return out, err
}

func (inv *Inventory) claimAsNew(ctx context.Context, c tenancy.Caller, q *dbq.Queries, r dbq.PcAgent, d domain.Details, reason string) (Agent, error) {
	p, err := place(ctx, q, c.Org, d.TeamID, d.EnvironmentID)
	if err != nil {
		return Agent{}, err
	}
	if err := c.Require(td.PermAgentManage, p.path); err != nil {
		return Agent{}, err
	}
	if err := checkOwners(ctx, q, c.Org, d.OwnerUserID, d.BackupOwnerUserID); err != nil {
		return Agent{}, err
	}
	if err := inv.checkLimit(ctx, q, c.Org); err != nil {
		return Agent{}, err
	}
	claimed, err := q.ClaimDiscoveredAgent(ctx, dbq.ClaimDiscoveredAgentParams{
		OrgID: c.Org, ID: r.ID, Name: d.Name, Purpose: d.Purpose, TeamID: &d.TeamID, EnvironmentID: &d.EnvironmentID,
		OwnerUserID: &d.OwnerUserID, BackupOwnerUserID: optUUID(d.BackupOwnerUserID), ExecutionContext: ptr(string(d.Context)),
	})
	if db.IsNoRows(err) {
		return Agent{}, ErrLostRace
	} else if err != nil {
		return Agent{}, err
	}
	if err := q.SetAgentDiscoveryState(ctx, "CLAIMED", c.Org, r.ID); err != nil {
		return Agent{}, err
	}
	return agentView(claimed), RecordChange(ctx, q, c.Org, r.ID, domain.Change{
		Kind: domain.ChangeClaimed, Actor: actor(c), Reason: reason,
		Details: map[string]string{"owner_user_id": d.OwnerUserID.String(), "execution_context": string(d.Context)},
	})
}

// mergeDiscovered moves the discovery to an existing claimed agent and
// retires the discovered record (F035). The target's runs and instances are
// untouched: the observed key still needs admission (HR-094).
func mergeDiscovered(ctx context.Context, c tenancy.Caller, q *dbq.Queries, r dbq.PcAgent, into ids.UUID, reason string) (Agent, error) {
	if into == r.ID {
		return Agent{}, pcerr.New(pcerr.InvalidArgument, "CLAIM_TARGET", "an agent cannot be merged into itself")
	}
	target, err := load(ctx, c, q, into, td.PermAgentManage, true)
	if err != nil {
		return Agent{}, err
	}
	if !domain.State(target.State).Claimed(stateOf(target.SuspendedFrom)) || domain.State(target.State) == domain.StateRetired {
		return Agent{}, ErrState
	}
	if err := q.MoveDiscovery(ctx, target.ID, c.Org, r.ID); err != nil {
		return Agent{}, err
	}
	if _, err := transition(ctx, q, r, domain.StateRetired, nil); err != nil {
		return Agent{}, err
	}
	details := map[string]string{"discovered_agent_id": r.ID.String(), "into_agent_id": target.ID.String()}
	for _, a := range []ids.UUID{r.ID, target.ID} {
		if err := RecordChange(ctx, q, c.Org, a, domain.Change{Kind: domain.ChangeMerged, Actor: actor(c), Reason: reason, Details: details}); err != nil {
			return Agent{}, err
		}
	}
	return agentView(target), nil
}

// entryCancelled is the stored waitlist state (waitlist_entries.state CHECK).
const entryCancelled = "CANCELLED" //nolint:misspell // stored value, British spelling as in ARCHITECTURE §6.2

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func stateOf(s *string) domain.State {
	if s == nil {
		return ""
	}
	return domain.State(*s)
}

// Suspend suspends an agent: its instances get no workload tokens and its
// runs are denied. The org's containment epoch moves in the same
// transaction, so outstanding permits fail BeginDispatch (HR-002).
// Resuming needs a RESTORATION entry (M5).
func (inv *Inventory) Suspend(ctx context.Context, id ids.UUID, reason string) (Agent, error) {
	if err := domain.ValidateReason(reason); err != nil {
		return Agent{}, invalid(err)
	}
	var out Agent
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := load(ctx, c, q, id, td.PermAgentManage, true)
		if err != nil {
			return err
		}
		r, err = transition(ctx, q, r, domain.StateSuspended, ptr(r.State))
		if err != nil {
			return err
		}
		if err := bumpEpoch(ctx, q, c.Org); err != nil {
			return err
		}
		out = agentView(r)
		if err := RecordChange(ctx, q, c.Org, r.ID, domain.Change{Kind: domain.ChangeSuspended, Actor: actor(c), Reason: reason}); err != nil {
			return err
		}
		return record(ctx, tx, c, "agents.agent_suspended", r.ID, nil)
	})
	return out, err
}

// Restore returns a suspended agent to the state it was suspended from,
// in the caller's transaction (G0 M5 part 2, decision 11). Only the
// approval of a RESTORATION request calls it: an agent.restore holder other
// than the requester signed it with a security key. It is conditional on
// the agent still being suspended (HR-004) and records the change.
func Restore(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID, to domain.State, by domain.Actor, request ids.UUID) error {
	if to == "" || to == domain.StateSuspended || to == domain.StateRetired {
		return pcerr.New(pcerr.FailedPrecondition, "AGENT_STATE", "the agent cannot return to "+string(to))
	}
	_, err := q.SetAgentState(ctx, dbq.SetAgentStateParams{
		OrgID: org, ID: agent, FromState: string(domain.StateSuspended), ToState: string(to),
	})
	if db.IsNoRows(err) {
		return ErrLostRace
	} else if err != nil {
		return err
	}
	return RecordChange(ctx, q, org, agent, domain.Change{
		Kind: domain.ChangeRestored, Actor: by, Details: map[string]string{"to": string(to), "approval_request": request.String()},
	})
}

// Retire retires an agent for good (F023): it revokes its instances and
// enrollment tokens, ends its runs, closes its open waitlist entries and
// moves the containment epoch. History is kept. Retiring a discovered
// agent dismisses its discovery.
func (inv *Inventory) Retire(ctx context.Context, id ids.UUID, reason string) (Agent, error) {
	if err := domain.ValidateReason(reason); err != nil {
		return Agent{}, invalid(err)
	}
	var out Agent
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := load(ctx, c, q, id, td.PermAgentManage, true)
		if err != nil {
			return err
		}
		discovered := domain.State(r.State) == domain.StateDiscovered
		r, err = transition(ctx, q, r, domain.StateRetired, nil)
		if err != nil {
			return err
		}
		by := string(actor(c))
		counts := map[string]string{}
		instances, err := q.RevokeAgentInstances(ctx, dbq.RevokeAgentInstancesParams{
			OrgID: c.Org, AgentID: r.ID, Reason: ptr("agent retired"), DecidedBy: &by,
		})
		if err != nil {
			return err
		}
		tokens, err := q.RevokeAgentEnrollmentTokens(ctx, c.Org, r.ID)
		if err != nil {
			return err
		}
		runs, err := q.RevokeAgentRuns(ctx, r.ID, "agent_retired", c.Org)
		if err != nil {
			return err
		}
		entryState := entryCancelled
		if discovered {
			entryState = "REJECTED"
			if err := q.SetAgentDiscoveryState(ctx, "DISMISSED", c.Org, r.ID); err != nil {
				return err
			}
		}
		if _, err := q.CloseOpenAgentEntries(ctx, dbq.CloseOpenAgentEntriesParams{
			OrgID: c.Org, AgentID: r.ID, State: entryState, DecidedBy: &by, Reason: reason,
		}); err != nil {
			return err
		}
		if err := bumpEpoch(ctx, q, c.Org); err != nil {
			return err
		}
		counts["instances_revoked"] = itoa(instances)
		counts["enrollments_revoked"] = itoa(tokens)
		counts["runs_ended"] = itoa(runs)
		out = agentView(r)
		if err := RecordChange(ctx, q, c.Org, r.ID, domain.Change{Kind: domain.ChangeRetired, Actor: actor(c), Reason: reason, Details: counts}); err != nil {
			return err
		}
		return record(ctx, tx, c, "agents.agent_retired", r.ID, counts)
	})
	return out, err
}

// bumpEpoch increments the org's containment epoch (HR-002), creating the
// containment row on first use.
func bumpEpoch(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	if err := q.InsertContainment(ctx, org); err != nil {
		return err
	}
	_, err := q.BumpEpoch(ctx, org)
	return err
}

// MarkVerified moves a claimed agent to VERIFIED when its first instance is
// admitted (F020), in the caller's transaction. Any other state is left
// alone: the agent may already be verified, or be suspended.
func MarkVerified(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID, by domain.Actor) error {
	_, err := q.SetAgentState(ctx, dbq.SetAgentStateParams{
		OrgID: org, ID: agent, FromState: string(domain.StateClaimed), ToState: string(domain.StateVerified),
	})
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	return RecordChange(ctx, q, org, agent, domain.Change{Kind: domain.ChangeVerified, Actor: by})
}

// MarkObserved moves a verified agent to OBSERVED on its first verified
// request (F020), in the caller's transaction. Any other state is left
// alone.
func MarkObserved(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID, by domain.Actor) error {
	_, err := q.SetAgentState(ctx, dbq.SetAgentStateParams{
		OrgID: org, ID: agent, FromState: string(domain.StateVerified), ToState: string(domain.StateObserved),
	})
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	return RecordChange(ctx, q, org, agent, domain.Change{Kind: domain.ChangeObserved, Actor: by})
}
