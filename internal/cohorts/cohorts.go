// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package cohorts groups an org's agents into fleet cohorts (G0 M11 part
// 2, coordinator decision D40; F600, F601, HR-291): static members (at
// most 1 000) plus the agents an optional rule matches (team, environment,
// task type), with an owner and an optional grant baseline. A cohort only
// organizes: it grants nothing, and its baseline is a template a person
// issues grants from. Its queue lists what needs a person (unowned or
// unpromoted agents, grants beyond the baseline, pending approvals), its
// changes what moved since a time, and the fleet overview every agent.
//
// Cohorts need the Team edition. Writes need cohort.manage (human only);
// reads need agent.read, and every agent listed is one the caller may
// read.
package cohorts

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions: cohort.manage (human only, D12) for every change, agent.read
// for reads.
const (
	PermManage = td.Permission("cohort.manage")
	PermRead   = td.PermAgentRead
)

// Bounds.
const (
	MaxMembers     = 1000
	maxAgentsPerOp = 1000
	maxList        = 200
	maxDescription = 1000
	maxBaselineTTL = int(gdomain.HardMaxRootLifetime / time.Second)
)

var (
	nameRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	taskTypeRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// Errors.
var (
	ErrNotFound      = pcerr.New(pcerr.NotFound, "COHORT_NOT_FOUND", "cohort not found")
	ErrAgentNotFound = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrExists        = pcerr.New(pcerr.AlreadyExists, "COHORT_EXISTS", "a cohort of that name exists")
	ErrFull          = pcerr.New(pcerr.FailedPrecondition, "COHORT_FULL", "a cohort holds at most 1000 agents")
	ErrEdition       = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "fleet cohorts need the Team edition")
	ErrHumanOnly     = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person signed in as themselves can change cohorts")
	ErrOwner         = pcerr.New(pcerr.FailedPrecondition, "OWNER_NOT_ACTIVE", "the owner must be an active person of the org")
)

func invalid(format string, args ...any) error {
	return pcerr.New(pcerr.InvalidArgument, "INVALID_COHORT", fmt.Sprintf(format, args...))
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service runs the cohort use cases.
type Service struct {
	Pool     *db.Pool
	Editions Editions
}

// Rule matches agents by every field it gives.
type Rule struct {
	TeamID        *ids.UUID `json:"team_id,omitzero"`
	EnvironmentID *ids.UUID `json:"environment_id,omitzero"`
	TaskType      string    `json:"task_type,omitzero"`
}

func (r *Rule) validate() error {
	if r == nil {
		return nil
	}
	if r.TeamID == nil && r.EnvironmentID == nil && r.TaskType == "" {
		return invalid("a rule names a team, an environment or a task type")
	}
	if r.TaskType != "" && !taskTypeRe.MatchString(r.TaskType) {
		return invalid("task type %q is not a lowercase slug", r.TaskType)
	}
	return nil
}

// Baseline is a cohort's grant template: what a grant for one of its
// agents is expected to stay within. It is never issued by itself.
type Baseline struct {
	Bounds     gdomain.Bounds `json:"bounds"`
	Limits     gdomain.Limits `json:"limits,omitzero"`
	TTLSeconds int            `json:"ttl_seconds,omitzero"`
}

func (b *Baseline) validate() error {
	if b == nil {
		return nil
	}
	if err := b.Bounds.Validate(); err != nil {
		return invalid("baseline: %s", strings.TrimPrefix(err.Error(), gdomain.ErrInvalid.Error()+": "))
	}
	if b.Bounds.Operations == nil {
		return invalid("baseline: list the operations")
	}
	if b.TTLSeconds < 0 || b.TTLSeconds > maxBaselineTTL {
		return invalid("baseline: ttl_seconds is 0 to %d", maxBaselineTTL)
	}
	return nil
}

// DecodeBaseline strictly decodes a baseline document.
func DecodeBaseline(raw []byte) (*Baseline, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var b Baseline
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("baseline: %v", err)
	}
	return &b, b.validate()
}

// Cohort is a stored cohort with its rule and baseline decoded.
type Cohort struct {
	dbq.PcFleetCohort
	Rule          *Rule
	Baseline      *Baseline
	StaticMembers int
}

func cohortOf(r dbq.PcFleetCohort, static int) Cohort {
	c := Cohort{PcFleetCohort: r, StaticMembers: static}
	if r.Rule != nil {
		c.Rule = &Rule{}
		_ = json.Unmarshal(r.Rule, c.Rule) // written by this package
	}
	if r.Baseline != nil {
		c.Baseline = &Baseline{}
		_ = json.Unmarshal(r.Baseline, c.Baseline)
	}
	return c
}

// Input is a cohort's content.
type Input struct {
	Name, Description string
	Owner             ids.UUID
	Rule              *Rule
	Baseline          *Baseline
}

func (in Input) encode() (rule, baseline []byte, err error) {
	switch {
	case !nameRe.MatchString(in.Name):
		return nil, nil, invalid("name %q is not a lowercase slug of up to 64 characters", in.Name)
	case utf8.RuneCountInString(in.Description) > maxDescription:
		return nil, nil, invalid("the description is at most %d characters", maxDescription)
	case in.Owner.IsZero():
		return nil, nil, invalid("name the owner")
	}
	if err := errors.Join(in.Rule.validate(), in.Baseline.validate()); err != nil {
		return nil, nil, err
	}
	if in.Rule != nil {
		if rule, err = json.Marshal(in.Rule, json.Deterministic(true)); err != nil {
			return nil, nil, err
		}
	}
	if in.Baseline != nil {
		if baseline, err = json.Marshal(in.Baseline, json.Deterministic(true)); err != nil {
			return nil, nil, err
		}
	}
	return rule, baseline, nil
}

func (s *Service) team(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.Edition.Paid() {
		return ErrEdition
	}
	return nil
}

// manager is a person holding cohort.manage at the org, in a Team org.
func (s *Service) manager(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tapp.CredAPIKey {
		return c, ErrHumanOnly
	}
	if err := c.Require(PermManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	return c, s.team(ctx)
}

// reader holds agent.read somewhere in a Team org.
func (s *Service) reader(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.CanAnywhere(PermRead) {
		return c, td.ErrPermissionDenied(PermRead)
	}
	return c, s.team(ctx)
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, c tapp.Caller, name string, cohort ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "fleet_cohort", ID: cohort.String()},
		Details: details,
	})
	return err
}

func ownerActive(ctx context.Context, q *dbq.Queries, org ids.OrgID, user ids.UUID) error {
	u, err := q.GetUser(ctx, org, user)
	if db.IsNoRows(err) || (err == nil && u.State != "ACTIVE") {
		return ErrOwner
	}
	return err
}

// Create creates a cohort (cohort.manage, Team).
func (s *Service) Create(ctx context.Context, in Input) (Cohort, error) {
	c, err := s.manager(ctx)
	if err != nil {
		return Cohort{}, err
	}
	rule, baseline, err := in.encode()
	if err != nil {
		return Cohort{}, err
	}
	var out Cohort
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := ownerActive(ctx, q, c.Org, in.Owner); err != nil {
			return err
		}
		row, err := q.InsertFleetCohort(ctx, dbq.InsertFleetCohortParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: in.Name, Description: in.Description, Rule: rule, OwnerUserID: in.Owner,
			Baseline: baseline, CreatedBy: c.Principal.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		out = cohortOf(row, 0)
		return s.audit(ctx, tx, c, "cohort.created", row.ID, map[string]string{"name": in.Name, "owner": in.Owner.String()})
	})
	return out, err
}

// Update replaces a cohort's content (cohort.manage, Team).
func (s *Service) Update(ctx context.Context, id ids.UUID, in Input) (Cohort, error) {
	c, err := s.manager(ctx)
	if err != nil {
		return Cohort{}, err
	}
	rule, baseline, err := in.encode()
	if err != nil {
		return Cohort{}, err
	}
	var out Cohort
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := ownerActive(ctx, q, c.Org, in.Owner); err != nil {
			return err
		}
		row, err := q.UpdateFleetCohort(ctx, dbq.UpdateFleetCohortParams{
			OrgID: c.Org, ID: id, Name: in.Name, Description: in.Description, Rule: rule, OwnerUserID: in.Owner, Baseline: baseline,
		})
		switch {
		case db.IsNoRows(err):
			return ErrNotFound
		case db.IsUniqueViolation(err):
			return ErrExists
		case err != nil:
			return err
		}
		out = cohortOf(row, 0)
		return s.audit(ctx, tx, c, "cohort.updated", id, map[string]string{"name": in.Name, "owner": in.Owner.String()})
	})
	return out, err
}

// Delete deletes a cohort and its memberships (cohort.manage, Team).
func (s *Service) Delete(ctx context.Context, id ids.UUID) error {
	c, err := s.manager(ctx)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockFleetCohort(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := q.DeleteFleetCohortMembers(ctx, c.Org, id); err != nil {
			return err
		}
		if _, err := q.DeleteFleetCohort(ctx, c.Org, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "cohort.deleted", id, map[string]string{"name": row.Name})
	})
}

// Get returns a cohort (agent.read, Team).
func (s *Service) Get(ctx context.Context, id ids.UUID) (Cohort, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return Cohort{}, err
	}
	var out Cohort
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetFleetCohort(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		out = cohortOf(row, 0)
		return err
	}, db.ReadOnly())
	return out, err
}

// List lists cohorts by name (agent.read, Team); after is the last name of
// the previous page.
func (s *Service) List(ctx context.Context, after string, limit int) ([]Cohort, string, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 || limit > maxList {
		limit = maxList
	}
	var aft *string
	if after != "" {
		aft = &after
	}
	var out []Cohort
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListFleetCohorts(ctx, c.Org, aft, int32(limit+1)) //nolint:gosec // ≤ 201
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows, next = rows[:limit], rows[limit-1].Name
		}
		for _, r := range rows {
			out = append(out, cohortOf(dbq.PcFleetCohort{
				OrgID: r.OrgID, ID: r.ID, Name: r.Name, Description: r.Description, Rule: r.Rule, OwnerUserID: r.OwnerUserID,
				Baseline: r.Baseline, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
			}, int(r.StaticMembers)))
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

// visible reads an agent and reports whether the caller holds p where it
// lives.
func visible(ctx context.Context, q *dbq.Queries, c tapp.Caller, id ids.UUID, p td.Permission) (dbq.PcAgent, bool, error) {
	a, err := q.GetAgent(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return a, false, nil
	} else if err != nil {
		return a, false, err
	}
	path, err := aapp.PathOf(ctx, q, a)
	if err != nil {
		return a, false, err
	}
	return a, c.Can(p, path), nil
}

// ChangeMembers adds agents to a cohort's static members, or removes them
// (cohort.manage, Team). Every agent must be one the caller may read. It
// returns how many memberships changed.
func (s *Service) ChangeMembers(ctx context.Context, id ids.UUID, agents []ids.UUID, remove bool) (int, error) {
	c, err := s.manager(ctx)
	if err != nil {
		return 0, err
	}
	if len(agents) == 0 || len(agents) > maxAgentsPerOp {
		return 0, invalid("name 1 to %d agents", maxAgentsPerOp)
	}
	var n int
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.LockFleetCohort(ctx, c.Org, id); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		for _, a := range agents {
			if _, ok, err := visible(ctx, q, c, a, PermRead); err != nil {
				return err
			} else if !ok {
				return ErrAgentNotFound
			}
			var k int64
			if remove {
				k, err = q.RemoveFleetCohortMember(ctx, c.Org, id, a)
			} else {
				k, err = q.AddFleetCohortMember(ctx, dbq.AddFleetCohortMemberParams{
					OrgID: c.Org, CohortID: id, AgentID: a, AddedBy: c.Principal.String(),
				})
			}
			if db.IsCheckViolation(err) {
				return ErrFull
			} else if err != nil {
				return err
			}
			n += int(k)
		}
		name := "cohort.members_added"
		if remove {
			name = "cohort.members_removed"
		}
		return s.audit(ctx, tx, c, name, id, map[string]string{"agents": fmt.Sprint(len(agents)), "changed": fmt.Sprint(n)})
	})
	return n, err
}

// SetAgentTaskType sets or clears ("") the task type cohort rules match
// (cohort.manage where the agent lives, Team).
func (s *Service) SetAgentTaskType(ctx context.Context, agent ids.UUID, taskType string) error {
	c, err := s.manager(ctx)
	if err != nil {
		return err
	}
	var tt *string
	if taskType != "" {
		if !taskTypeRe.MatchString(taskType) {
			return invalid("task type %q is not a lowercase slug", taskType)
		}
		tt = &taskType
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, ok, err := visible(ctx, q, c, agent, PermRead)
		if err != nil {
			return err
		} else if !ok {
			return ErrAgentNotFound
		}
		path, err := aapp.PathOf(ctx, q, a)
		if err != nil {
			return err
		}
		if err := c.Require(PermManage, path); err != nil {
			return err
		}
		if _, err := q.SetAgentTaskType(ctx, tt, c.Org, agent); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "agent.task_type_set", Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "agent", ID: agent.String()},
			Details: map[string]string{"task_type": taskType},
		})
		return err
	})
}

// agentsOf reads a cohort's agents in id order, after the given id.
func agentsOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, co dbq.PcFleetCohort, after *ids.UUID, limit int) ([]dbq.FleetCohortAgentsRow, error) {
	p := dbq.FleetCohortAgentsParams{OrgID: org, CohortID: co.ID, After: after, MaxRows: int32(limit)} //nolint:gosec // ≤ 2000
	if co.Rule != nil {
		var r Rule
		if err := json.Unmarshal(co.Rule, &r); err != nil {
			return nil, err
		}
		p.HasRule, p.RuleTeamID, p.RuleEnvironmentID = true, r.TeamID, r.EnvironmentID
		if r.TaskType != "" {
			p.RuleTaskType = &r.TaskType
		}
	}
	return q.FleetCohortAgents(ctx, p)
}

// Resolve returns a cohort's agents, at most limit, for a caller that
// already authorized the read (governed automations resolve a ceiling's
// cohort per execution, D2): static members and rule matches, retired
// agents left out.
func Resolve(ctx context.Context, tx db.TenantTx, cohort ids.UUID, limit int) ([]ids.UUID, error) {
	q := dbq.New(tx)
	co, err := q.GetFleetCohort(ctx, tx.OrgID(), cohort)
	if db.IsNoRows(err) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	rows, err := agentsOf(ctx, q, tx.OrgID(), co, nil, MaxMembers*2)
	if err != nil {
		return nil, err
	}
	var out []ids.UUID
	for _, r := range rows {
		if r.State != "RETIRED" && len(out) < limit {
			out = append(out, r.ID)
		}
	}
	return out, nil
}

// Member is one agent of a cohort the caller may read.
type Member struct {
	Agent  dbq.PcAgent
	Static bool
}

// Members lists a cohort's agents the caller may read, by id (agent.read,
// Team). Agents the caller cannot read are left out and counted.
func (s *Service) Members(ctx context.Context, id ids.UUID, after *ids.UUID, limit int) (members []Member, hidden int, next *ids.UUID, err error) {
	c, err := s.reader(ctx)
	if err != nil {
		return nil, 0, nil, err
	}
	if limit <= 0 || limit > maxList {
		limit = maxList
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		co, err := q.GetFleetCohort(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		rows, err := agentsOf(ctx, q, c.Org, co, after, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1].ID
			next = &last
		}
		for _, r := range rows {
			a := agentOf(r)
			path, err := aapp.PathOf(ctx, q, a)
			if err != nil {
				return err
			}
			if !c.Can(PermRead, path) {
				hidden++
				continue
			}
			members = append(members, Member{Agent: a, Static: r.StaticMember})
		}
		return nil
	}, db.ReadOnly())
	return members, hidden, next, err
}

func agentOf(r dbq.FleetCohortAgentsRow) dbq.PcAgent {
	return dbq.PcAgent{
		OrgID: r.OrgID, ID: r.ID, Name: r.Name, Purpose: r.Purpose, TeamID: r.TeamID, EnvironmentID: r.EnvironmentID,
		OwnerUserID: r.OwnerUserID, BackupOwnerUserID: r.BackupOwnerUserID, ExecutionContext: r.ExecutionContext, State: r.State,
		SuspendedFrom: r.SuspendedFrom, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, ClaimedAt: r.ClaimedAt,
		RetiredAt: r.RetiredAt, RangeAgent: r.RangeAgent, TaskType: r.TaskType,
	}
}

// readable lists the cohort's agents the caller may read (all of them, at
// most MaxMembers*2) and how many were left out.
func readable(ctx context.Context, q *dbq.Queries, c tapp.Caller, co dbq.PcFleetCohort) ([]ids.UUID, int, error) {
	rows, err := agentsOf(ctx, q, c.Org, co, nil, MaxMembers*2)
	if err != nil {
		return nil, 0, err
	}
	var out []ids.UUID
	var hidden int
	for _, r := range rows {
		path, err := aapp.PathOf(ctx, q, agentOf(r))
		if err != nil {
			return nil, 0, err
		}
		if c.Can(PermRead, path) {
			out = append(out, r.ID)
		} else {
			hidden++
		}
	}
	slices.SortFunc(out, func(a, b ids.UUID) int { return bytes.Compare(a[:], b[:]) })
	return out, hidden, nil
}
