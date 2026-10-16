// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rollout takes a policy version to an org's agents in stages (G0
// M11.1, coordinator decisions D12 and D13; F200–F205): SHADOW, where the
// rollout sweeper replays new decisions under the version and records
// what it would have decided, never enforcing it (HR-233); PILOT, where the
// Authority selects the version for the agents of the pilot's ENFORCE
// cohorts (HR-234); and COMPLETE, where the version is published for
// everyone. Targets are agents (founder decision F3), each CONFIGURED,
// ACKNOWLEDGED, VERIFIED, FAILED or EXCEPTION.
//
// Shadow, pilots and cohorts need the Team edition; a Community org gets a
// COMPLETE rollout recorded for every publish, for target status only.
// Every change is made by a person holding policy.publish; reads need
// policy.read. Entering a pilot and completing go through the publish gate
// (D6): a pilot of a version that loosens the published one waits for a
// ROLLOUT change request (D11).
package rollout

import (
	"context"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Stages of a rollout.
const (
	StageShadow    = "SHADOW"
	StagePilot     = "PILOT"
	StageComplete  = "COMPLETE"
	StageCancelled = "CANCELLED" //nolint:misspell // stored value (D12), British spelling as in ARCHITECTURE §6.2
)

// Modes of a rollout's cohort.
const (
	ModeShadow  = "SHADOW"
	ModeEnforce = "ENFORCE"
)

// States of a rollout target (F3).
const (
	TargetConfigured   = "CONFIGURED"
	TargetAcknowledged = "ACKNOWLEDGED"
	TargetVerified     = "VERIFIED"
	TargetFailed       = "FAILED"
	TargetException    = "EXCEPTION"
)

// ShadowLabel labels every shadow result shown (D13).
const ShadowLabel = "shadow prediction, not enforcement"

// Bounds.
const (
	MaxCohortMembers = 1000
	maxCohortsPerOp  = 50
	maxAgentsPerOp   = 1000
	maxList          = 200
	maxReason        = 500
)

// Errors.
var (
	ErrNotFound        = pcerr.New(pcerr.NotFound, "POLICY_ROLLOUT_NOT_FOUND", "policy rollout not found")
	ErrCohortNotFound  = pcerr.New(pcerr.NotFound, "POLICY_COHORT_NOT_FOUND", "policy cohort not found")
	ErrAgentNotFound   = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrVersionNotFound = pcerr.New(pcerr.NotFound, "POLICY_VERSION_NOT_FOUND", "policy version not found")
	ErrCohortName      = pcerr.New(pcerr.InvalidArgument, "POLICY_COHORT_INVALID",
		"a cohort name is 1 to 64 lowercase letters, digits and hyphens, starting with a letter")
	ErrCohortExists = pcerr.New(pcerr.AlreadyExists, "POLICY_COHORT_EXISTS", "a cohort with this name exists")
	ErrCohortFull   = pcerr.New(pcerr.FailedPrecondition, "POLICY_COHORT_FULL", "a cohort holds at most 1,000 agents")
	ErrArgument     = pcerr.New(pcerr.InvalidArgument, "POLICY_ROLLOUT_INVALID",
		"name 1 to 50 cohorts, 1 to 1,000 agents, and a reason of 1 to 500 characters where one is needed")
	ErrRolloutOpen = pcerr.New(pcerr.FailedPrecondition, "POLICY_ROLLOUT_OPEN",
		"the org already has a rollout in shadow or pilot; complete or cancel it first")
	ErrStage        = pcerr.New(pcerr.FailedPrecondition, "POLICY_ROLLOUT_STAGE", "the rollout is not in a stage that allows this")
	ErrVersionState = pcerr.New(pcerr.FailedPrecondition, "POLICY_ROLLOUT_VERSION",
		"only a version that is not published and was not superseded can be rolled out")
	ErrBaseChanged = pcerr.New(pcerr.FailedPrecondition, "BASE_CHANGED",
		"another policy version was published since this rollout started; cancel it and start again")
	ErrEdition     = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "shadow, pilots and cohorts need the Team edition or above")
	ErrHumanOnly   = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrGateMissing = pcerr.New(pcerr.FailedPrecondition, "POLICY_GATE_UNAVAILABLE",
		"the policy publish gate is not available on this server, so nothing can be enforced")
	cohortName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// ChangeRequest is a change request the gate created and a person must
// confirm (D11): its id and the page that confirms it.
type ChangeRequest struct {
	ID  ids.UUID
	URL string
}

// Gate is the publish gate (D6) as rollouts use it. Every path that makes
// a version enforced goes through it; without one, nothing is.
type Gate interface {
	// CheckPilot runs the gate's validation and tests for version again,
	// with the current definitions and catalog, and classifies it against
	// base, the published version the rollout started from (D3); it
	// publishes nothing. It returns nil when the version does not loosen
	// base, so the pilot starts now, else the ROLLOUT change request the
	// pilot waits for, whose apply calls Service.EnterPilot (D11).
	CheckPilot(ctx context.Context, rollout, version ids.UUID, base *ids.UUID, cohorts []RolloutCohort) (*ChangeRequest, error)
	// Publish publishes version through the gate expecting base to be the
	// published version, or returns the PUBLISH change request it created
	// when the version loosens it. A publish calls Service.Published in its
	// transaction (D6's OnPublished hook).
	Publish(ctx context.Context, version ids.UUID, base *ids.UUID) (*ChangeRequest, error)
}

// Notifier enqueues notifications (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service runs the rollout use cases.
type Service struct {
	Pool     *db.Pool
	Editions Editions
	Gate     Gate
	Notify   Notifier
	Log      *slog.Logger
	// Receipts, when set, gives the sweeper a decision's receipt when its
	// recording cannot be read (D31).
	Receipts Receipts
	// Replay reads the recordings of new decisions and replays them for the
	// sweeper (D12, D13); nil: the sweeper reads no decisions.
	Replay Replayer
	// Lag is how old a decision must be before the sweeper reads it, so one
	// committed late is not passed over: zero is a minute, a negative value
	// none (tests).
	Lag time.Duration
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// Rollout is a rollout with its cohorts and target counts.
type Rollout struct {
	dbq.PcPolicyRollout
	Cohorts []RolloutCohort
	// Targets counts the targets by state.
	Targets map[string]int64
}

// RolloutCohort is one of a rollout's cohorts.
type RolloutCohort struct {
	ID      ids.UUID
	Name    string
	Mode    string
	Members int
}

// Cohort is a named group of agents with its members.
type Cohort struct {
	dbq.PcPolicyCohort
	Agents []ids.UUID
}

func reader(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(tdomain.PermPolicyRead, tdomain.OrgPath(c.Org))
}

// publisher is a person holding policy.publish at the org, signed in as
// themselves.
func publisher(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tapp.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, c.Require(tdomain.PermPolicyPublish, tdomain.OrgPath(c.Org))
}

// team refuses unless the licence is Team or above (fail closed: without an
// edition source the server is Community).
func (s *Service) team(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.PolicyRollout() {
		return ErrEdition
	}
	return nil
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, c tapp.Caller, name string, object ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "policy_rollout", ID: object.String()},
		Details: details,
	})
	return err
}

// CreateCohort creates an empty cohort (Team; a person holding
// policy.publish).
func (s *Service) CreateCohort(ctx context.Context, name string) (Cohort, error) {
	if !cohortName.MatchString(name) {
		return Cohort{}, ErrCohortName
	}
	c, err := publisher(ctx)
	if err != nil {
		return Cohort{}, err
	}
	if err := s.team(ctx); err != nil {
		return Cohort{}, err
	}
	var out Cohort
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).InsertPolicyCohort(ctx, dbq.InsertPolicyCohortParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: name, CreatedBy: c.Principal.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrCohortExists
		}
		if err != nil {
			return err
		}
		out = Cohort{PcPolicyCohort: row, Agents: []ids.UUID{}}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "policy.cohort_created", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "policy_cohort", ID: row.ID.String()}, Details: map[string]string{"name": name},
		})
		return err
	})
	return out, err
}

// ChangeCohort adds agents to a cohort (Team), or removes them (a person
// holding policy.publish). An agent added to a cohort an open pilot
// enforces becomes one of its targets at once; such an addition needs the
// pilot's base to still be the published version (D31). An agent removed
// from every ENFORCE cohort of an open rollout is that rollout's EXCEPTION
// (REMOVED_FROM_COHORT) and keeps the published version. It returns how
// many memberships changed.
func (s *Service) ChangeCohort(ctx context.Context, name string, agents []ids.UUID, remove bool) (int, error) {
	if !cohortName.MatchString(name) {
		return 0, ErrCohortName
	}
	if len(agents) == 0 || len(agents) > maxAgentsPerOp {
		return 0, ErrArgument
	}
	c, err := publisher(ctx)
	if err != nil {
		return 0, err
	}
	if !remove {
		if err := s.team(ctx); err != nil {
			return 0, err
		}
	}
	var n int
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cohort, err := q.GetPolicyCohortByName(ctx, c.Org, name)
		if db.IsNoRows(err) {
			return ErrCohortNotFound
		}
		if err != nil {
			return err
		}
		if !remove {
			if err := baseStillPublished(ctx, q, c.Org, cohort.ID); err != nil {
				return err
			}
		}
		for _, a := range agents {
			var k int64
			if remove {
				if k, err = q.RemovePolicyCohortMember(ctx, c.Org, cohort.ID, a); err == nil && k > 0 {
					_, err = q.RemovedFromCohortTargets(ctx, c.Org, a)
				}
			} else {
				k, err = q.AddPolicyCohortMember(ctx, dbq.AddPolicyCohortMemberParams{
					OrgID: c.Org, CohortID: cohort.ID, AgentID: a, AddedBy: c.Principal.String(),
				})
			}
			switch {
			case db.IsForeignKeyViolation(err):
				return ErrAgentNotFound
			case db.IsCheckViolation(err):
				return ErrCohortFull
			case err != nil:
				return err
			}
			n += int(k)
		}
		if !remove {
			if err := s.syncPilotTargets(ctx, tx, c.Org); err != nil {
				return err
			}
		}
		event := "policy.cohort_members_added"
		if remove {
			event = "policy.cohort_members_removed"
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: event, Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "policy_cohort", ID: cohort.ID.String()}, Details: map[string]string{"name": name, "agents": strconv.Itoa(len(agents))},
		})
		return err
	})
	return n, err
}

// baseStillPublished refuses (BASE_CHANGED) when an open pilot that
// enforces its version for cohort started from a version that is no longer
// the published one (D31).
func baseStillPublished(ctx context.Context, q *dbq.Queries, org ids.OrgID, cohort ids.UUID) error {
	pilots, err := q.PilotsEnforcingCohort(ctx, org, cohort)
	if err != nil || len(pilots) == 0 {
		return err
	}
	cur, err := published(ctx, q, org)
	if err != nil {
		return err
	}
	for _, r := range pilots {
		if !sameVersion(cur, r.BaseVersionID) {
			return ErrBaseChanged
		}
	}
	return nil
}

// syncPilotTargets adds a CONFIGURED target for every agent of the org's
// open pilot's ENFORCE cohorts that has none.
func (s *Service) syncPilotTargets(ctx context.Context, tx db.TenantTx, org ids.OrgID) error {
	q := dbq.New(tx)
	due, err := q.DuePolicyRollouts(ctx, org)
	if err != nil {
		return err
	}
	for _, r := range due {
		if r.Stage == StagePilot {
			if _, err := q.AddCohortRolloutTargets(ctx, org, r.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// ListCohorts returns the org's cohorts with their members (policy.read).
func (s *Service) ListCohorts(ctx context.Context) ([]Cohort, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []Cohort
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListPolicyCohorts(ctx, c.Org, maxList)
		if err != nil {
			return err
		}
		for _, r := range rows {
			agents, err := q.ListPolicyCohortMembers(ctx, c.Org, r.ID)
			if err != nil {
				return err
			}
			out = append(out, Cohort{PcPolicyCohort: r, Agents: agents})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// cohortIDs resolves cohort names in the caller's org.
func cohortIDs(ctx context.Context, q *dbq.Queries, org ids.OrgID, names []string) ([]ids.UUID, error) {
	if len(names) > maxCohortsPerOp {
		return nil, ErrArgument
	}
	out := make([]ids.UUID, 0, len(names))
	for _, n := range names {
		if !cohortName.MatchString(n) {
			return nil, ErrCohortName
		}
		c, err := q.GetPolicyCohortByName(ctx, org, n)
		if db.IsNoRows(err) {
			return nil, ErrCohortNotFound
		}
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, c.ID) {
			out = append(out, c.ID)
		}
	}
	return out, nil
}

// published returns the id of the org's published version, or nil.
func published(ctx context.Context, q *dbq.Queries, org ids.OrgID) (*ids.UUID, error) {
	row, err := q.GetPublishedPolicy(ctx, org)
	if db.IsNoRows(err) {
		return nil, nil //nolint:nilnil // none is published
	}
	if err != nil {
		return nil, err
	}
	return &row.ID, nil
}

func sameVersion(a, b *ids.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// StartRollout starts a SHADOW rollout of version (Team; a person holding
// policy.publish): the sweeper replays the new decisions of the agents of
// shadowCohorts (none: every agent) under it, and nothing is enforced.
func (s *Service) StartRollout(ctx context.Context, version ids.UUID, shadowCohorts []string) (Rollout, error) {
	c, err := publisher(ctx)
	if err != nil {
		return Rollout{}, err
	}
	if err := s.team(ctx); err != nil {
		return Rollout{}, err
	}
	var id ids.UUID
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, err := q.GetPolicyVersionBundle(ctx, c.Org, version)
		if db.IsNoRows(err) {
			return ErrVersionNotFound
		}
		if err != nil {
			return err
		}
		if v.State == "PUBLISHED" || v.State == "SUPERSEDED" {
			return ErrVersionState
		}
		cohorts, err := cohortIDs(ctx, q, c.Org, shadowCohorts)
		if err != nil {
			return err
		}
		base, err := published(ctx, q, c.Org)
		if err != nil {
			return err
		}
		r, err := q.InsertPolicyRollout(ctx, dbq.InsertPolicyRolloutParams{
			OrgID: c.Org, ID: ids.NewV7(), VersionID: version, BaseVersionID: base, Stage: StageShadow, CreatedBy: c.Principal.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrRolloutOpen
		}
		if err != nil {
			return err
		}
		id = r.ID
		for _, co := range cohorts {
			if err := q.AddPolicyRolloutCohort(ctx, dbq.AddPolicyRolloutCohortParams{
				OrgID: c.Org, RolloutID: r.ID, CohortID: co, Mode: ModeShadow,
			}); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, c, "policy.rollout_started", r.ID, map[string]string{
			"version_id": version.String(), "stage": StageShadow, "shadow_cohorts": strconv.Itoa(len(shadowCohorts)),
		})
	})
	if err != nil {
		return Rollout{}, err
	}
	return s.get(ctx, c.Org, id)
}

// StartPilot enforces a SHADOW rollout's version for the agents of cohorts
// (Team; a person holding policy.publish). The version goes through the
// publish gate first (D6). When it loosens the published version, the pilot
// waits for a ROLLOUT change request, which this returns; otherwise the
// pilot starts now.
func (s *Service) StartPilot(ctx context.Context, rollout ids.UUID, cohorts []string) (Rollout, *ChangeRequest, error) {
	if len(cohorts) == 0 {
		return Rollout{}, nil, ErrArgument
	}
	c, err := publisher(ctx)
	if err != nil {
		return Rollout{}, nil, err
	}
	if err := s.team(ctx); err != nil {
		return Rollout{}, nil, err
	}
	if s.Gate == nil {
		return Rollout{}, nil, ErrGateMissing
	}
	var r dbq.PcPolicyRollout
	var cohortList []ids.UUID
	var cohortNames []string // cohorts without repeats, in cohortList's order
	for _, n := range cohorts {
		if !slices.Contains(cohortNames, n) {
			cohortNames = append(cohortNames, n)
		}
	}
	var base *ids.UUID
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if r, err = q.GetPolicyRollout(ctx, c.Org, rollout); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if r.Stage != StageShadow {
			return ErrStage
		}
		if cohortList, err = cohortIDs(ctx, q, c.Org, cohorts); err != nil {
			return err
		}
		// The rollout's base never changes (D22): a pilot is checked against
		// the version published when the rollout started, which must still be.
		cur, err := published(ctx, q, c.Org)
		if err != nil {
			return err
		}
		if !sameVersion(cur, r.BaseVersionID) {
			return ErrBaseChanged
		}
		base = r.BaseVersionID
		return nil
	}, db.ReadOnly())
	if err != nil {
		return Rollout{}, nil, err
	}
	named := make([]RolloutCohort, 0, len(cohortList))
	for i, id := range cohortList {
		named = append(named, RolloutCohort{ID: id, Name: cohortNames[i]})
	}
	cr, err := s.Gate.CheckPilot(ctx, rollout, r.VersionID, base, named)
	if err != nil {
		return Rollout{}, nil, err
	}
	if cr != nil {
		out, err := s.get(ctx, c.Org, rollout)
		return out, cr, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return s.EnterPilot(ctx, tx, c.Actor(), rollout, base, cohortList)
	})
	if err != nil {
		return Rollout{}, nil, err
	}
	out, err := s.get(ctx, c.Org, rollout)
	return out, nil, err
}

// EnterPilot moves a SHADOW rollout to PILOT in tx: its cohorts enforce the
// version, each of their agents becomes a CONFIGURED target, and base (the
// version the pilot was checked against) must still be published. It is
// StartPilot's second half and the ROLLOUT change request's apply (D11).
func (s *Service) EnterPilot(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, rollout ids.UUID, base *ids.UUID, cohorts []ids.UUID) error {
	q := dbq.New(tx)
	org := tx.OrgID()
	r, err := q.LockPolicyRollout(ctx, org, rollout)
	if db.IsNoRows(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if r.Stage != StageShadow {
		return ErrStage
	}
	cur, err := published(ctx, q, org)
	if err != nil {
		return err
	}
	if !sameVersion(cur, base) || !sameVersion(cur, r.BaseVersionID) {
		return ErrBaseChanged
	}
	if _, err := q.SetPolicyRolloutStage(ctx, dbq.SetPolicyRolloutStageParams{
		Stage: StagePilot, OrgID: org, ID: rollout, FromStages: []string{StageShadow},
	}); db.IsNoRows(err) {
		return ErrStage
	} else if err != nil {
		return err
	}
	if err := enforce(ctx, q, org, rollout, cohorts); err != nil {
		return err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "policy.rollout_pilot_started", Actor: actor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "policy_rollout", ID: rollout.String()},
		Details: map[string]string{"version_id": r.VersionID.String(), "cohorts": strconv.Itoa(len(cohorts))},
	})
	return err
}

func enforce(ctx context.Context, q *dbq.Queries, org ids.OrgID, rollout ids.UUID, cohorts []ids.UUID) error {
	for _, co := range cohorts {
		if err := q.AddPolicyRolloutCohort(ctx, dbq.AddPolicyRolloutCohortParams{
			OrgID: org, RolloutID: rollout, CohortID: co, Mode: ModeEnforce,
		}); err != nil {
			return err
		}
	}
	_, err := q.AddCohortRolloutTargets(ctx, org, rollout)
	return err
}

// ExpandPilot adds cohorts to a pilot (Team; a person holding
// policy.publish). The pilot's version was approved against its base, so
// no new approval is needed while the base is still published.
func (s *Service) ExpandPilot(ctx context.Context, rollout ids.UUID, cohorts []string) (Rollout, error) {
	if len(cohorts) == 0 {
		return Rollout{}, ErrArgument
	}
	c, err := publisher(ctx)
	if err != nil {
		return Rollout{}, err
	}
	if err := s.team(ctx); err != nil {
		return Rollout{}, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockPolicyRollout(ctx, c.Org, rollout)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if r.Stage != StagePilot {
			return ErrStage
		}
		cur, err := published(ctx, q, c.Org)
		if err != nil {
			return err
		}
		if !sameVersion(cur, r.BaseVersionID) {
			return ErrBaseChanged
		}
		added, err := cohortIDs(ctx, q, c.Org, cohorts)
		if err != nil {
			return err
		}
		if err := enforce(ctx, q, c.Org, rollout, added); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "policy.rollout_pilot_expanded", rollout, map[string]string{"cohorts": strconv.Itoa(len(cohorts))})
	})
	if err != nil {
		return Rollout{}, err
	}
	return s.get(ctx, c.Org, rollout)
}

// ExcludeTarget keeps an agent on the published version for a rollout in
// SHADOW or PILOT (a person holding policy.publish): its target is
// EXCEPTION, with the reason, and the Authority no longer selects the
// rollout's version for it.
func (s *Service) ExcludeTarget(ctx context.Context, rollout, agent ids.UUID, reason string) (dbq.PcPolicyRolloutTarget, error) {
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > maxReason {
		return dbq.PcPolicyRolloutTarget{}, ErrArgument
	}
	c, err := publisher(ctx)
	if err != nil {
		return dbq.PcPolicyRolloutTarget{}, err
	}
	var out dbq.PcPolicyRolloutTarget
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockPolicyRollout(ctx, c.Org, rollout)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if r.Stage != StageShadow && r.Stage != StagePilot {
			return ErrStage
		}
		out, err = q.ExcludeRolloutTarget(ctx, dbq.ExcludeRolloutTargetParams{RolloutID: rollout, Reason: &reason, OrgID: c.Org, AgentID: agent})
		if db.IsNoRows(err) {
			return ErrAgentNotFound
		}
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "policy.rollout_target_excluded", rollout, map[string]string{
			"agent": agent.String(), "reason_length": strconv.Itoa(utf8.RuneCountInString(reason)),
		})
	})
	return out, err
}

// CompleteRollout publishes the rollout's version for everyone through the
// publish gate (D6; a person holding policy.publish): the gate runs again,
// and the version the rollout started from must still be published. The
// rollout becomes COMPLETE in the publishing transaction (Published); when
// the version loosens the published one, the gate returns the PUBLISH
// change request instead and the rollout stays where it is until it is
// confirmed.
func (s *Service) CompleteRollout(ctx context.Context, rollout ids.UUID) (Rollout, *ChangeRequest, error) {
	c, err := publisher(ctx)
	if err != nil {
		return Rollout{}, nil, err
	}
	if s.Gate == nil {
		return Rollout{}, nil, ErrGateMissing
	}
	// The rollout is read under its lock (D31), so a cancel that commits
	// first is seen; a cancel that commits after voids the PUBLISH request
	// this may create.
	var r dbq.PcPolicyRollout
	if err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if r, err = q.LockPolicyRollout(ctx, c.Org, rollout); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if r.Stage != StageShadow && r.Stage != StagePilot {
			return ErrStage
		}
		cur, err := published(ctx, q, c.Org)
		if err != nil {
			return err
		}
		if !sameVersion(cur, r.BaseVersionID) {
			return ErrBaseChanged
		}
		return nil
	}); err != nil {
		return Rollout{}, nil, err
	}
	cr, err := s.Gate.Publish(ctx, r.VersionID, r.BaseVersionID)
	if err != nil {
		return Rollout{}, nil, err
	}
	out, err := s.get(ctx, c.Org, rollout)
	return out, cr, err
}

// CancelRollout ends a rollout in SHADOW or PILOT (a person holding
// policy.publish): its cohorts' agents are decided by the published version
// again, and its pending change requests (its pilot's, and the publication
// of its version) are voided (D31). No approval is needed: the published
// version was approved for everyone.
func (s *Service) CancelRollout(ctx context.Context, rollout ids.UUID) (Rollout, error) {
	c, err := publisher(ctx)
	if err != nil {
		return Rollout{}, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockPolicyRollout(ctx, c.Org, rollout)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := cancel(ctx, tx, c.Actor(), r, voidRolloutCancelled); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "policy.rollout_cancelled", rollout, nil) //nolint:misspell // as the stage
	})
	if err != nil {
		return Rollout{}, err
	}
	return s.get(ctx, c.Org, rollout)
}

// Reasons a rollout's pending change requests are voided with.
const (
	voidRolloutCancelled = "ROLLOUT_CANCELLED" //nolint:misspell // as the stage
	voidBaseChanged      = "BASE_CHANGED"
)

// cancel ends an open rollout (StageCancelled) and voids its pending change
// requests: the ROLLOUT request of its pilot and the PUBLISH request of its
// version (D31).
func cancel(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, r dbq.PcPolicyRollout, reason string) error {
	q := dbq.New(tx)
	if _, err := q.SetPolicyRolloutStage(ctx, dbq.SetPolicyRolloutStageParams{
		Stage: StageCancelled, OrgID: r.OrgID, ID: r.ID, FromStages: []string{StageShadow, StagePilot},
	}); db.IsNoRows(err) {
		return ErrStage
	} else if err != nil {
		return err
	}
	if err := voidRequests(ctx, tx, actor, "ROLLOUT", r.ID, reason); err != nil {
		return err
	}
	return voidRequests(ctx, tx, actor, "PUBLISH", r.VersionID, reason)
}

// VoidCompromised is the reason a rollout is halted when its creator or a
// confirmer of its requests is marked compromised (G0 M11 D43).
const VoidCompromised = "PUBLISHER_COMPROMISED"

// Halt ends an open rollout (StageCancelled) and voids its pending change
// requests, in the caller's transaction (G0 M11 D43, HR-293: its creator
// or a confirmer was marked compromised). The rollout is audited
// with the cancel event and the reason.
func Halt(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, r dbq.PcPolicyRollout, reason string) error {
	if err := cancel(ctx, tx, actor, r, reason); err != nil {
		return err
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "policy.rollout_cancelled", Actor: actor, Outcome: audit.Success, ReasonCode: reason, //nolint:misspell // as the stage
		Object: &audit.Object{Type: "policy_rollout", ID: r.ID.String()},
	})
	return err
}

// voidRequests voids the pending change requests of a kind for a subject.
func voidRequests(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, kind string, subject ids.UUID, reason string) error {
	q := dbq.New(tx)
	org := tx.OrgID()
	pending, err := q.PendingChangeRequestsFor(ctx, org, kind, subject)
	if err != nil {
		return err
	}
	for _, id := range pending {
		if _, err := q.DecidePolicyChangeRequest(ctx, dbq.DecidePolicyChangeRequestParams{
			State: "VOIDED", Reason: &reason, OrgID: org, ID: id,
		}); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "policy.change_voided", Actor: actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "policy_change_request", ID: id.String()}, Details: map[string]string{"reason": reason},
		}); err != nil {
			return err
		}
	}
	return nil
}

// publishActor is who a publication's hook acts as: the person who made
// it, or the system for the dev seed.
func publishActor(ctx context.Context) evdomain.Actor {
	if c, err := tapp.CallerFrom(ctx); err == nil {
		return c.Actor()
	}
	return evdomain.Actor{Type: "system", ID: "policy-publish"}
}

// Published records a publish in its transaction (D6's OnPublished hook).
// The org's open rollouts are locked; the one of version, if any, becomes
// COMPLETE (its pending pilot request voided), and every other ends
// (StageCancelled) with its pending requests voided (BASE_CHANGED, D31):
// its version was classified against a base that is no longer published.
// Their shadow results are kept. Without an open rollout of version a
// COMPLETE rollout is recorded (every edition: status only). Every
// EXCEPTION target is CONFIGURED again (INCLUDED_AT_COMPLETION) and every
// non-retired agent becomes a target, so the sweeper can follow each one
// to VERIFIED.
func (s *Service) Published(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID, base *ids.UUID) error {
	q := dbq.New(tx)
	open, err := q.LockOpenPolicyRollouts(ctx, org)
	if err != nil {
		return err
	}
	actor := publishActor(ctx)
	var id ids.UUID
	for _, r := range open {
		if r.VersionID != version {
			if err := cancel(ctx, tx, actor, r, voidBaseChanged); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "policy.rollout_cancelled", Actor: actor, Outcome: audit.Success, ReasonCode: voidBaseChanged, //nolint:misspell // as the stage
				Object: &audit.Object{Type: "policy_rollout", ID: r.ID.String()}, Details: map[string]string{"published_version_id": version.String()},
			}); err != nil {
				return err
			}
			continue
		}
		if _, err := q.SetPolicyRolloutStage(ctx, dbq.SetPolicyRolloutStageParams{
			Stage: StageComplete, OrgID: org, ID: r.ID, FromStages: []string{StageShadow, StagePilot},
		}); err != nil {
			return err
		}
		if err := voidRequests(ctx, tx, actor, "ROLLOUT", r.ID, voidRolloutCompleted); err != nil {
			return err
		}
		id = r.ID
	}
	if id.IsZero() {
		r, err := q.InsertPolicyRollout(ctx, dbq.InsertPolicyRolloutParams{
			OrgID: org, ID: ids.NewV7(), VersionID: version, BaseVersionID: base, Stage: StageComplete, CreatedBy: "system:publish",
		})
		if err != nil {
			return err
		}
		id = r.ID
	}
	// The version is everyone's now: an excluded agent is followed too (D37).
	if _, err := q.IncludeExceptionsAtCompletion(ctx, org, id); err != nil {
		return err
	}
	_, err = q.AddAllRolloutTargets(ctx, id, org)
	return err
}

// voidRolloutCompleted voids a completed rollout's pending pilot request.
const voidRolloutCompleted = "ROLLOUT_COMPLETED"

// GetRollout returns a rollout with its cohorts and target counts
// (policy.read).
func (s *Service) GetRollout(ctx context.Context, id ids.UUID) (Rollout, error) {
	c, err := reader(ctx)
	if err != nil {
		return Rollout{}, err
	}
	return s.get(ctx, c.Org, id)
}

func (s *Service) get(ctx context.Context, org ids.OrgID, id ids.UUID) (Rollout, error) {
	var out Rollout
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = load(ctx, dbq.New(tx), org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

func load(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Rollout, error) {
	r, err := q.GetPolicyRollout(ctx, org, id)
	if db.IsNoRows(err) {
		return Rollout{}, ErrNotFound
	}
	if err != nil {
		return Rollout{}, err
	}
	out := Rollout{PcPolicyRollout: r, Cohorts: []RolloutCohort{}, Targets: map[string]int64{}}
	cohorts, err := q.ListPolicyRolloutCohorts(ctx, org, id)
	if err != nil {
		return Rollout{}, err
	}
	for _, co := range cohorts {
		out.Cohorts = append(out.Cohorts, RolloutCohort{ID: co.CohortID, Name: co.Name, Mode: co.Mode, Members: int(co.Members)})
	}
	counts, err := q.CountRolloutTargets(ctx, org, id)
	if err != nil {
		return Rollout{}, err
	}
	for _, n := range counts {
		out.Targets[n.State] = n.N
	}
	return out, nil
}

// ListRollouts returns the org's rollouts, newest first (policy.read).
func (s *Service) ListRollouts(ctx context.Context, limit int) ([]Rollout, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []Rollout
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListPolicyRollouts(ctx, c.Org, int32(min(max(limit, 1), maxList)))
		if err != nil {
			return err
		}
		for _, r := range rows {
			x, err := load(ctx, q, c.Org, r.ID)
			if err != nil {
				return err
			}
			out = append(out, x)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// ListTargets returns a rollout's targets, by agent id after after, in one
// state or all (policy.read).
func (s *Service) ListTargets(ctx context.Context, rollout ids.UUID, state string, after ids.UUID, limit int) ([]dbq.PcPolicyRolloutTarget, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var st *string
	if state != "" {
		if !slices.Contains([]string{TargetConfigured, TargetAcknowledged, TargetVerified, TargetFailed, TargetException}, state) {
			return nil, ErrArgument
		}
		st = &state
	}
	var out []dbq.PcPolicyRolloutTarget
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetPolicyRollout(ctx, c.Org, rollout); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		var err error
		out, err = q.ListRolloutTargets(ctx, dbq.ListRolloutTargetsParams{
			OrgID: c.Org, RolloutID: rollout, State: st, AfterAgent: optional(after), MaxRows: int32(min(max(limit, 1), maxList)),
		})
		return err
	}, db.ReadOnly())
	return out, err
}
