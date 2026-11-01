// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the governed-automation use cases of the core stream
// (G0 M11 part 2 D5, D7, D8, D9, D14, D15, D28, D54, D57): automations and
// their execution identities, versions and validation, enabling through
// the generic change-request ceremony, issuance ceilings and their daily
// caps, pause, resume, retire and revoke-authority controls, the Pauser
// the kill switch uses, the ceiling sweep and the inventory. Every person
// action is human only (HR-279); the engine reaches this package only
// through the ports it implements (grants Ceilings, runs AutomationRuns,
// autoports.Pauser and CeilingChecker).
//
// Import it as autoapp.
package app

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrNotFound        = pcerr.New(pcerr.NotFound, "AUTOMATION_NOT_FOUND", "automation not found")
	ErrVersionNotFound = pcerr.New(pcerr.NotFound, "AUTOMATION_VERSION_NOT_FOUND", "automation version not found")
	ErrHumanOnly       = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrEdition         = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "automations need the Team edition or above")
	ErrNameTaken       = pcerr.New(pcerr.AlreadyExists, "AUTOMATION_NAME_TAKEN", "an automation or service account with this name exists")
	ErrName            = pcerr.New(pcerr.InvalidArgument, "AUTOMATION_NAME",
		"a name is a lowercase slug of at most 52 characters starting with a letter")
	ErrOwner        = pcerr.New(pcerr.FailedPrecondition, "OWNER_NOT_ACTIVE_PERSON", "the owner must be an active person of the organization")
	ErrState        = pcerr.New(pcerr.FailedPrecondition, "AUTOMATION_STATE", "the automation is not in a state that allows this")
	ErrVersionState = pcerr.New(pcerr.FailedPrecondition, "VERSION_STATE",
		"the version is not in a state that allows this")
	ErrDefinition      = pcerr.New(pcerr.InvalidArgument, "DEFINITION_INVALID", "the definition cannot be read")
	ErrRevisionChanged = pcerr.New(pcerr.Aborted, "REVISION_CHANGED", "the version changed; read it again")
	ErrUntested        = pcerr.New(pcerr.FailedPrecondition, "VERSION_UNTESTED",
		"a cohort or full rollout needs a version whose scenario tests passed for its current content (HR-287)")
	ErrRolloutUnverified = pcerr.New(pcerr.FailedPrecondition, "ROLLOUT_UNVERIFIED",
		"widening to a full rollout needs a verified cohort stage")
	ErrRollout         = pcerr.New(pcerr.InvalidArgument, "ROLLOUT_INVALID", "the rollout or its cohort is not valid here")
	ErrFullNeedsCohort = pcerr.New(pcerr.FailedPrecondition, "FULL_NEEDS_COHORT",
		"enable this version at COHORT first, then widen it to FULL with rollout evidence")
	ErrCohortUnavail = pcerr.New(pcerr.FailedPrecondition, "COHORT_UNAVAILABLE", "fleet cohorts are not available on this server")
	ErrRevalidation  = pcerr.New(pcerr.FailedPrecondition, "AUTHORITY_CHANGED",
		"the automation's authority no longer holds; ask for a new enabling")
	ErrKillSwitch            = pcerr.New(pcerr.FailedPrecondition, "KILL_SWITCH_ENGAGED", "the kill switch is engaged")
	ErrExecutionsUnavailable = pcerr.New(pcerr.FailedPrecondition, "EXECUTIONS_UNAVAILABLE",
		"active executions cannot be canceled here: the execution engine is not available")
	ErrGrantsUnavailable = pcerr.New(pcerr.Unavailable, "GRANTS_UNAVAILABLE", "grants cannot be revoked here")
	ErrContained         = pcerr.New(pcerr.FailedPrecondition, "CONTAINED", "a containment control holds the automation's identity")
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Operations returns the org's active definition of an exact operation
// (nil when there is none).
type Operations interface {
	Active(ctx context.Context, org ids.OrgID, op string) (*defs.Definition, error)
}

// Destinations checks automation destinations (triggers, D22); nil: none
// are available.
type Destinations interface {
	Active(ctx context.Context, tx pgx.Tx, org ids.OrgID, destination ids.UUID, purpose string) (bool, error)
}

// Executions cancels an automation's active executions at their next
// boundary (engine, D28); nil: there are none to cancel.
type Executions interface {
	CancelActive(ctx context.Context, tx pgx.Tx, org ids.OrgID, automation ids.UUID, reason string) (ControlEffect, error)
}

// Service serves the core automation use cases as pc_app.
type Service struct {
	Pool    *db.Pool
	Clock   clock.Clock
	Changes *changes.Service
	Grants  *grantsapp.Service
	Runs    *runsapp.Service
	// Optional ports (nil-safe).
	Editions     Editions
	Operations   Operations
	Destinations Destinations
	Executions   Executions
	Triggers     autoports.TriggerActivator
	TestGate     autoports.TestGate
	Rollout      autoports.RolloutEvidence
	Compromise   autoports.CompromiseChecker
	Failures     reflexports.FailureSink
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

// Automation is one automation as the API shows it.
type Automation struct {
	ID, Owner, ServiceAccount ids.UUID
	Name, Purpose             string
	Kind                      autodomain.WorkKind
	State                     autodomain.State
	Rollout                   autodomain.Rollout
	CohortAgents              []ids.UUID
	EnabledVersion            ids.UUID
	PauseReason               autodomain.PauseReason
	PausedAt, RetiredAt       *time.Time
	CreatedBy                 ids.UUID
	CreatedAt, UpdatedAt      time.Time
	Ceiling                   *Ceiling
}

// Ceiling is an automation's authority row (D54).
type Ceiling struct {
	ID, Version, ChangeRequest ids.UUID
	Digest                     []byte
	ApprovedBy                 []ids.UUID
	State                      autodomain.CeilingState
	ReviewBy                   time.Time
	VoidReason                 string
	CreatedAt                  time.Time
	EndedAt                    *time.Time
}

// Version is one version as the API shows it.
type Version struct {
	ID, Automation                     ids.UUID
	Number                             int
	State                              autodomain.VersionState
	Definition                         []byte
	Digest                             []byte
	Summary                            string
	Findings                           []autodomain.Finding
	TestedRun, ChangeRequest           ids.UUID
	CreatedBy                          ids.UUID
	CreatedAt                          time.Time
	ValidatedAt, TestedAt, PublishedAt *time.Time
}

// ControlEffect is what a control verifiably did (HR-283).
type ControlEffect struct {
	GrantsRevoked, RunsEnded, LaunchesCancelled, DeliveriesCancelled, ExecutionsAffected []ids.UUID
	// DeliveriesNotVerified were handed to a receiver and their cancellation
	// could not be confirmed (D97, D102, HR-283): they may still arrive.
	DeliveriesNotVerified []ids.UUID
}

func (e *ControlEffect) add(o ControlEffect) {
	e.GrantsRevoked = append(e.GrantsRevoked, o.GrantsRevoked...)
	e.RunsEnded = append(e.RunsEnded, o.RunsEnded...)
	e.LaunchesCancelled = append(e.LaunchesCancelled, o.LaunchesCancelled...)
	e.DeliveriesCancelled = append(e.DeliveriesCancelled, o.DeliveriesCancelled...)
	e.ExecutionsAffected = append(e.ExecutionsAffected, o.ExecutionsAffected...)
	e.DeliveriesNotVerified = append(e.DeliveriesNotVerified, o.DeliveriesNotVerified...)
}

func automationView(r dbq.PcAutomation) Automation {
	out := Automation{
		ID: r.ID, Name: r.Name, Purpose: r.Purpose, Kind: autodomain.WorkKind(r.Kind), Owner: r.OwnerUserID,
		ServiceAccount: r.ServiceAccountID, State: autodomain.State(r.State), CohortAgents: r.CohortAgents,
		PausedAt: r.PausedAt, RetiredAt: r.RetiredAt, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	if r.Rollout != nil {
		out.Rollout = autodomain.Rollout(*r.Rollout)
	}
	if r.EnabledVersionID != nil {
		out.EnabledVersion = *r.EnabledVersionID
	}
	if r.PauseReason != nil {
		out.PauseReason = autodomain.PauseReason(*r.PauseReason)
	}
	return out
}

func ceilingView(r dbq.GetActiveAutomationCeilingRow) *Ceiling {
	out := &Ceiling{
		ID: r.ID, Version: r.VersionID, ChangeRequest: r.ChangeRequestID, Digest: r.Digest, ApprovedBy: r.ApprovedBy,
		State: autodomain.CeilingState(r.State), ReviewBy: r.ReviewBy, CreatedAt: r.CreatedAt, EndedAt: r.EndedAt,
	}
	if r.VoidReason != nil {
		out.VoidReason = *r.VoidReason
	}
	return out
}

func versionView(r dbq.PcAutomationVersion) Version {
	out := Version{
		ID: r.ID, Automation: r.AutomationID, Number: int(r.Number), State: autodomain.VersionState(r.State),
		Definition: r.Definition, Digest: r.Digest, Summary: r.Summary, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		ValidatedAt: r.ValidatedAt, TestedAt: r.TestedAt, PublishedAt: r.PublishedAt,
	}
	_ = json.Unmarshal(r.Findings, &out.Findings)
	if r.TestedRunID != nil {
		out.TestedRun = *r.TestedRunID
	}
	if r.ChangeRequestID != nil {
		out.ChangeRequest = *r.ChangeRequestID
	}
	return out
}

// manager checks that the caller is a person holding automation.manage at
// the org: every automation change is human only (HR-279).
func manager(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermAutomationManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHumanOnly
	}
	return c, nil
}

// reader checks that the caller holds automation.read at the org.
func reader(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermAutomationRead, td.OrgPath(c.Org))
}

func (s *Service) edition(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.Automations() {
		return ErrEdition
	}
	return nil
}

// CanCreateDraft is the permission and edition check CreateDraftTx runs on
// its caller.
func (s *Service) CanCreateDraft(ctx context.Context) error {
	if _, err := manager(ctx); err != nil {
		return err
	}
	return s.edition(ctx)
}

func (s *Service) entitled(ctx context.Context, x autodomain.Edition) bool {
	if s.Editions == nil {
		return false
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return false
	}
	switch x {
	case autodomain.EditionBusiness:
		return e.AutomationPlaybooks()
	case autodomain.EditionTeam:
		return e.Automations()
	}
	return false
}

// record audits an automation event in tx.
func record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name string, automation ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "automation", ID: automation.String()},
		Details: details,
	})
	return err
}

// systemActor is PantherClaw acting by itself (sweeps, kill switch pauses
// are attributed to the person who engaged it by their own record).
var systemActor = evdomain.Actor{Type: "system", ID: "automations"}

func oneRow(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return db.ErrLostRace
	}
	return nil
}

func loadAutomation(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID, lock bool) (dbq.PcAutomation, error) {
	var r dbq.PcAutomation
	var err error
	if lock {
		r, err = q.LockAutomation(ctx, org, id)
	} else {
		r, err = q.GetAutomation(ctx, org, id)
	}
	if db.IsNoRows(err) {
		return r, ErrNotFound
	}
	return r, err
}

func loadVersion(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID, lock bool) (dbq.PcAutomationVersion, error) {
	var r dbq.PcAutomationVersion
	var err error
	if lock {
		r, err = q.LockAutomationVersion(ctx, org, id)
	} else {
		r, err = q.GetAutomationVersion(ctx, org, id)
	}
	if db.IsNoRows(err) {
		return r, ErrVersionNotFound
	}
	return r, err
}

func definitionOf(v dbq.PcAutomationVersion) (*autodomain.Definition, error) {
	d, err := autodomain.Parse(v.Definition)
	if err != nil {
		return nil, pcerr.Wrap(err, pcerr.Internal, "DEFINITION_STORED", "a stored definition cannot be read")
	}
	return d, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func hexDigest(b []byte) string { return hex.EncodeToString(b) }
