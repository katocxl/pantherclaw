// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the response service.
var (
	ErrHuman          = pcerr.New(pcerr.PermissionDenied, "HUMAN_SESSION_REQUIRED", "only a person may do this")
	ErrEdition        = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "this needs a higher edition")
	ErrApproveOnPage  = pcerr.New(pcerr.FailedPrecondition, "APPROVE_ON_PAGE", "approving a held write needs a security key: approve it on the approval page")
	ErrSkipReason     = pcerr.New(pcerr.InvalidArgument, "SKIP_REASON_REQUIRED", "skipping the preview needs a reason of 1 to 500 characters")
	ErrSubjectInvalid = pcerr.New(pcerr.InvalidArgument, "SUBJECT_INVALID", "the subject must be a run, agent, transaction, alert or incident")
)

// HoldDecider declines a write held by a containment control (approvals,
// D44).
type HoldDecider interface {
	DeclineContainmentHold(ctx context.Context, transaction ids.UUID, note string) error
	// HoldPage is the approval page of the transaction's containment hold.
	HoldPage(ctx context.Context, org ids.OrgID, transaction ids.UUID) (string, error)
}

// Response serves ResponseService (G0 M10 D21–D26): every use case reads the
// caller, checks the permission where the scope lives, and runs in one
// tenant transaction.
type Response struct {
	C *Containment
	// Replay re-decides test actions of staged restorations (nil: staged
	// restoration cannot test, so it applies nothing).
	Replay Replayer
	Holds  HoldDecider
}

func (s *Response) entitlements(ctx context.Context) (teamUp, soar bool) {
	if s.C.Editions == nil {
		return false, false
	}
	e, err := s.C.Editions.Current(ctx)
	if err != nil {
		return false, false
	}
	return e.ReflexTeam(), e.SOAR()
}

// scopePath is where a control's scope lives: an agent's or a run's agent's
// path, else the org.
func scopePath(ctx context.Context, q *dbq.Queries, org ids.OrgID, scopeType, scopeID string) (td.Path, error) {
	var agent ids.UUID
	switch scopeType {
	case rdomain.ScopeAgent:
		id, err := ids.ParseUUID(scopeID)
		if err != nil {
			return nil, rdomain.ErrScope
		}
		agent = id
	case rdomain.ScopeRun:
		id, err := ids.ParseUUID(scopeID)
		if err != nil {
			return nil, rdomain.ErrScope
		}
		a, err := q.AgentOfRun(ctx, org, id)
		if db.IsNoRows(err) {
			return nil, ErrScopeNotFound
		} else if err != nil {
			return nil, err
		}
		agent = a
	default:
		return td.OrgPath(org), nil
	}
	a, err := q.GetAgent(ctx, org, agent)
	if db.IsNoRows(err) {
		return nil, ErrScopeNotFound
	} else if err != nil {
		return nil, err
	}
	return agents.PathOf(ctx, q, a)
}

// freshStepUp checks the caller is a person whose browser session stepped
// up with one of their own active security keys within StepUpWithin, by the
// database clock; it returns when.
func freshStepUp(ctx context.Context, q *dbq.Queries, c tenancy.Caller) (time.Time, error) {
	if !c.Human() || c.Credential != tenancy.CredBrowserSession || c.Session.IsZero() {
		return time.Time{}, ErrStepUp
	}
	su, err := q.SessionStepUp(ctx, c.Org, c.Session, c.Principal.ID)
	if db.IsNoRows(err) {
		return time.Time{}, ErrStepUp
	} else if err != nil {
		return time.Time{}, err
	}
	if su.DbNow.Sub(su.StepUpAt) > StepUpWithin || su.StepUpAt.After(su.DbNow.Add(time.Minute)) {
		return time.Time{}, ErrStepUp
	}
	return su.StepUpAt, nil
}

func callerActor(c tenancy.Caller) reflexdomain.Subject {
	t := reflexdomain.SubjectUser
	if !c.Human() {
		t = reflexdomain.SubjectServiceAccount
	}
	return reflexdomain.Subject{Type: t, ID: c.Principal.ID.String()}
}

// ContainInput is a person's containment request (D21, D23).
type ContainInput struct {
	Scope         reflexdomain.Subject
	Control       string
	Operation     string
	Reason        string
	CaseID        *ids.UUID
	IncidentID    *ids.UUID
	PreviewDigest []byte
	// SkipPreview is the emergency skip of a wider control's preview: it
	// needs SkipReason and a fresh step-up, and is recorded (HR-252).
	SkipPreview bool
	SkipReason  string
	Idempotency string
	ExpiresAt   *time.Time
}

// PreviewContainment previews a control (D23, F013): with the reach before
// and after on Team and above, else a note.
func (s *Response) PreviewContainment(ctx context.Context, scope reflexdomain.Subject, control, operation string) (Preview, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Preview{}, err
	}
	scopeType, scopeID, err := scopeOf(scope)
	if err != nil {
		return Preview{}, err
	}
	ctl := rdomain.Control{ScopeType: scopeType, ScopeID: scopeID, Control: control, Operation: operation, Reason: "preview"}
	var out Preview
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		path, err := scopePath(ctx, q, c.Org, scopeType, scopeID)
		if err != nil {
			return err
		}
		if err := c.Require(td.PermContainmentRead, path); err != nil {
			return err
		}
		out, err = s.C.PreviewIn(ctx, tx, ctl)
		return err
	}, db.ReadOnly())
	if err != nil {
		return Preview{}, err
	}
	team, _ := s.entitlements(ctx)
	switch {
	case !team:
		out.ReachNote = "reach before and after is shown on the Team edition and above"
	case s.C.Reach == nil:
		out.ReachNote = "reach is not computed on this server"
	default:
		diff, err := s.C.Reach.PreviewReduction(ctx, c.Org, reflexdomain.ReductionChange{
			Kind: "contain", Subjects: []reflexdomain.Subject{scope}, Control: control, Operation: operation,
		})
		switch {
		case pcerr.ReasonOf(err) == "EDITION_REQUIRED":
			out.ReachNote = "reach before and after is shown on the Team edition and above"
		case err != nil:
			out.ReachNote = "reach could not be computed"
		default:
			out.Reach = &diff
		}
	}
	return out, nil
}

// Contain adds a control for a person holding incident.respond where the
// scope lives (D21–D23).
func (s *Response) Contain(ctx context.Context, in ContainInput) (reflexdomain.ContainResult, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if !c.Human() {
		return reflexdomain.ContainResult{}, ErrHuman
	}
	scopeType, scopeID, err := scopeOf(in.Scope)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	ctl := rdomain.Control{ScopeType: scopeType, ScopeID: scopeID, Control: in.Control, Operation: in.Operation, Reason: in.Reason}
	ctl, err = ctl.Canonical()
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if in.SkipPreview && !reasonOK(in.SkipReason) {
		return reflexdomain.ContainResult{}, ErrSkipReason
	}
	actor, source, evActor, err := actorOf(callerActor(c))
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	var out reflexdomain.ContainResult
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		path, err := scopePath(ctx, q, c.Org, scopeType, scopeID)
		if err != nil {
			return err
		}
		if err := c.Require(td.PermIncidentRespond, path); err != nil {
			return err
		}
		o := containOpts{
			actor: actor, source: source, evActor: evActor, caseID: in.CaseID, incidentID: in.IncidentID,
			previewDigest: in.PreviewDigest, expires: in.ExpiresAt,
		}
		if in.Idempotency != "" {
			// A person's keys live apart from SOAR's (D61).
			o.idempotency = "person:" + in.Idempotency
		}
		if in.SkipPreview && !ctl.Narrow() {
			at, err := freshStepUp(ctx, q, c)
			if err != nil {
				return err
			}
			o.skipReason, o.skipStepUpAt = in.SkipReason, &at
		}
		out, err = s.C.contain(ctx, tx, c.Org, ctl, o)
		return err
	})
	return out, err
}

// Option is one prefilled, narrow-first response option (F243, F230).
type Option struct {
	Kind      string
	Scope     reflexdomain.Subject
	Control   string
	Narrow    bool
	Rationale string
}

// ProposeResponse returns narrow-first options for a run, agent,
// transaction, alert or incident (D23, F243, F230): the narrowest first,
// each saying what it stops. Nothing is applied.
func (s *Response) ProposeResponse(ctx context.Context, subject reflexdomain.Subject) ([]Option, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	var out []Option
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		subjects, err := subjectsOf(ctx, q, c.Org, subject)
		if err != nil {
			return err
		}
		var runs, agentIDs []string
		for _, sub := range subjects {
			//exhaustive:ignore // only runs and agents have narrow options
			switch sub.Type {
			case reflexdomain.SubjectRun:
				if !slices.Contains(runs, sub.ID) {
					runs = append(runs, sub.ID)
				}
				if id, err := ids.ParseUUID(sub.ID); err == nil {
					if a, err := q.AgentOfRun(ctx, c.Org, id); err == nil && !slices.Contains(agentIDs, a.String()) {
						agentIDs = append(agentIDs, a.String())
					}
				}
			case reflexdomain.SubjectAgent:
				if !slices.Contains(agentIDs, sub.ID) {
					agentIDs = append(agentIDs, sub.ID)
				}
			}
		}
		for _, r := range runs {
			path, err := scopePath(ctx, q, c.Org, rdomain.ScopeRun, r)
			if err != nil || !c.Can(td.PermContainmentRead, path) {
				continue
			}
			run := reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: r}
			out = append(out,
				Option{
					Kind: rdomain.KindContain, Scope: run, Control: rdomain.HoldWrites, Narrow: true,
					Rationale: "holds this run's writes for a responder; its reads continue",
				},
				Option{
					Kind: rdomain.KindContain, Scope: run, Control: rdomain.DenyAll, Narrow: true,
					Rationale: "denies every new action of this run",
				},
				Option{
					Kind: rdomain.KindTerminate, Scope: run, Narrow: true,
					Rationale: "ends this run and its children and voids their waiting approvals; dispatched work is listed",
				})
		}
		for _, a := range agentIDs {
			path, err := scopePath(ctx, q, c.Org, rdomain.ScopeAgent, a)
			if err != nil || !c.Can(td.PermContainmentRead, path) {
				continue
			}
			agent := reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: a}
			out = append(out,
				Option{
					Kind: rdomain.KindContain, Scope: agent, Control: rdomain.HoldWrites, Narrow: true,
					Rationale: "holds every run's writes of this agent for a responder; reads continue",
				},
				Option{
					Kind: rdomain.KindContain, Scope: agent, Control: rdomain.DenyAll, Narrow: true,
					Rationale: "denies every new action of this agent",
				})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// subjectsOf resolves a proposal's subject to runs and agents.
func subjectsOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, s reflexdomain.Subject) ([]reflexdomain.Subject, error) {
	//exhaustive:ignore // any other subject is refused below
	switch s.Type {
	case reflexdomain.SubjectRun, reflexdomain.SubjectAgent:
		if _, err := ids.ParseUUID(s.ID); err != nil {
			return nil, ErrSubjectInvalid
		}
		return []reflexdomain.Subject{s}, nil
	case reflexdomain.SubjectTransaction:
		id, err := ids.ParseUUID(s.ID)
		if err != nil {
			return nil, ErrSubjectInvalid
		}
		run, err := q.RunOfTransaction(ctx, org, id)
		if db.IsNoRows(err) {
			return nil, ErrScopeNotFound
		} else if err != nil {
			return nil, err
		}
		return []reflexdomain.Subject{{Type: reflexdomain.SubjectRun, ID: run.String()}}, nil
	case reflexdomain.SubjectAlert:
		id, err := ids.ParseUUID(s.ID)
		if err != nil {
			return nil, ErrSubjectInvalid
		}
		raw, err := q.AlertSubjects(ctx, org, id)
		if db.IsNoRows(err) {
			return nil, ErrScopeNotFound
		} else if err != nil {
			return nil, err
		}
		return decodeSubjects([][]byte{raw})
	case reflexdomain.SubjectIncident:
		id, err := ids.ParseUUID(s.ID)
		if err != nil {
			return nil, ErrSubjectInvalid
		}
		raws, err := q.IncidentAlertSubjects(ctx, org, &id)
		if err != nil {
			return nil, err
		}
		return decodeSubjects(raws)
	}
	return nil, ErrSubjectInvalid
}

func decodeSubjects(raws [][]byte) ([]reflexdomain.Subject, error) {
	var out []reflexdomain.Subject
	for _, r := range raws {
		var subs []reflexdomain.Subject
		if err := json.Unmarshal(r, &subs); err != nil {
			return nil, err
		}
		out = append(out, subs...)
	}
	return out, nil
}

// Terminate terminates a run for a person holding incident.respond where
// its agent lives (F134).
func (s *Response) Terminate(ctx context.Context, run ids.UUID, reason string, caseID, incidentID *ids.UUID) (reflexdomain.ContainResult, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if !c.Human() {
		return reflexdomain.ContainResult{}, ErrHuman
	}
	var out reflexdomain.ContainResult
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		path, err := scopePath(ctx, dbq.New(tx), c.Org, rdomain.ScopeRun, run.String())
		if err != nil {
			return err
		}
		if err := c.Require(td.PermIncidentRespond, path); err != nil {
			return err
		}
		out, err = s.C.TerminateIn(ctx, tx, Termination{Run: run, Reason: reason, CaseID: caseID, IncidentID: incidentID, Actor: callerActor(c)})
		return err
	})
	return out, err
}

// PreviewCredentialChange lists every workload sharing a credential (D25).
func (s *Response) PreviewCredentialChange(ctx context.Context, connection ids.UUID, version int32) (CredentialPreview, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return CredentialPreview{}, err
	}
	if err := c.Require(td.PermContainmentRead, td.OrgPath(c.Org)); err != nil {
		return CredentialPreview{}, err
	}
	var out CredentialPreview
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.C.PreviewCredentialIn(ctx, tx, connection, version)
		return err
	}, db.ReadOnly())
	return out, err
}

// ChangeCredential revokes or rotates a credential for a person holding
// incident.respond (D25, HR-252).
func (s *Response) ChangeCredential(ctx context.Context, r CredentialChange, rotate bool) (reflexdomain.ContainResult, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if !c.Human() {
		return reflexdomain.ContainResult{}, ErrHuman
	}
	if err := c.Require(td.PermIncidentRespond, td.OrgPath(c.Org)); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	r.Actor = callerActor(c)
	var out reflexdomain.ContainResult
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if r.Attested {
			// An upstream attestation is a person's word at a fresh security-key
			// step-up (D61).
			at, err := freshStepUp(ctx, dbq.New(tx), c)
			if err != nil {
				return err
			}
			r.AttestedAt = at
		}
		var err error
		if rotate {
			out, err = s.C.RotateCredentialIn(ctx, tx, r)
		} else {
			out, err = s.C.RevokeCredentialIn(ctx, tx, r)
		}
		return err
	})
	return out, err
}

// RequestControl serves a SOAR request (D26, HR-251): response.request at
// org scope, Business edition.
func (s *Response) RequestControl(ctx context.Context, r SOARRequest) (SOARResult, []PathView, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return SOARResult{}, nil, err
	}
	if c.Human() {
		return SOARResult{}, nil, ErrSOARCaller
	}
	if err := c.Require(td.PermResponseRequest, td.OrgPath(c.Org)); err != nil {
		return SOARResult{}, nil, err
	}
	if _, soar := s.entitlements(ctx); !soar {
		return SOARResult{}, nil, ErrEdition
	}
	r.Requester = callerActor(c)
	var out SOARResult
	var paths []PathView
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		if out, err = s.C.RequestControlIn(ctx, tx, r); err != nil {
			return err
		}
		paths, err = pathViews(ctx, dbq.New(tx), c.Org, out.ActionID)
		return err
	})
	return out, paths, err
}

// RequestRestoration asks for controls to be lifted (D24): a person holding
// incident.respond; a staged plan needs Team.
func (s *Response) RequestRestoration(ctx context.Context, r RestorationRequest) (ids.UUID, []Precondition, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return ids.UUID{}, nil, err
	}
	if !c.Human() {
		return ids.UUID{}, nil, ErrHuman
	}
	if err := c.Require(td.PermIncidentRespond, td.OrgPath(c.Org)); err != nil {
		return ids.UUID{}, nil, err
	}
	if team, _ := s.entitlements(ctx); len(r.Stages) > 0 && !team {
		return ids.UUID{}, nil, ErrStagedEdition
	}
	r.Requester = c.Principal.ID
	var plan ids.UUID
	var pre []Precondition
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		plan, pre, err = s.C.RequestRestorationIn(ctx, tx, r)
		return err
	})
	return plan, pre, err
}

// reviewer checks a restoration's reviewer: a person holding agent.restore
// whose session stepped up with a security key within 5 minutes.
func reviewer(ctx context.Context, q *dbq.Queries, c tenancy.Caller) error {
	if !c.Human() {
		return ErrHuman
	}
	if err := c.Require(td.PermAgentRestore, td.OrgPath(c.Org)); err != nil {
		return err
	}
	_, err := freshStepUp(ctx, q, c)
	return err
}

// DecideRestoration records an independent reviewer's decision (D24,
// HR-250).
func (s *Response) DecideRestoration(ctx context.Context, plan ids.UUID, approve bool) (string, []Precondition, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return "", nil, err
	}
	var state string
	var pre []Precondition
	var decideErr error
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := reviewer(ctx, dbq.New(tx), c); err != nil {
			return err
		}
		state, pre, decideErr = s.C.DecideRestorationIn(ctx, tx, plan, c.Principal.ID, approve)
		if errors.Is(decideErr, ErrPreconditions) {
			return nil // keep the recorded preconditions
		}
		return decideErr
	})
	if err == nil {
		err = decideErr
	}
	return state, pre, err
}

// ApplyRestorationStage runs a stage's test actions, dry run, and lifts its
// controls when all pass (D24, F568; Team).
func (s *Response) ApplyRestorationStage(ctx context.Context, plan ids.UUID, ordinal int32) (string, []TestResult, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return "", nil, err
	}
	if team, _ := s.entitlements(ctx); !team {
		return "", nil, ErrStagedEdition
	}
	var sp StagePlan
	if err := s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := reviewer(ctx, dbq.New(tx), c); err != nil {
			return err
		}
		var err error
		sp, err = s.C.StageToApply(ctx, tx, plan, ordinal)
		return err
	}, db.ReadOnly()); err != nil {
		return "", nil, err
	}
	results, passed, err := RunStageTests(ctx, s.Replay, c.Org, sp)
	if err != nil {
		return "", nil, err
	}
	var state string
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := reviewer(ctx, dbq.New(tx), c); err != nil {
			return err
		}
		// The controls may have changed while the tests ran: test against
		// what is active now, or refuse.
		again, err := s.C.StageToApply(ctx, tx, plan, ordinal)
		if err != nil {
			return err
		}
		if !sameControls(again.Remaining, sp.Remaining) {
			return ErrStageOrder
		}
		state, err = s.C.ApplyStageIn(ctx, tx, sp, c.Principal.ID, results, passed)
		return err
	})
	return state, results, err
}

// DecideContainmentHold declines a write held by a HOLD_WRITES control, or
// says where to approve it (D44): approving needs a security-key ceremony
// on the approval page.
func (s *Response) DecideContainmentHold(ctx context.Context, transaction ids.UUID, approve bool, note string) (string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return "", err
	}
	if !c.Human() {
		return "", ErrHuman
	}
	if s.Holds == nil {
		return "", ErrNoReplay
	}
	if approve {
		page, err := s.Holds.HoldPage(ctx, c.Org, transaction)
		if err != nil {
			return "", err
		}
		return page, ErrApproveOnPage
	}
	return "", s.Holds.DeclineContainmentHold(ctx, transaction, note)
}

// PathView is one path of an action as the API shows it.
type PathView struct {
	Type, SubjectType, SubjectID, Control, Status string
	Material                                      bool
	Evidence                                      map[string]string
	Failure, Unsupported, Cancel                  string
	Confirmed                                     *time.Time
}

func pathViews(ctx context.Context, q *dbq.Queries, org ids.OrgID, action ids.UUID) ([]PathView, error) {
	rows, err := q.ListResponsePaths(ctx, org, action)
	if err != nil {
		return nil, err
	}
	return toPathViews(rows), nil
}

func toPathViews(rows []dbq.PcResponsePath) []PathView {
	out := make([]PathView, 0, len(rows))
	for _, r := range rows {
		v := PathView{
			Type: r.PathType, SubjectType: r.SubjectType, SubjectID: r.SubjectID, Control: r.Control, Status: r.Status,
			Material: r.Material, Confirmed: r.ConfirmedAt,
		}
		_ = json.Unmarshal(r.Evidence, &v.Evidence)
		if r.Failure != nil {
			v.Failure = *r.Failure
		}
		if r.UnsupportedReason != nil {
			v.Unsupported = *r.UnsupportedReason
		}
		if r.CancelCapability != nil {
			v.Cancel = *r.CancelCapability
		}
		out = append(out, v)
	}
	return out
}

// sameControls compares two sets of controls by id, whatever their order.
func sameControls(a, b []pipeline.Control) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[ids.UUID]bool, len(a))
	for _, c := range a {
		seen[c.ID] = true
	}
	for _, c := range b {
		if !seen[c.ID] {
			return false
		}
	}
	return true
}

// ActionView is a response action with its paths.
type ActionView struct {
	Action dbq.PcResponseAction
	Paths  []PathView
	// Controls are the controls it added, with their lift state.
	Controls []dbq.PcContainmentControl
}

// GetAction returns one response action (containment.read).
func (s *Response) GetAction(ctx context.Context, id ids.UUID) (ActionView, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return ActionView{}, err
	}
	if err := c.Require(td.PermContainmentRead, td.OrgPath(c.Org)); err != nil {
		return ActionView{}, err
	}
	var out ActionView
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.GetResponseAction(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrActionNotFound
		} else if err != nil {
			return err
		}
		out.Action = a
		if out.Paths, err = pathViews(ctx, q, c.Org, id); err != nil {
			return err
		}
		out.Controls, err = q.ControlsOfAction(ctx, c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListActions lists response actions newest first, optionally of one case,
// incident or subject (containment.read): the read port cases' response
// lens and the operations queue adapt to (D49).
func (s *Response) ListActions(ctx context.Context, caseID, incidentID *ids.UUID, scope *reflexdomain.Subject, before *ids.UUID, limit int32) ([]dbq.PcResponseAction, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(td.PermContainmentRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var scopeType, scopeID *string
	if scope != nil {
		st, sid, err := scopeOf(*scope)
		if err != nil {
			// A credential or transaction action names its own scope type.
			st, sid = string(scope.Type), scope.ID
		}
		scopeType, scopeID = &st, &sid
	}
	var out []dbq.PcResponseAction
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ListResponseActions(ctx, dbq.ListResponseActionsParams{
			OrgID: c.Org, CaseID: caseID, IncidentID: incidentID, ScopeType: scopeType, ScopeID: scopeID, Before: before, MaxRows: limit,
		})
		return err
	}, db.ReadOnly())
	return out, err
}

// ListControls lists the org's controls, active only unless includeLifted
// (containment.read).
func (s *Response) ListControls(ctx context.Context, includeLifted bool, limit int32) ([]dbq.PcContainmentControl, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(td.PermContainmentRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []dbq.PcContainmentControl
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ListContainmentControls(ctx, c.Org, includeLifted, limit)
		return err
	}, db.ReadOnly())
	return out, err
}

// PlanView is a restoration plan with its controls and stages.
type PlanView struct {
	Plan     dbq.PcRestorationPlan
	Controls []dbq.PcContainmentControl
	Stages   []dbq.PcRestorationStage
}

// GetRestorationPlan returns one plan (containment.read).
func (s *Response) GetRestorationPlan(ctx context.Context, id ids.UUID) (PlanView, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return PlanView{}, err
	}
	if err := c.Require(td.PermContainmentRead, td.OrgPath(c.Org)); err != nil {
		return PlanView{}, err
	}
	var out PlanView
	err = s.C.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		p, err := q.GetRestorationPlan(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrPlanNotFound
		} else if err != nil {
			return err
		}
		out.Plan = p
		if out.Controls, err = q.RestorationPlanControls(ctx, c.Org, id); err != nil {
			return err
		}
		out.Stages, err = q.RestorationStages(ctx, c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}
