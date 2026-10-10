// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the approval use cases (G0 M5 part 2): the responses
// that grant nothing (declining, asking for evidence, proposing a narrower
// action, HR-172), evidence from the run, and approving or stepping up once
// the approval page has verified a WebAuthn assertion over the binding
// (decision 1, HR-033). Each use case locks the request, checks the
// responder's eligibility by the database clock (HR-170) and changes the
// request by a conditional update (HR-004), with its audit event, in one
// transaction. Notes and evidence are never logged.
package app

import (
	"context"
	"slices"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the approval use cases.
var (
	ErrNotFound = pcerr.New(pcerr.NotFound, "APPROVAL_REQUEST_NOT_FOUND", "approval request not found")
	// ErrHumanSession refuses an API key, a service account or a workload
	// (HR-032, HR-172).
	ErrHumanSession = pcerr.New(pcerr.PermissionDenied, "HUMAN_SESSION_REQUIRED",
		"responding to an approval request needs a person signed in with a browser or the CLI")
	ErrNotEligible = pcerr.New(pcerr.PermissionDenied, "NOT_ELIGIBLE", "you are not eligible to decide this request")
	ErrNotWaiting  = pcerr.New(pcerr.FailedPrecondition, "APPROVAL_REQUEST_NOT_WAITING",
		"the request is not waiting for this response")
	ErrInvalidCode      = pcerr.New(pcerr.InvalidArgument, "INVALID_CODE", "unknown reason, alternative or question code")
	ErrEvidenceDeadline = pcerr.New(pcerr.InvalidArgument, "EVIDENCE_DEADLINE_INVALID",
		"the evidence deadline must be in the future and before the request's deadline")
	ErrTooMuchEvidence = pcerr.New(pcerr.ResourceExhausted, "EVIDENCE_LIMIT_REACHED", "the request has its maximum of evidence notes")
	ErrNoProposals     = pcerr.New(pcerr.FailedPrecondition, "PROPOSAL_UNAVAILABLE", "this request cannot take a narrower proposal")
	ErrNoEvidence      = pcerr.New(pcerr.FailedPrecondition, "EVIDENCE_UNAVAILABLE", "this request cannot take evidence")
	// ErrCeremony refuses an approval whose BINDING ceremony is unknown,
	// used, expired or bound to another session, user or request (HR-033).
	ErrCeremony = pcerr.New(pcerr.PermissionDenied, "CEREMONY_INVALID", "the security key ceremony is not valid for this approval")
)

// Responder is a person responding and the human session they respond
// through: the approval page's browser session, or the CLI session of a
// user's access token. API keys and service accounts are never responders.
type Responder struct {
	User    ids.UUID
	Browser ids.UUID
	CLI     ids.UUID
}

// ResponderFrom returns the caller as a responder, or ErrHumanSession.
func ResponderFrom(c tenancy.Caller) (Responder, error) {
	if c.Principal.Kind != td.KindUser || c.Session.IsZero() {
		return Responder{}, ErrHumanSession
	}
	switch c.Credential {
	case tenancy.CredAccessToken:
		return Responder{User: c.Principal.ID, CLI: c.Session}, nil
	case tenancy.CredBrowserSession:
		return Responder{User: c.Principal.ID, Browser: c.Session}, nil
	case tenancy.CredAPIKey:
	}
	return Responder{}, ErrHumanSession
}

func (r Responder) sessions() (browser, cli *ids.UUID) {
	if !r.Browser.IsZero() {
		b := r.Browser
		browser = &b
	}
	if !r.CLI.IsZero() {
		c := r.CLI
		cli = &c
	}
	return browser, cli
}

// Simulator checks a narrower proposal against the held action and decides
// it as the pipeline would, recording nothing (HR-172, F147).
type Simulator interface {
	Narrow(ctx context.Context, org ids.OrgID, held, proposed []byte) (Simulation, error)
}

// Simulation is a proposal's canonical parameters and the decision the
// agent would get for them.
type Simulation struct {
	Params   []byte
	Decision string
	Reasons  []Reason
}

// Reason is one reason of a simulated decision.
type Reason struct {
	Code, Check, Detail string
	Decisive            bool
}

// Service runs the approval use cases.
type Service struct {
	Pool      *db.Pool
	Simulator Simulator
	// Defs reads pinned definitions for batch approval.
	Defs Definitions
	// Ents gates batch review (Team edition); nil fails closed.
	Ents Entitlements
	// Notify sends outcome notices (slice 211); nil sends none.
	Notify Notifier
}

// Request is an approval request as the use cases return it.
type Request = dbq.PcApprovalRequest

// locked is a request read FOR UPDATE with its eligibility for one person.
type locked struct {
	row  dbq.PcApprovalRequest
	elig pgapprovals.Eligibility
}

// lock reads a request FOR UPDATE and the eligibility of user.
func lock(ctx context.Context, q *dbq.Queries, org ids.OrgID, id, user ids.UUID) (locked, error) {
	row, err := q.GetApprovalRequestForUpdate(ctx, org, id)
	if db.IsNoRows(err) {
		return locked{}, ErrNotFound
	}
	if err != nil {
		return locked{}, err
	}
	e, err := pgapprovals.LoadEligibility(ctx, q, org, id, []ids.UUID{user})
	return locked{row: row, elig: e}, err
}

// mayRespond reports whether user may respond to the request at all, for
// any of its requirements.
func (l locked) mayRespond(user ids.UUID) bool {
	for _, r := range l.elig.Requirements {
		if ok, _ := apdomain.MayRespond(r, l.elig.People[user], l.elig.Context); ok {
			return true
		}
	}
	return false
}

// visible reports whether the caller may see a request: its eligible
// deciders, the run's launcher and principal, and holders of approval.read
// on the agent's scope path (design decision 10). Anyone else gets "not
// found" (T-037).
func visible(ctx context.Context, q *dbq.Queries, c tenancy.Caller, l locked) (bool, error) {
	if c.Principal.Kind == td.KindUser {
		if l.mayRespond(c.Principal.ID) {
			return true, nil
		}
		run := l.elig.Context.Run
		for _, p := range []string{run.Launcher.String(), run.Principal.String()} {
			if p == c.Principal.String() {
				return true, nil
			}
		}
	}
	a, err := q.GetAgent(ctx, c.Org, l.row.AgentID)
	if err != nil {
		return false, err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return false, err
	}
	return c.Can(td.PermApprovalRead, path), nil
}

// refuse answers a responder who may not respond: not found unless they may
// see the request (T-037).
func refuse(ctx context.Context, q *dbq.Queries, c tenancy.Caller, l locked) error {
	ok, err := visible(ctx, q, c, l)
	if err != nil {
		return err
	}
	if ok {
		return ErrNotEligible
	}
	return ErrNotFound
}

func event(ctx context.Context, tx db.TenantTx, name string, actor evdomain.Actor, reason string, request ids.UUID,
	details map[string]string,
) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, ReasonCode: reason,
		Object: &audit.Object{Type: "approval_request", ID: request.String()}, Details: details,
	})
	return err
}

func userActor(u ids.UUID) evdomain.Actor {
	return evdomain.Actor{Type: string(td.KindUser), ID: u.String()}
}

func waiting(row dbq.PcApprovalRequest, now time.Time, states ...apdomain.State) bool {
	st, _ := apdomain.At(apdomain.State(row.State), apdomain.Times{
		Deadline: row.DeadlineAt, EvidenceDeadline: row.EvidenceDeadlineAt, ConsumeBy: row.ConsumeBy,
	}, now)
	return slices.Contains(states, st)
}
