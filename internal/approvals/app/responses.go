// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Decline declines a waiting request (HR-172): the held action ends as DENY
// (APPROVAL_DECLINED) at its next resubmission. The note is for people only:
// never returned to the workload, sent in a notification or logged.
func (s *Service) Decline(ctx context.Context, id ids.UUID, reason, alternative, note string) (Request, error) {
	if !slices.Contains(apdomain.DeclineReasons, reason) || (alternative != "" && !slices.Contains(apdomain.Alternatives, alternative)) ||
		len([]rune(note)) > apdomain.MaxNote {
		return Request{}, ErrInvalidCode
	}
	return s.end(ctx, id, dbq.InsertApprovalResponseParams{Kind: "DECLINE", ReasonCode: &reason, AlternativeCode: optional(alternative), Note: note},
		apdomain.EndDeclined, "approval.declined", reason)
}

// end records a response that ends a waiting request: a decline or a
// narrower proposal (HR-171: terminal for the action).
func (s *Service) end(ctx context.Context, id ids.UUID, resp dbq.InsertApprovalResponseParams, endReason, eventName, code string) (Request, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Request{}, err
	}
	r, err := ResponderFrom(c)
	if err != nil {
		return Request{}, err
	}
	var out Request
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.endIn(ctx, tx, c, r, id, resp, endReason, eventName, code)
		return err
	})
	return out, err
}

// endIn is end inside the caller's transaction.
func (s *Service) endIn(ctx context.Context, tx db.TenantTx, c tenancy.Caller, r Responder, id ids.UUID, resp dbq.InsertApprovalResponseParams,
	endReason, eventName, code string,
) (Request, error) {
	q := dbq.New(tx)
	l, err := lock(ctx, q, c.Org, id, r.User)
	if err != nil {
		return Request{}, err
	}
	if !l.mayRespond(r.User) {
		return Request{}, refuse(ctx, q, c, l)
	}
	if !waiting(l.row, l.elig.Context.Now, apdomain.StatePending, apdomain.StateEvidenceRequested) {
		return Request{}, ErrNotWaiting
	}
	resp.OrgID, resp.ID, resp.RequestID, resp.UserID = c.Org, ids.NewV7(), id, r.User
	resp.SessionID, resp.CliSessionID = r.sessions()
	if err := q.InsertApprovalResponse(ctx, resp); err != nil {
		return Request{}, err
	}
	if err := pgapprovals.End(ctx, tx, org(c), id, endReason, "REJECTED"); err != nil {
		return Request{}, err
	}
	details := map[string]string(nil)
	if resp.BatchID != nil {
		details = map[string]string{"batch": resp.BatchID.String()}
	}
	if err := event(ctx, tx, eventName, userActor(r.User), code, id, details); err != nil {
		return Request{}, err
	}
	if err := tell(ctx, tx, s.Notify, c.Org, id, string(apdomain.StateDeclined), "approval.decided",
		map[string]string{"outcome": endReason}); err != nil {
		return Request{}, err
	}
	return q.GetApprovalRequest(ctx, c.Org, id)
}

func org(c tenancy.Caller) ids.OrgID { return c.Org }

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// RequestEvidence asks the run for evidence before evidenceDeadline, which
// must come before the request's deadline: the request waits in
// EVIDENCE_REQUESTED, and without evidence by then it expires (HR-039).
func (s *Service) RequestEvidence(ctx context.Context, id ids.UUID, question, note string, evidenceDeadline time.Time) (Request, error) {
	if !slices.Contains(apdomain.Questions, question) || len([]rune(note)) > apdomain.MaxNote {
		return Request{}, ErrInvalidCode
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Request{}, err
	}
	r, err := ResponderFrom(c)
	if err != nil {
		return Request{}, err
	}
	var out Request
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		l, err := lock(ctx, q, c.Org, id, r.User)
		if err != nil {
			return err
		}
		if !l.mayRespond(r.User) {
			return refuse(ctx, q, c, l)
		}
		if l.row.SubjectKind != subjectAction {
			return ErrNoEvidence // a restoration has no run to give it
		}
		if !waiting(l.row, l.elig.Context.Now, apdomain.StatePending) {
			return ErrNotWaiting
		}
		n, err := q.AskForEvidence(ctx, &evidenceDeadline, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrEvidenceDeadline
		}
		resp := dbq.InsertApprovalResponseParams{
			OrgID: c.Org, ID: ids.NewV7(), RequestID: id, UserID: r.User, Kind: "REQUEST_EVIDENCE",
			ReasonCode: &question, Note: note,
		}
		resp.SessionID, resp.CliSessionID = r.sessions()
		if err := q.InsertApprovalResponse(ctx, resp); err != nil {
			return err
		}
		if err := event(ctx, tx, "approval.evidence_requested", userActor(r.User), question, id, nil); err != nil {
			return err
		}
		out, err = q.GetApprovalRequest(ctx, c.Org, id)
		return err
	})
	return out, err
}

// Proposal is a narrower proposal and the decision the agent would get.
type Proposal struct {
	Request    Request
	Simulation Simulation
}

// ProposeNarrower proposes the held action with narrower material
// parameters (HR-172, F147). The proposal is checked against the held
// action and simulated; unless validateOnly, the request ends DECLINED
// (NARROWER_PROPOSED) and the wait handle returns the proposed parameters,
// which the agent may submit as a new action with its own decision.
func (s *Service) ProposeNarrower(ctx context.Context, id ids.UUID, params []byte, note string, validateOnly bool) (Proposal, error) {
	if len([]rune(note)) > apdomain.MaxNote || !jsontext.Value(params).IsValid() {
		return Proposal{}, ErrInvalidCode
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Proposal{}, err
	}
	r, err := ResponderFrom(c)
	if err != nil {
		return Proposal{}, err
	}
	// The eligibility and the held action are read first; the pipeline
	// simulates outside any transaction of this use case.
	var held []byte
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		l, err := lock(ctx, q, c.Org, id, r.User)
		if err != nil {
			return err
		}
		if !l.mayRespond(r.User) {
			return refuse(ctx, q, c, l)
		}
		if l.row.SubjectKind != "ACTION" || len(l.row.ActionIr) == 0 {
			return ErrNoProposals
		}
		if !waiting(l.row, l.elig.Context.Now, apdomain.StatePending, apdomain.StateEvidenceRequested) {
			return ErrNotWaiting
		}
		held = l.row.ActionIr
		return nil
	})
	if err != nil {
		return Proposal{}, err
	}
	sim, err := s.Simulator.Narrow(ctx, c.Org, held, params)
	if err != nil {
		return Proposal{}, err
	}
	out := Proposal{Simulation: sim}
	if validateOnly {
		err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			out.Request, err = dbq.New(tx).GetApprovalRequest(ctx, c.Org, id)
			return err
		}, db.ReadOnly())
		return out, err
	}
	out.Request, err = s.end(ctx, id, dbq.InsertApprovalResponseParams{Kind: "PROPOSE_NARROWER", Note: note, ProposedParams: sim.Params},
		apdomain.EndNarrowerProposed, "approval.narrower_proposed", apdomain.ReasonNarrowerProposed)
	return out, err
}

// Author is who submits evidence: the run's launcher or represented
// principal (a person), or the run's workload instance.
type Author struct {
	User     ids.UUID
	Instance ids.UUID
}

// SubmitEvidence adds an UNTRUSTED note to a waiting request from the
// run's launcher or represented principal (HR-172). It never changes the
// binding; a request waiting for evidence returns to PENDING.
func (s *Service) SubmitEvidence(ctx context.Context, id ids.UUID, note string) (Request, ids.UUID, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Request{}, ids.UUID{}, err
	}
	if _, err := ResponderFrom(c); err != nil {
		return Request{}, ids.UUID{}, err
	}
	return s.evidence(ctx, c.Org, Author{User: c.Principal.ID}, func(q *dbq.Queries) (dbq.PcApprovalRequest, error) {
		row, err := q.GetApprovalRequestForUpdate(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return row, ErrNotFound
		}
		return row, err
	}, note)
}

// SubmitWorkloadEvidence adds an UNTRUSTED note from the workload to the
// live request of a held transaction of its own run (HR-172, HR-174).
func (s *Service) SubmitWorkloadEvidence(ctx context.Context, org ids.OrgID, instance, run, transaction ids.UUID, note string) (Request, ids.UUID, error) {
	return s.evidence(ctx, org, Author{Instance: instance}, func(q *dbq.Queries) (dbq.PcApprovalRequest, error) {
		row, err := q.LiveRequestOfTransaction(ctx, org, &transaction)
		if db.IsNoRows(err) || (err == nil && (row.RunID == nil || *row.RunID != run)) {
			return row, ErrNotFound
		}
		return row, err
	}, note)
}

func (s *Service) evidence(ctx context.Context, org ids.OrgID, a Author, load func(*dbq.Queries) (dbq.PcApprovalRequest, error), note string) (Request, ids.UUID, error) {
	if note == "" || len(note) > apdomain.MaxEvidence {
		return Request{}, ids.UUID{}, ErrInvalidCode
	}
	evidence := ids.NewV7()
	var out Request
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := load(q)
		if err != nil {
			return err
		}
		if !a.User.IsZero() {
			// Only the run's launcher or represented principal (a person).
			e, err := pgapprovals.LoadEligibility(ctx, q, org, row.ID, nil)
			if err != nil {
				return err
			}
			mine := false
			for _, p := range []string{e.Context.Run.Launcher.String(), e.Context.Run.Principal.String()} {
				mine = mine || p == "user:"+a.User.String()
			}
			if !mine {
				return ErrNotFound
			}
		} else {
			inst, err := q.RunInstance(ctx, org, *row.RunID)
			if err != nil || inst == nil || *inst != a.Instance {
				return ErrNotFound
			}
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if !waiting(row, now, apdomain.StatePending, apdomain.StateEvidenceRequested) {
			return ErrNotWaiting
		}
		n, err := q.CountApprovalEvidence(ctx, org, row.ID)
		if err != nil {
			return err
		}
		if n >= apdomain.MaxEvidenceNotes {
			return ErrTooMuchEvidence
		}
		p := dbq.InsertApprovalEvidenceParams{OrgID: org, ID: evidence, RequestID: row.ID, Note: note}
		actor := userActor(a.User)
		if a.User.IsZero() {
			p.AuthorKind, p.AuthorInstanceID, actor.Type, actor.ID = "workload", &a.Instance, "instance", a.Instance.String()
		} else {
			p.AuthorKind, p.AuthorUserID = "user", &a.User
		}
		if err := q.InsertApprovalEvidence(ctx, p); err != nil {
			return err
		}
		if _, err := q.EvidenceArrived(ctx, org, row.ID); err != nil {
			return err
		}
		if err := event(ctx, tx, "approval.evidence_submitted", actor, "", row.ID,
			map[string]string{"evidence": evidence.String()}); err != nil {
			return err
		}
		out, err = q.GetApprovalRequest(ctx, org, row.ID)
		return err
	})
	return out, evidence, err
}

// Assertion is a verified WebAuthn assertion over the binding (HR-033): the
// approval page verified its signature, origin, RP ID, UV flag and counter
// (slice 208); it is kept for M6 (HR-038).
type Assertion struct {
	Ceremony          ids.UUID
	Credential        ids.UUID
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// Approve records an approval or a step-up from the approval page (decision
// 1): in one transaction it consumes the BINDING ceremony, checks the
// person's eligibility and cooldowns again with the credential they used
// (HR-035, HR-170), records the response toward the first requirement
// still short that they qualify for, and when every requirement is met
// moves the request to APPROVED with its consume-by time (decision 6).
func (s *Service) Approve(ctx context.Context, orgID ids.OrgID, r Responder, id ids.UUID, a Assertion) (Request, error) {
	if r.Browser.IsZero() || r.User.IsZero() {
		return Request{}, ErrHumanSession
	}
	var out Request
	err := s.Pool.InTenantTx(ctx, orgID, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.ConsumeBindingCeremony(ctx, dbq.ConsumeBindingCeremonyParams{
			OrgID: orgID, ID: a.Ceremony, RequestID: &id, UserID: r.User, SessionID: r.Browser,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrCeremony
		}
		l, err := lock(ctx, q, orgID, id, r.User)
		if err != nil {
			return err
		}
		// Count the responses only under the lock: two people approving at
		// once each see the other's response (TestRace_TwoApproversAtOnce).
		rows, err := q.CountingResponses(ctx, orgID, id)
		if err != nil {
			return err
		}
		users := []ids.UUID{r.User}
		var counted []apdomain.Response
		for _, x := range rows {
			users = append(users, x.UserID)
			counted = append(counted, apdomain.Response{UserID: x.UserID, CredentialID: x.CredentialID, Requirement: int(x.Requirement)})
		}
		if e, err := pgapprovals.LoadEligibility(ctx, q, orgID, id, users); err == nil {
			l.elig = e
		} else {
			return err
		}
		if !approvalSubject(l.row.SubjectKind) || !waiting(l.row, l.elig.Context.Now, apdomain.StatePending) {
			return ErrNotWaiting
		}
		reqs := l.elig.Requirements
		me := l.elig.People[r.User]
		idx, ok := apdomain.Next(reqs, counted, func(i int) bool {
			ok, _ := apdomain.Check(reqs[i], me, l.elig.Context, a.Credential)
			return ok
		})
		if !ok {
			return ErrNotEligible
		}
		kind := "APPROVE"
		if reqs[idx].Kind == apdomain.KindStepUp {
			kind = "STEP_UP"
		}
		if err := q.InsertApprovalResponse(ctx, dbq.InsertApprovalResponseParams{
			OrgID: orgID, ID: ids.NewV7(), RequestID: id, UserID: r.User, SessionID: &r.Browser, Kind: kind,
			Requirement: pgtype.Int2{Int16: int16(idx), Valid: true}, CredentialID: &a.Credential, //nolint:gosec // < 16
			AuthenticatorData: a.AuthenticatorData, ClientDataJson: a.ClientDataJSON, Signature: a.Signature,
		}); err != nil {
			return err
		}
		if err := event(ctx, tx, "approval.response", userActor(r.User), kind, id,
			map[string]string{"requirement": reqs[idx].Kind + ":" + reqs[idx].Role + reqs[idx].Subject}); err != nil {
			return err
		}
		counted = append(counted, apdomain.Response{UserID: r.User, CredentialID: a.Credential, Requirement: idx})
		if apdomain.Met(reqs, counted) {
			if err := approved(ctx, tx, q, orgID, l, counted); err != nil {
				return err
			}
			state := apdomain.StateApproved
			if l.row.SubjectKind == subjectRestoration {
				if err := restored(ctx, q, orgID, l, r.User); err != nil {
					return err
				}
				if err := event(ctx, tx, "approval.restoration_completed", userActor(r.User), "", id,
					map[string]string{"agent": l.row.AgentID.String()}); err != nil {
					return err
				}
				state = apdomain.StateConsumed
			}
			if err := tell(ctx, tx, s.Notify, orgID, id, string(state), "approval.decided",
				map[string]string{"outcome": string(apdomain.StateApproved)}); err != nil {
				return err
			}
			if slices.ContainsFunc(reqs, func(r apdomain.Requirement) bool { return r.Count >= 2 }) {
				if err := tellAdmins(ctx, tx, s.Notify, orgID, l.row, "approval.multi_person_completed"); err != nil {
					return err
				}
			}
		}
		out, err = q.GetApprovalRequest(ctx, orgID, id)
		return err
	})
	return out, err
}

// approved moves a met request to APPROVED with its consume-by time, closes
// its entry and audits it; a multi-person approval is recorded for the
// admins' notice (HR-035).
func approved(ctx context.Context, tx db.TenantTx, q *dbq.Queries, orgID ids.OrgID, l locked, rs []apdomain.Response) error {
	w, err := q.ConsumeWindow(ctx, orgID)
	if err != nil {
		return err
	}
	window := apdomain.DefaultConsumeWindow
	if w != nil {
		window = time.Duration(*w) * time.Second
	}
	now := l.elig.Context.Now
	by := apdomain.ConsumeBy(now, l.row.DeadlineAt, window)
	n, err := q.MarkApproved(ctx, &by, orgID, l.row.ID)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotWaiting
	}
	system := "system"
	if _, err := q.CloseRequestEntry(ctx, dbq.CloseRequestEntryParams{State: "APPROVED", DecidedBy: &system, Reason: "", OrgID: orgID, RequestID: l.row.ID}); err != nil {
		return err
	}
	if err := event(ctx, tx, "approval.approved", userActor(rs[len(rs)-1].UserID), "", l.row.ID, nil); err != nil {
		return err
	}
	multi := slices.ContainsFunc(l.elig.Requirements, func(r apdomain.Requirement) bool { return r.Count >= 2 })
	if !multi {
		return nil
	}
	return event(ctx, tx, "approval.multi_person_completed", userActor(rs[len(rs)-1].UserID), "", l.row.ID, nil)
}

// BeginApproval checks that a person may approve or step up now, before the
// approval page starts the BINDING ceremony (design decision 7), and
// returns the binding, which is the ceremony's challenge (HR-033). The page
// has already checked that the person may see the request.
func (s *Service) BeginApproval(ctx context.Context, orgID ids.OrgID, r Responder, id ids.UUID) ([32]byte, error) {
	var binding [32]byte
	if r.Browser.IsZero() || r.User.IsZero() {
		return binding, ErrHumanSession
	}
	err := s.Pool.InTenantTx(ctx, orgID, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetApprovalRequest(ctx, orgID, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := approvable(ctx, q, orgID, row, r.User); err != nil {
			return err
		}
		copy(binding[:], row.Binding)
		return nil
	}, db.ReadOnly())
	return binding, err
}

// approvable checks that user may approve or step up the request now: it is
// PENDING, they have not responded yet, and they are eligible, with one of
// their active keys, for a requirement still short. It returns
// ErrNotEligible or ErrNotWaiting otherwise.
func approvable(ctx context.Context, q *dbq.Queries, orgID ids.OrgID, row dbq.PcApprovalRequest, user ids.UUID) error {
	rows, err := q.CountingResponses(ctx, orgID, row.ID)
	if err != nil {
		return err
	}
	users := []ids.UUID{user}
	var counted []apdomain.Response
	for _, x := range rows {
		if x.UserID == user {
			return ErrNotEligible // one response per person (HR-035)
		}
		users = append(users, x.UserID)
		counted = append(counted, apdomain.Response{UserID: x.UserID, CredentialID: x.CredentialID, Requirement: int(x.Requirement)})
	}
	e, err := pgapprovals.LoadEligibility(ctx, q, orgID, row.ID, users)
	if err != nil {
		return err
	}
	if !approvalSubject(row.SubjectKind) || !waiting(row, e.Context.Now, apdomain.StatePending) {
		return ErrNotWaiting
	}
	me := e.People[user]
	if _, ok := apdomain.Next(e.Requirements, counted, func(i int) bool {
		ok, _ := apdomain.Check(e.Requirements[i], me, e.Context, ids.UUID{})
		return ok
	}); !ok {
		return ErrNotEligible
	}
	return nil
}
