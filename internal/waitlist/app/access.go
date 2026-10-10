// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Errors of access requests (decision 10).
var (
	ErrRunNotFound = pcerr.New(pcerr.NotFound, "RUN_NOT_FOUND", "run not found")
	ErrNoGrant     = pcerr.New(pcerr.FailedPrecondition, "RUN_HAS_NO_GRANT", "the run has no grant to change")
	ErrBadNote     = pcerr.New(pcerr.InvalidArgument, "NOTE_INVALID", "the note must be 1 to 4096 bytes")
	// ErrNotScopeDenial refuses a workload citing a transaction that was
	// not denied for the grant's scope.
	ErrNotScopeDenial = pcerr.New(pcerr.FailedPrecondition, "NOT_A_SCOPE_DENIAL",
		"the transaction was not denied for the grant's scope")
	ErrAccessRequestLimit = pcerr.New(pcerr.ResourceExhausted, "ACCESS_REQUEST_LIMIT",
		"the run's workload has filed its maximum of access requests")
	ErrNotAccessRequest = pcerr.New(pcerr.FailedPrecondition, "ACCESS_REQUEST_NOT_OPEN", "the entry is not an open access request")
	ErrBadReason        = pcerr.New(pcerr.InvalidArgument, "REASON_INVALID", "the reason must be 1 to 500 characters")
)

// maxReason caps a dismissal's reason, in characters.
const maxReason = 500

func checkNote(note string) error {
	if note == "" || len(note) > wdomain.MaxAccessNote {
		return ErrBadNote
	}
	return nil
}

// RequestAccess files an access request for a run's grant from the run's
// launcher or represented principal (decision 10, F051). The note is
// UNTRUSTED. It grants nothing: the grant's issuer decides through a grant
// revision citing the entry. A grant with an open request returns that
// one. Anyone else gets "run not found" (T-037).
func (w *Writer) RequestAccess(ctx context.Context, run ids.UUID, note string, transaction *ids.UUID) (Entry, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Entry{}, err
	}
	if err := checkNote(note); err != nil {
		return Entry{}, err
	}
	var out Entry
	err = w.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetRun(ctx, c.Org, run)
		if db.IsNoRows(err) {
			return ErrRunNotFound
		} else if err != nil {
			return err
		}
		mine := c.Human() && (eq(r.PcRun.LauncherUserID, c.Principal.ID) || eq(r.PcRun.PrincipalUserID, c.Principal.ID))
		if !mine {
			return ErrRunNotFound
		}
		a := pgwaitlist.AccessRequest{Run: run, Agent: r.PcRun.AgentID, Transaction: transaction, Note: note, RequestedBy: c.Principal.String()}
		if transaction != nil {
			t, err := q.RunTransaction(ctx, c.Org, *transaction, run)
			if db.IsNoRows(err) {
				return ErrEntryNotFound
			} else if err != nil {
				return err
			}
			a.Reason = t.ReasonCode
		}
		id, err := openAccess(ctx, tx, q, c.Org, r.PcRun, a, c.Actor())
		if err != nil {
			return err
		}
		out, err = entryOf(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// RequestWorkloadAccess files an access request from a run's workload,
// citing one of its own run's denials about the grant's scope, at most 3
// per run (decision 10). The note is UNTRUSTED. It returns the entry (the
// grant's open one, when there is one).
func (w *Writer) RequestWorkloadAccess(ctx context.Context, org ids.OrgID, instance, run, transaction ids.UUID, note string) (Entry, error) {
	if err := checkNote(note); err != nil {
		return Entry{}, err
	}
	var out Entry
	err := w.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetRun(ctx, org, run)
		if db.IsNoRows(err) || (err == nil && !eq(r.PcRun.InstanceID, instance)) {
			return ErrRunNotFound
		} else if err != nil {
			return err
		}
		t, err := q.RunTransaction(ctx, org, transaction, run)
		if db.IsNoRows(err) {
			return ErrEntryNotFound
		} else if err != nil {
			return err
		}
		if !wdomain.ScopeDenial(t.Decision, t.ReasonCode) {
			return ErrNotScopeDenial
		}
		n, err := q.CountWorkloadAccessRequests(ctx, org, &run)
		if err != nil {
			return err
		}
		if n >= wdomain.MaxWorkloadAccessRequests {
			return ErrAccessRequestLimit
		}
		actor := evdomain.Actor{Type: "instance", ID: instance.String()}
		id, err := openAccess(ctx, tx, q, org, r.PcRun, pgwaitlist.AccessRequest{
			Run: run, Agent: r.PcRun.AgentID, Transaction: &transaction, Reason: t.ReasonCode, Note: note,
			RequestedBy: "instance:" + instance.String(),
		}, actor)
		if err != nil {
			return err
		}
		out, err = entryOf(ctx, q, org, id)
		return err
	})
	return out, err
}

// openAccess opens the request for the run's current grant.
func openAccess(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, run dbq.PcRun, a pgwaitlist.AccessRequest,
	actor evdomain.Actor,
) (ids.UUID, error) {
	if run.GrantID == nil {
		return ids.UUID{}, ErrNoGrant
	}
	rev, err := q.GrantCurrentRevision(ctx, org, *run.GrantID)
	if err != nil {
		return ids.UUID{}, err
	}
	a.Grant, a.GrantRevision = *run.GrantID, int(rev)
	return pgwaitlist.OpenAccessRequest(ctx, tx, org, a, actor)
}

// DismissAccessRequest closes an access request without changing the grant
// (HR-176). The caller must be a person holding grant.issue on the agent's
// scope path; anyone who may not read the entry gets "not found".
func (w *Writer) DismissAccessRequest(ctx context.Context, id ids.UUID, reason string) (Entry, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Entry{}, err
	}
	if reason == "" || len([]rune(reason)) > maxReason {
		return Entry{}, ErrBadReason
	}
	var out Entry
	err = w.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetWaitlistEntry(ctx, c.Org, id)
		if db.IsNoRows(err) || (err == nil && (r.Kind != wdomain.KindAccessRequest || r.AgentID == nil)) {
			return ErrEntryNotFound
		} else if err != nil {
			return err
		}
		a, err := q.GetAgent(ctx, c.Org, *r.AgentID)
		if err != nil {
			return err
		}
		path, err := agents.PathOf(ctx, q, a)
		if err != nil {
			return err
		}
		if !c.Can(td.PermWaitlistRead, path) {
			return ErrEntryNotFound
		}
		if !c.Human() || !c.Can(td.PermGrantIssue, path) {
			return td.ErrPermissionDenied(td.PermGrantIssue)
		}
		err = pgwaitlist.DismissAccessRequest(ctx, tx, c.Org, id, r.SubjectID, c.Principal.String(), reason)
		if errors.Is(err, pgwaitlist.ErrAccessRequestNotOpen) {
			return ErrNotAccessRequest
		} else if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "waitlist.access_request_dismissed", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "waitlist_entry", ID: id.String()}, Details: map[string]string{"grant": r.SubjectID.String()},
		}); err != nil {
			return err
		}
		out, err = entryOf(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

func entryOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Entry, error) {
	r, err := q.GetWaitlistEntry(ctx, org, id)
	if err != nil {
		return Entry{}, err
	}
	return view(r)
}

func eq(p *ids.UUID, v ids.UUID) bool { return p != nil && *p == v }
