// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Errors of restorations (decision 11).
var (
	ErrAgentNotFound = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrNotSuspended  = pcerr.New(pcerr.FailedPrecondition, "AGENT_NOT_SUSPENDED", "only a suspended agent can be restored")
	ErrBadReason     = pcerr.New(pcerr.InvalidArgument, "REASON_INVALID", "the reason must be 1 to 1000 characters")
	// ErrAgentChanged refuses the approval of a restoration whose agent
	// changed after it was asked for; ask again.
	ErrAgentChanged = pcerr.New(pcerr.FailedPrecondition, "AGENT_CHANGED", "the agent changed after the restoration was asked for")
)

// maxRestoreReason caps a restoration's reason, in characters.
const maxRestoreReason = 1000

// Subject kinds of approval requests.
const (
	subjectAction      = "ACTION"
	subjectRestoration = "RESTORATION"
)

// approvalSubject reports whether requests of kind are approved on the
// page: held actions and restorations.
func approvalSubject(kind string) bool { return kind == subjectAction || kind == subjectRestoration }

// RequestRestoration asks for a suspended agent to be restored to the state
// it was suspended from (decision 11, F563). The caller must be a person
// holding agent.manage where the agent lives, and gives a reason, which the
// deciders see as untrusted text. It creates a RESTORATION approval request
// bound to the agent's recorded changes and the state it returns to, with
// its RESTORATION waitlist entry, due within 24 hours (or the org's shorter
// setting). A person holding agent.restore, other than the requester,
// approves it on the approval page with a security key. It returns the
// request and its entry; an agent with a live restoration returns that
// one.
func (s *Service) RequestRestoration(ctx context.Context, agent ids.UUID, reason string) (Request, ids.UUID, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Request{}, ids.UUID{}, err
	}
	if !c.Human() {
		return Request{}, ids.UUID{}, ErrHumanSession
	}
	if n := len([]rune(reason)); n == 0 || n > maxRestoreReason {
		return Request{}, ids.UUID{}, ErrBadReason
	}
	user := c.Principal.ID
	var out Request
	var entry ids.UUID
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.GetAgent(ctx, c.Org, agent)
		if db.IsNoRows(err) {
			return ErrAgentNotFound
		} else if err != nil {
			return err
		}
		path, err := agents.PathOf(ctx, q, a)
		if err != nil {
			return err
		}
		if !c.Can(td.PermAgentRead, path) {
			return ErrAgentNotFound
		}
		if !c.Can(td.PermAgentManage, path) {
			return td.ErrPermissionDenied(td.PermAgentManage)
		}
		if a.State != string(adomain.StateSuspended) || a.SuspendedFrom == nil {
			return ErrNotSuspended
		}
		if live, err := q.LiveRestoration(ctx, c.Org, agent); err == nil {
			if out, err = q.GetApprovalRequest(ctx, c.Org, live); err != nil {
				return err
			}
			entry, err = q.OpenEntryOf(ctx, c.Org, "approval_request", live)
			return err
		} else if !db.IsNoRows(err) {
			return err
		}
		id, err := insertRestoration(ctx, q, c.Org, a, user, reason)
		if err != nil {
			return err
		}
		if err := event(ctx, tx, "approval.restoration_requested", userActor(user), "", id,
			map[string]string{"agent": agent.String()}); err != nil {
			return err
		}
		out, err = q.GetApprovalRequest(ctx, c.Org, id)
		if err != nil {
			return err
		}
		entry, err = pgwaitlist.OpenRestoration(ctx, tx, c.Org, id, agent, user, out.DeadlineAt)
		return err
	})
	return out, entry, err
}

// insertRestoration renders, binds and inserts a restoration request.
func insertRestoration(ctx context.Context, q *dbq.Queries, org ids.OrgID, a dbq.PcAgent, user ids.UUID, reason string) (ids.UUID, error) {
	seq, err := q.AgentChangeCount(ctx, org, a.ID)
	if err != nil {
		return ids.UUID{}, err
	}
	suspendedAt, err := q.AgentSuspendedAt(ctx, org, a.ID)
	if err != nil {
		return ids.UUID{}, err
	}
	settings, err := q.GetWaitlistSettings(ctx, org)
	if err != nil && !db.IsNoRows(err) {
		return ids.UUID{}, err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	deadline := now.Add(wdomain.Deadline(wdomain.KindRestoration, settings.RestorationDeadlineS)).Truncate(time.Second)
	reqs := []apdomain.Requirement{apdomain.RestoreRequirement}
	display, err := apdomain.RenderRestoration(apdomain.RestorationInput{
		AgentID: a.ID, SuspendedFrom: *a.SuspendedFrom, SuspendedAt: suspendedAt, RequestedBy: user, Reason: reason,
		Requirements: reqs, Deadline: deadline,
	}).Canonical()
	if err != nil {
		return ids.UUID{}, err
	}
	binding, err := apdomain.RestorationParts{
		AgentID: a.ID, ChangeSeq: seq, RequestedState: *a.SuspendedFrom, RequestedBy: user, Reason: reason,
		Requirements: reqs, ExpiresAt: deadline, DisplayHash: display.Hash,
	}.Binding()
	if err != nil {
		return ids.UUID{}, err
	}
	rs, err := json.Marshal(reqs)
	if err != nil {
		return ids.UUID{}, err
	}
	id := ids.NewV7()
	return id, q.InsertRestorationRequest(ctx, dbq.InsertRestorationRequestParams{
		OrgID: org, ID: id, AgentID: a.ID, RequestedBy: &user, Binding: binding.Hash[:], BindingInput: binding.Input,
		Requirements: rs, Display: display.Input, DisplayHash: display.Hash[:], DeadlineAt: deadline,
	})
}

// restored uses an approved restoration at once (HR-176): the agent must
// still be suspended from the state the binding names, with no change
// since, and it returns to that state in this transaction.
func restored(ctx context.Context, q *dbq.Queries, orgID ids.OrgID, l locked, by ids.UUID) error {
	var b apdomain.RestorationBinding
	if err := json.Unmarshal(l.row.BindingInput, &b); err != nil {
		return err
	}
	a, err := q.GetAgent(ctx, orgID, l.row.AgentID)
	if err != nil {
		return err
	}
	seq, err := q.AgentChangeCount(ctx, orgID, l.row.AgentID)
	if err != nil {
		return err
	}
	if a.State != string(adomain.StateSuspended) || a.SuspendedFrom == nil || *a.SuspendedFrom != b.RequestedState || seq != b.AgentChangeSeq {
		return ErrAgentChanged
	}
	n, err := q.ConsumeRestoration(ctx, orgID, l.row.ID)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotWaiting
	}
	return agents.Restore(ctx, q, orgID, l.row.AgentID, adomain.State(b.RequestedState), adomain.UserActor(by), l.row.ID)
}
