// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The approval page's reads (slice 209). Both read by the database clock in
// one read-only transaction and record nothing; a request the caller may
// not see is "not found" (T-037).

const (
	// InboxScan caps the waiting requests the list checks, most urgent
	// first.
	InboxScan = 100
	// RecentLimit caps the caller's recent responses on the list (F626).
	RecentLimit = 10
)

// Summary is one request on the list.
type Summary struct {
	ID        ids.UUID
	Title     string
	Operation string
	State     apdomain.State
	Priority  int
	Deadline  time.Time
}

// Recent is one of the caller's recent responses.
type Recent struct {
	Request   ids.UUID
	Kind      string
	At        time.Time
	Voided    bool
	Operation string
	State     string
}

// Inbox is the list of requests waiting for the caller (F626): what they may
// decide and have not approved yet, where their roles let them decide (the
// scope checked), and their recent responses.
type Inbox struct {
	Waiting []Summary
	// Scopes are the caller's bindings of roles that decide approvals.
	Scopes []td.Binding
	// Capped is set when more requests were waiting than the list checks.
	Capped bool
	Recent []Recent
}

// Inbox lists the requests waiting for the calling person.
func (s *Service) Inbox(ctx context.Context) (Inbox, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Inbox{}, err
	}
	if !c.Human() {
		return Inbox{}, ErrHumanSession
	}
	user := c.Principal.ID
	out := Inbox{}
	for _, b := range c.Bindings {
		if r, ok := td.LookupRole(b.Role); ok && r.Has(td.PermApprovalRespond) {
			out.Scopes = append(out.Scopes, b)
		}
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.WaitingApprovalRequests(ctx, c.Org, InboxScan+1)
		if err != nil {
			return err
		}
		if len(rows) > InboxScan {
			rows, out.Capped = rows[:InboxScan], true
		}
		list := make([]ids.UUID, len(rows))
		for i, r := range rows {
			list[i] = r.ID
		}
		done, err := q.RespondedRequests(ctx, c.Org, user, list)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if slices.Contains(done, r.ID) {
				continue
			}
			e, err := pgapprovals.LoadEligibility(ctx, q, c.Org, r.ID, []ids.UUID{user})
			if err != nil {
				return err
			}
			if !(locked{elig: e}).mayRespond(user) {
				continue
			}
			st, _ := apdomain.At(apdomain.State(r.State), apdomain.Times{
				Deadline: r.DeadlineAt, EvidenceDeadline: r.EvidenceDeadlineAt, ConsumeBy: r.ConsumeBy,
			}, e.Context.Now)
			out.Waiting = append(out.Waiting, Summary{
				ID: r.ID, Title: title(r.Display, r.Operation), Operation: r.Operation, State: st, Priority: int(r.Priority),
				Deadline: r.DeadlineAt,
			})
		}
		recent, err := q.RecentResponsesBy(ctx, c.Org, user, RecentLimit)
		for _, x := range recent {
			out.Recent = append(out.Recent, Recent{
				Request: x.RequestID, Kind: x.Kind, At: x.CreatedAt, Voided: x.Voided, Operation: x.Operation, State: x.State,
			})
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// title is a stored display's title, or the operation when it has none.
func title(display []byte, operation string) string {
	var d apdomain.Display
	if json.Unmarshal(display, &d) != nil || d.Title == "" {
		return operation
	}
	return d.Title
}

// ResponseLine is one response on a request's page. A decider's note is
// for people only (design decision 18) and is cleaned like any free text.
type ResponseLine struct {
	ID   ids.UUID
	User ids.UUID
	Kind string
	// Requirement is the requirement an approval counted toward, or -1.
	Requirement         int
	Reason, Alternative string
	Note                apdomain.Untrusted
	// Proposed is a narrower proposal's canonical parameters.
	Proposed string
	At       time.Time
	// Voided is the reason a response no longer counts.
	Voided   string
	VoidedAt *time.Time
	// Credential and Batch are an approval's key and batch, if any.
	Credential, Batch *ids.UUID
}

// EvidenceLine is one UNTRUSTED evidence note (HR-034).
type EvidenceLine struct {
	ID ids.UUID
	// Author is "user:<id>" or "instance:<id>".
	Author string
	Note   apdomain.Untrusted
	At     time.Time
}

// View is one request as the approval page shows it: the stored display
// the binding covers (HR-034), the state by the database clock, the
// responses and evidence, and what the caller may do now.
type View struct {
	Request   Request
	Display   apdomain.Display
	State     apdomain.State
	Now       time.Time
	Responses []ResponseLine
	Evidence  []EvidenceLine
	// MayRespond: the caller may decline, ask for evidence or propose a
	// narrower action while the request waits. MayApprove: the caller may
	// approve or step up now.
	MayRespond, MayApprove bool
	// Params are the held action's parameters, cleaned, for a narrower
	// proposal; empty when the request cannot take one.
	Params apdomain.Untrusted
	// Requirements are the merged requirements; Variants the earlier
	// requests of the same grant, operation and target (HR-037);
	// Eligibility the caller's, for the API.
	Requirements []apdomain.Requirement
	Variants     []Variant
	Eligibility  Eligibility
}

// maxParams caps the held parameters shown for a narrower proposal.
const maxParams = 16384

// heldParams is the held action's canonical parameters, cleaned.
func heldParams(row dbq.PcApprovalRequest) apdomain.Untrusted {
	var a actionir.ActionIR
	if row.SubjectKind != "ACTION" || json.Unmarshal(row.ActionIr, &a) != nil || len(a.Params) == 0 {
		return apdomain.Untrusted{}
	}
	return apdomain.Clean("params", string(a.Params), maxParams)
}

// View reads one request for the calling person.
func (s *Service) View(ctx context.Context, id ids.UUID) (View, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return View{}, err
	}
	var users []ids.UUID
	if c.Human() {
		users = []ids.UUID{c.Principal.ID}
	}
	var out View
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetApprovalRequest(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		e, err := pgapprovals.LoadEligibility(ctx, q, c.Org, id, users)
		if err != nil {
			return err
		}
		l := locked{row: row, elig: e}
		if ok, err := visible(ctx, q, c, l); err != nil || !ok {
			return orNotFound(err)
		}
		out = View{Request: row, Now: e.Context.Now}
		if err := json.Unmarshal(row.Display, &out.Display); err != nil {
			return err
		}
		out.State, _ = apdomain.At(apdomain.State(row.State), apdomain.Times{
			Deadline: row.DeadlineAt, EvidenceDeadline: row.EvidenceDeadlineAt, ConsumeBy: row.ConsumeBy,
		}, out.Now)
		if c.Human() && l.mayRespond(c.Principal.ID) {
			out.MayRespond = out.State == apdomain.StatePending || out.State == apdomain.StateEvidenceRequested
			if out.MayRespond {
				out.Params = heldParams(row)
			}
			err := approvable(ctx, q, c.Org, row, c.Principal.ID)
			switch {
			case err == nil:
				out.MayApprove = true
			case !errors.Is(err, ErrNotWaiting) && !errors.Is(err, ErrNotEligible):
				return err
			}
		}
		if out.Responses, err = responseLines(ctx, q, c.Org, id); err != nil {
			return err
		}
		if out.Evidence, err = evidenceLines(ctx, q, c.Org, id); err != nil {
			return err
		}
		out.Requirements = e.Requirements
		if out.Eligibility, err = eligibility(ctx, q, c, l, out.State); err != nil {
			return err
		}
		if len(row.VariantKey) == 0 {
			return nil
		}
		vs, err := q.ApprovalVariants(ctx, c.Org, row.VariantKey)
		for _, v := range vs {
			if v.ID != id {
				out.Variants = append(out.Variants, Variant{Request: v.ID, State: v.State, CreatedAt: v.CreatedAt})
			}
		}
		return err
	}, db.ReadOnly())
	return out, err
}

func orNotFound(err error) error {
	if err != nil {
		return err
	}
	return ErrNotFound
}

func responseLines(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) ([]ResponseLine, error) {
	rows, err := q.RequestResponses(ctx, org, id)
	if err != nil {
		return nil, err
	}
	out := make([]ResponseLine, 0, len(rows))
	for _, r := range rows {
		l := ResponseLine{
			User: r.UserID, Kind: r.Kind, Requirement: -1, Reason: deref(r.ReasonCode), Alternative: deref(r.AlternativeCode),
			Note: apdomain.Clean("note", r.Note, apdomain.MaxNote), Proposed: string(r.ProposedParams), At: r.CreatedAt,
			Voided: deref(r.VoidReason), VoidedAt: r.VoidedAt, ID: r.ID, Credential: r.CredentialID, Batch: r.BatchID,
		}
		if r.Requirement.Valid {
			l.Requirement = int(r.Requirement.Int16)
		}
		out = append(out, l)
	}
	return out, nil
}

func evidenceLines(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) ([]EvidenceLine, error) {
	rows, err := q.RequestEvidence(ctx, org, id)
	if err != nil {
		return nil, err
	}
	out := make([]EvidenceLine, 0, len(rows))
	for _, r := range rows {
		author := "user:"
		switch {
		case r.AuthorUserID != nil:
			author += r.AuthorUserID.String()
		case r.AuthorInstanceID != nil:
			author = "instance:" + r.AuthorInstanceID.String()
		}
		out = append(out, EvidenceLine{ID: r.ID, Author: author, Note: apdomain.Clean("evidence", r.Note, apdomain.MaxUntrustedRunes), At: r.CreatedAt})
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
