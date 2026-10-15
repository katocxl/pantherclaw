// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the case use cases (G0 M10 D19; F237, F244, F248,
// F249, F251, F571, F299): opening a case, adding entries, reading a case
// and its lenses, and exporting it for handoff. Cases need the Team
// edition (D5).
//
// A case is read with case.read and changed with case.manage (a person
// only, D4) where it lives: the whole organization, or every agent it is
// about (linked agents and the agents of linked runs and transactions). A
// case the caller may not read looks like a case that does not exist, and
// lists leave it out before they count (HR-247, D8).
package app

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// Bounds of a manual case.
const (
	MaxSubjects  = 32
	MaxQuestions = 16
)

// Errors of the case use cases.
var (
	ErrEdition    = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "cases need the Team edition or above")
	ErrHumanOnly  = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can change a case")
	ErrForbidden  = pcerr.New(pcerr.PermissionDenied, "PERMISSION_DENIED", "the caller may not change this case")
	ErrBadSubject = pcerr.New(pcerr.InvalidArgument, "INVALID_CASE_SUBJECT",
		"subjects are agents, runs, transactions or other known subjects with an id, at most 32")
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service serves the case use cases as pc_app.
type Service struct {
	Pool     *db.Pool
	Editions Editions
	// Reach and Response feed the reach and response lenses; nil: those
	// lenses say they are not available.
	Reach    ReachView
	Response ResponseView
}

// cases fails closed: without entitlements, or below Team, no cases.
func cases(ctx context.Context, e Editions) error {
	if e == nil {
		return ErrEdition
	}
	ents, err := e.Current(ctx)
	if err != nil {
		return err
	}
	if !ents.Cases() {
		return ErrEdition
	}
	return nil
}

// scope answers whether a caller holds a permission over a case.
type scope struct {
	c tenancy.Caller
	q *dbq.Queries
}

// over reports whether the caller holds perm over every agent in agents,
// or over the organization. A case about no agent needs the organization.
func (s scope) over(ctx context.Context, perm td.Permission, agents []ids.UUID) (bool, error) {
	if s.c.Can(perm, td.OrgPath(s.c.Org)) {
		return true, nil
	}
	if len(agents) == 0 {
		return false, nil
	}
	as := tapp.NewAgentScope(s.c, s.q, perm)
	for _, a := range agents {
		ok, err := as.Can(ctx, a)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// caseAgents returns the agents case c is about.
func (s scope) caseAgents(ctx context.Context, c ids.UUID) ([]ids.UUID, error) {
	return s.q.CaseAgents(ctx, s.c.Org, c)
}

// readable loads case c for the caller, or NotFound when the caller may
// not read it.
func (s scope) readable(ctx context.Context, tx db.TenantTx, c ids.UUID) (domain.Case, []ids.UUID, error) {
	k, err := store.Get(ctx, tx, c)
	if err != nil {
		return domain.Case{}, nil, err
	}
	agents, err := s.caseAgents(ctx, c)
	if err != nil {
		return domain.Case{}, nil, err
	}
	ok, err := s.over(ctx, td.PermCaseRead, agents)
	if err != nil {
		return domain.Case{}, nil, err
	}
	if !ok {
		return domain.Case{}, nil, store.ErrNotFound
	}
	return k, agents, nil
}

// manageable loads case c for a change by the caller.
func (s scope) manageable(ctx context.Context, tx db.TenantTx, c ids.UUID) (domain.Case, error) {
	k, agents, err := s.readable(ctx, tx, c)
	if err != nil {
		return domain.Case{}, err
	}
	if !s.c.Human() {
		return domain.Case{}, ErrHumanOnly
	}
	ok, err := s.over(ctx, td.PermCaseManage, agents)
	if err != nil {
		return domain.Case{}, err
	}
	if !ok {
		return domain.Case{}, ErrForbidden
	}
	return k, nil
}

func author(c tenancy.Caller) domain.Author {
	a := c.Actor()
	return domain.Author{Type: a.Type, ID: a.ID}
}

// OpenRequest is a case a person opens by hand.
type OpenRequest struct {
	Title     string
	Subjects  []reflexdomain.Subject
	Questions []string
	Alert     *ids.UUID
	Incident  *ids.UUID
}

// Open opens a case about the subjects, as a person holding case.manage
// over them, with the questions as open QUESTION entries.
func (s *Service) Open(ctx context.Context, r OpenRequest) (domain.Case, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return domain.Case{}, err
	}
	if err := cases(ctx, s.Editions); err != nil {
		return domain.Case{}, err
	}
	if !c.Human() {
		return domain.Case{}, ErrHumanOnly
	}
	if err := checkSeed(r.Subjects, r.Questions); err != nil {
		return domain.Case{}, err
	}
	var out domain.Case
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		sc := scope{c: c, q: dbq.New(tx)}
		agents, err := subjectAgents(ctx, sc.q, c.Org, r.Subjects)
		if err != nil {
			return err
		}
		ok, err := sc.over(ctx, td.PermCaseManage, agents)
		if err != nil {
			return err
		}
		if !ok {
			return ErrForbidden
		}
		out, err = seed(ctx, tx, seedOf{
			title: r.Title, source: "manual", opener: author(c), subjects: r.Subjects, questions: r.Questions, questionOwner: &c.Principal.ID,
			alert: r.Alert, incident: r.Incident,
		})
		return err
	})
	return out, err
}

// checkSeed bounds the subjects and questions a case opens with.
func checkSeed(subjects []reflexdomain.Subject, questions []string) error {
	if len(subjects) > MaxSubjects || len(questions) > MaxQuestions {
		return ErrBadSubject
	}
	for _, sub := range subjects {
		if !sub.Valid() {
			return ErrBadSubject
		}
	}
	for _, q := range questions {
		if strings.TrimSpace(q) == "" || utf8.RuneCountInString(q) > domain.MaxText {
			return store.ErrInvalid
		}
	}
	return nil
}

// subjectAgents returns the agents of the agent, run and transaction
// subjects; other subjects name no agent.
func subjectAgents(ctx context.Context, q *dbq.Queries, org ids.OrgID, subjects []reflexdomain.Subject) ([]ids.UUID, error) {
	p := dbq.AgentsOfSubjectsParams{OrgID: org, AgentIds: []ids.UUID{}, RunIds: []ids.UUID{}, TransactionIds: []ids.UUID{}}
	slot := map[reflexdomain.SubjectType]*[]ids.UUID{
		reflexdomain.SubjectAgent: &p.AgentIds, reflexdomain.SubjectRun: &p.RunIds, reflexdomain.SubjectTransaction: &p.TransactionIds,
	}
	for _, sub := range subjects {
		s, ok := slot[sub.Type]
		if !ok {
			continue
		}
		id, err := ids.ParseUUID(sub.ID)
		if err != nil {
			return nil, ErrBadSubject
		}
		*s = append(*s, id)
	}
	return q.AgentsOfSubjects(ctx, p)
}

// seedOf is what a new case starts from.
type seedOf struct {
	title, source string
	opener        domain.Author
	subjects      []reflexdomain.Subject
	evidence      []reflexdomain.EvidenceRef
	questions     []string
	// questionOwner owns the seeded questions: the person who opens a case;
	// nil for the product's seeds, which a person takes on later.
	questionOwner   *ids.UUID
	alert, incident *ids.UUID
}

// seed opens the case and appends a LINK entry per subject, evidence ref,
// alert and incident, then a QUESTION entry per question.
func seed(ctx context.Context, tx db.TenantTx, s seedOf) (domain.Case, error) {
	k, err := store.Open(ctx, tx, domain.NewCase{
		Title: s.title, Source: s.source, OpenedBy: s.opener, Alert: s.alert, Incident: s.incident,
	})
	if err != nil {
		return domain.Case{}, err
	}
	var links []domain.Ref
	for _, sub := range s.subjects {
		links = append(links, domain.Ref{Kind: string(sub.Type), ID: sub.ID})
	}
	for _, e := range s.evidence {
		switch e.Kind {
		case reflexdomain.EvidenceTransaction, reflexdomain.EvidenceRun:
			links = append(links, domain.Ref{Kind: e.Kind, ID: e.ID.String()})
		case reflexdomain.EvidenceLedger, reflexdomain.EvidenceReceipt:
			links = append(links, domain.Ref{Kind: "ledger", ID: e.ID.String()})
		default:
		}
	}
	if s.alert != nil {
		links = append(links, domain.Ref{Kind: string(reflexdomain.SubjectAlert), ID: s.alert.String()})
	}
	if s.incident != nil {
		links = append(links, domain.Ref{Kind: string(reflexdomain.SubjectIncident), ID: s.incident.String()})
	}
	seen := map[domain.Ref]bool{}
	for _, l := range links {
		if seen[l] {
			continue
		}
		seen[l] = true
		if _, err := store.Append(ctx, tx, k.ID, s.opener, domain.Draft{Kind: domain.KindLink, Ref: &l}); err != nil {
			return domain.Case{}, err
		}
	}
	for _, q := range s.questions {
		if _, err := store.Append(ctx, tx, k.ID, s.opener, domain.Draft{Kind: domain.KindQuestion, Text: q, Owner: s.questionOwner}); err != nil {
			return domain.Case{}, err
		}
	}
	return store.Get(ctx, tx, k.ID)
}

// Append adds an entry to case c as the calling person (case.manage).
func (s *Service) Append(ctx context.Context, c ids.UUID, d domain.Draft) (domain.Entry, error) {
	caller, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return domain.Entry{}, err
	}
	if err := cases(ctx, s.Editions); err != nil {
		return domain.Entry{}, err
	}
	var out domain.Entry
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		sc := scope{c: caller, q: dbq.New(tx)}
		if _, err := sc.manageable(ctx, tx, c); err != nil {
			return err
		}
		// The subjects an entry names must stay inside what the person may
		// manage: a link, or the runs and transactions a fact or impact cites
		// (D62).
		subjects := []reflexdomain.Subject{}
		if d.Kind == domain.KindLink && d.Ref != nil {
			subjects = append(subjects, reflexdomain.Subject{Type: reflexdomain.SubjectType(d.Ref.Kind), ID: d.Ref.ID})
		}
		for _, e := range d.Evidence {
			if e.Kind == domain.EvidenceRun || e.Kind == domain.EvidenceTransaction {
				subjects = append(subjects, reflexdomain.Subject{Type: reflexdomain.SubjectType(e.Kind), ID: e.ID.String()})
			}
		}
		if len(subjects) > 0 {
			agents, err := subjectAgents(ctx, sc.q, caller.Org, subjects)
			if err != nil {
				return err
			}
			ok, err := sc.over(ctx, td.PermCaseManage, agents)
			if err != nil {
				return err
			}
			if !ok {
				return ErrForbidden
			}
		}
		out, err = store.Append(ctx, tx, c, author(caller), d)
		return err
	})
	return out, err
}

// View is a case with its entries.
type View struct {
	Case          domain.Case
	Entries       []domain.Entry
	Superseded    map[ids.UUID]bool
	OpenQuestions int64
	// More: the case has entries after the last one returned.
	More bool
}

// Get returns case c and up to limit entries after seq (case.read).
func (s *Service) Get(ctx context.Context, c ids.UUID, after int64, limit int) (View, error) {
	caller, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return View{}, err
	}
	if err := cases(ctx, s.Editions); err != nil {
		return View{}, err
	}
	if limit < 1 || limit > store.MaxEntriesPage {
		limit = store.MaxEntriesPage
	}
	var v View
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		sc := scope{c: caller, q: dbq.New(tx)}
		k, _, err := sc.readable(ctx, tx, c)
		if err != nil {
			return err
		}
		v.Case = k
		if v.Entries, err = store.Entries(ctx, tx, c, after, limit+1); err != nil {
			return err
		}
		if len(v.Entries) > limit {
			v.Entries, v.More = v.Entries[:limit], true
		}
		if v.Superseded, err = store.Superseded(ctx, tx, c); err != nil {
			return err
		}
		v.OpenQuestions, err = store.OpenQuestions(ctx, tx, c)
		return err
	}, db.ReadOnly())
	return v, err
}

// Filter narrows List; empty fields match every case.
type Filter struct {
	States   []domain.State
	Owner    *ids.UUID
	Alert    *ids.UUID
	Incident *ids.UUID
}

// Page is a page of cases.
type Page struct {
	Items []domain.Case
	Next  string
}

// cursor is the keyset of List: the last case's update time and id.
type cursor struct {
	updated time.Time
	id      ids.UUID
}

// List lists the cases the caller may read, most recently updated first.
// A page holds fewer than its size when some are not readable; hidden
// cases are never counted.
func (s *Service) List(ctx context.Context, size int32, token string, f Filter) (Page, error) {
	caller, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Page{}, err
	}
	if err := cases(ctx, s.Editions); err != nil {
		return Page{}, err
	}
	pr, err := page.Parse(size, "")
	if err != nil {
		return Page{}, err
	}
	cur, err := parseCursor(token)
	if err != nil {
		return Page{}, err
	}
	states := make([]string, 0, len(f.States))
	for _, st := range f.States {
		states = append(states, string(st))
	}
	var out Page
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		p := dbq.ListCasesParams{
			OrgID: caller.Org, States: states, OwnerID: f.Owner, AlertID: f.Alert,
			IncidentID: f.Incident, PageLimit: pr.Limit(),
		}
		if cur != nil {
			p.BeforeUpdated, p.BeforeID = &cur.updated, &cur.id
		}
		rows, err := q.ListCases(ctx, p)
		if err != nil {
			return err
		}
		more := len(rows) == int(pr.Limit())
		if more {
			rows = rows[:len(rows)-1]
		}
		sc := scope{c: caller, q: q}
		for _, r := range rows {
			agents, err := sc.caseAgents(ctx, r.ID)
			if err != nil {
				return err
			}
			ok, err := sc.over(ctx, td.PermCaseRead, agents)
			if err != nil {
				return err
			}
			if ok {
				out.Items = append(out.Items, store.FromRow(r))
			}
		}
		if more && len(rows) > 0 {
			last := rows[len(rows)-1]
			out.Next = formatCursor(cursor{updated: last.UpdatedAt, id: last.ID})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

var errBadCursor = pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE_TOKEN", "invalid page token")

func formatCursor(c cursor) string {
	return c.updated.UTC().Format(time.RFC3339Nano) + "_" + c.id.String()
}

func parseCursor(s string) (*cursor, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // first page
	}
	at, id, ok := strings.Cut(s, "_")
	if !ok || len(s) > 128 {
		return nil, errBadCursor
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return nil, errBadCursor
	}
	u, err := ids.ParseUUID(id)
	if err != nil {
		return nil, errBadCursor
	}
	return &cursor{updated: t, id: u}, nil
}
