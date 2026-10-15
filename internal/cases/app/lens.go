// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// Lens names (F237).
const (
	LensSequence  = "sequence"
	LensAuthority = "authority"
	LensEffects   = "effects"
	LensReach     = "reach"
	LensRelated   = "related"
	LensResponse  = "response"
)

// Lenses lists every lens.
var Lenses = []string{LensSequence, LensAuthority, LensEffects, LensReach, LensRelated, LensResponse}

// Bounds of a lens.
const (
	MaxLensItems    = 1000
	MaxLensRange    = 30 * 24 * time.Hour
	DefaultLensSpan = 7 * 24 * time.Hour
)

// NoteNotAvailable is a lens's note when its source is not connected.
const NoteNotAvailable = "NOT_AVAILABLE"

// Errors of the lenses.
var (
	ErrLens = pcerr.New(pcerr.InvalidArgument, "INVALID_LENS",
		"the lens is one of sequence, authority, effects, reach, related or response; the range ends after it starts and spans at most 30 days")
	ErrSelection = pcerr.New(pcerr.InvalidArgument, "INVALID_SELECTION", "the selection must be an agent, run or transaction the case links")
)

// ReachAgent is one agent's current reach (the exposure read port).
type ReachAgent struct {
	Agent ids.UUID
	Reach reflexdomain.Reach
	Stale bool
	Note  string
}

// ReachView reads current reach for the reach lens (exposure, D27).
type ReachView interface {
	AgentReach(ctx context.Context, org ids.OrgID, agents []ids.UUID) ([]ReachAgent, error)
}

// ResponseAction is one containment action for the response lens.
type ResponseAction struct {
	ID        ids.UUID
	Scope     reflexdomain.Subject
	Control   string
	Status    string
	Requested time.Time
	// Paths are the per-path confirmations (gateway, route, credential,
	// in-flight work) and their status.
	Paths []ResponsePath
}

// ResponsePath is one path of a containment action.
type ResponsePath struct {
	Kind   string
	Status string
}

// ResponseView reads the containment actions of a case: those naming the
// case and those on its subjects (response, D22, D49). Ops wires the
// response stream's implementation; nil: the lens says NOT_AVAILABLE.
type ResponseView interface {
	CaseActions(ctx context.Context, org ids.OrgID, caseID ids.UUID, subjects []reflexdomain.Subject) ([]ResponseAction, error)
}

// LensItem is one row of a lens.
type LensItem struct {
	At       time.Time
	Kind     string
	Subjects []reflexdomain.Subject
	Title    string
	Detail   string
	Basis    reflexdomain.Basis
}

// Lens is one view of a case with the shared selection and range.
type Lens struct {
	Name      string
	Selection *reflexdomain.Subject
	Start     time.Time
	End       time.Time
	Available bool
	Note      string
	Items     []LensItem
	Truncated bool
	// ScopeLimited: the caller's scope is narrower than the organization,
	// so rows outside it may exist and are not shown.
	ScopeLimited bool
}

// LensRequest asks for one lens.
type LensRequest struct {
	Case      ids.UUID
	Lens      string
	Selection *reflexdomain.Subject
	// Start and End bound the lens; zero: the DefaultLensSpan up to now.
	Start, End time.Time
}

// subjects of a case, by kind.
type links struct {
	agents, runs, txns []ids.UUID
	all                []domain.Ref
}

func caseLinks(ctx context.Context, q *dbq.Queries, org ids.OrgID, c ids.UUID) (links, error) {
	rows, err := q.CaseLinks(ctx, org, c)
	if err != nil {
		return links{}, err
	}
	l := links{agents: []ids.UUID{}, runs: []ids.UUID{}, txns: []ids.UUID{}}
	for _, r := range rows {
		if r.RefKind == nil || r.RefID == nil {
			continue
		}
		l.all = append(l.all, domain.Ref{Kind: *r.RefKind, ID: *r.RefID})
		id, err := ids.ParseUUID(*r.RefID)
		if err != nil {
			continue
		}
		if s := l.slot(reflexdomain.SubjectType(*r.RefKind)); s != nil {
			*s = append(*s, id)
		}
	}
	return l, nil
}

// slot is the list of ids of an agent, run or transaction subject; nil for
// other subjects.
func (l *links) slot(t reflexdomain.SubjectType) *[]ids.UUID {
	return map[reflexdomain.SubjectType]*[]ids.UUID{
		reflexdomain.SubjectAgent: &l.agents, reflexdomain.SubjectRun: &l.runs, reflexdomain.SubjectTransaction: &l.txns,
	}[t]
}

// narrow keeps only the selection, which must be a linked agent, run or
// transaction.
func (l links) narrow(sel *reflexdomain.Subject) (links, error) {
	if sel == nil {
		return l, nil
	}
	if !slices.Contains(l.all, domain.Ref{Kind: string(sel.Type), ID: sel.ID}) {
		return links{}, ErrSelection
	}
	id, err := ids.ParseUUID(sel.ID)
	if err != nil {
		return links{}, ErrSelection
	}
	out := links{agents: []ids.UUID{}, runs: []ids.UUID{}, txns: []ids.UUID{}, all: l.all}
	s := out.slot(sel.Type)
	if s == nil {
		return links{}, ErrSelection
	}
	*s = []ids.UUID{id}
	return out, nil
}

// GetLens returns one lens of a case (case.read). Rows of agents the
// caller may not read (evidence.read where the agent lives) are left out
// before anything is counted (HR-247).
func (s *Service) GetLens(ctx context.Context, r LensRequest) (Lens, error) {
	caller, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Lens{}, err
	}
	if err := cases(ctx, s.Editions); err != nil {
		return Lens{}, err
	}
	if !slices.Contains(Lenses, r.Lens) {
		return Lens{}, ErrLens
	}
	if r.Start.IsZero() && r.End.IsZero() {
		r.End = time.Now()
		r.Start = r.End.Add(-DefaultLensSpan)
	}
	if !r.End.After(r.Start) || r.End.Sub(r.Start) > MaxLensRange {
		return Lens{}, ErrLens
	}
	out := Lens{
		Name: r.Lens, Selection: r.Selection, Start: r.Start, End: r.End, Available: true,
		ScopeLimited: !caller.Can(td.PermEvidenceRead, td.OrgPath(caller.Org)),
	}
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sc := scope{c: caller, q: q}
		if _, _, err := sc.readable(ctx, tx, r.Case); err != nil {
			return err
		}
		all, err := caseLinks(ctx, q, caller.Org, r.Case)
		if err != nil {
			return err
		}
		l, err := all.narrow(r.Selection)
		if err != nil {
			return err
		}
		ev := tapp.NewAgentScope(caller, q, td.PermEvidenceRead)
		switch r.Lens {
		case LensSequence, LensEffects:
			return s.actionLens(ctx, q, caller.Org, ev, l, r, &out)
		case LensAuthority:
			return authorityLens(ctx, q, caller.Org, ev, l, r, &out)
		case LensRelated:
			return relatedLens(ctx, q, sc, r.Case, all, &out)
		case LensReach:
			return s.reachLens(ctx, q, caller.Org, ev, l, &out)
		case LensResponse:
			return s.responseLens(ctx, q, caller.Org, ev, r.Case, l, &out)
		}
		return ErrLens
	}, db.ReadOnly())
	return out, err
}

func (s *Service) actionLens(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *tapp.AgentScope, l links,
	r LensRequest, out *Lens,
) error {
	rows, err := q.CaseLensTransactions(ctx, dbq.CaseLensTransactionsParams{
		OrgID: org, TransactionIds: l.txns, RunIds: l.runs, AgentIds: l.agents, StartTime: r.Start, EndTime: r.End,
		EffectsOnly: r.Lens == LensEffects, MaxRows: MaxLensItems + 1,
	})
	if err != nil {
		return err
	}
	if len(rows) > MaxLensItems {
		rows, out.Truncated = rows[:MaxLensItems], true
	}
	for _, t := range rows {
		ok, err := ev.Can(ctx, t.AgentID)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		it := LensItem{
			At: t.CreatedAt, Kind: "ACTION", Title: t.Operation, Detail: t.Decision, Basis: reflexdomain.BasisObserved,
			Subjects: []reflexdomain.Subject{
				{Type: reflexdomain.SubjectTransaction, ID: t.ID.String()},
				{Type: reflexdomain.SubjectRun, ID: t.RunID.String()},
				{Type: reflexdomain.SubjectAgent, ID: t.AgentID.String()},
			},
		}
		if r.Lens == LensEffects {
			it.Kind = "EFFECT"
			switch {
			case t.EffectState != nil:
				it.Detail = *t.EffectState
			case t.Outcome != nil:
				it.Detail = "OUTCOME_" + *t.Outcome
			}
		}
		out.Items = append(out.Items, it)
	}
	return nil
}

func authorityLens(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *tapp.AgentScope, l links, r LensRequest, out *Lens) error {
	agents := slices.Clone(l.agents)
	for _, run := range l.runs {
		x, err := q.InvRun(ctx, org, run)
		if db.IsNoRows(err) {
			continue
		} else if err != nil {
			return err
		}
		agents = append(agents, x.AgentID)
	}
	for _, t := range l.txns {
		x, err := q.InvTransaction(ctx, org, t)
		if db.IsNoRows(err) {
			continue
		} else if err != nil {
			return err
		}
		agents = append(agents, x.AgentID)
	}
	slices.SortFunc(agents, compareIDs)
	agents = slices.Compact(agents)
	for _, a := range agents {
		ok, err := ev.Can(ctx, a)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		rows, err := q.InvGrantChanges(ctx, dbq.InvGrantChangesParams{OrgID: org, AgentID: a, StartTime: r.Start, EndTime: r.End})
		if err != nil {
			return err
		}
		for _, c := range rows {
			detail := c.Change
			if c.Change == "REVISED" && c.Widens {
				detail = "REVISED_WIDER"
			}
			out.Items = append(out.Items, LensItem{
				At: c.At, Kind: "AUTHORITY", Title: "grant " + detail, Detail: detail,
				Basis: reflexdomain.BasisObserved, Subjects: []reflexdomain.Subject{
					{Type: reflexdomain.SubjectGrant, ID: c.GrantID.String()},
					{Type: reflexdomain.SubjectAgent, ID: a.String()},
				},
			})
		}
	}
	slices.SortStableFunc(out.Items, func(a, b LensItem) int { return a.At.Compare(b.At) })
	if len(out.Items) > MaxLensItems {
		out.Items, out.Truncated = out.Items[:MaxLensItems], true
	}
	return nil
}

func compareIDs(a, b ids.UUID) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// relatedLens lists the other cases, readable by the caller, that link one
// of this case's subjects.
func relatedLens(ctx context.Context, q *dbq.Queries, sc scope, c ids.UUID, l links, out *Lens) error {
	seen := map[ids.UUID]bool{c: true}
	for _, ref := range l.all {
		rows, err := q.CasesLinking(ctx, dbq.CasesLinkingParams{OrgID: sc.c.Org, RefKind: &ref.Kind, RefID: &ref.ID, MaxRows: 100})
		if err != nil {
			return err
		}
		for _, k := range rows {
			if seen[k.ID] {
				continue
			}
			seen[k.ID] = true
			agents, err := sc.caseAgents(ctx, k.ID)
			if err != nil {
				return err
			}
			ok, err := sc.over(ctx, td.PermCaseRead, agents)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			out.Items = append(out.Items, LensItem{
				At: k.UpdatedAt, Kind: "CASE", Title: k.Title, Detail: k.State,
				Basis: reflexdomain.BasisObserved, Subjects: []reflexdomain.Subject{
					{Type: reflexdomain.SubjectCase, ID: k.ID.String()},
					{Type: reflexdomain.SubjectType(ref.Kind), ID: ref.ID},
				},
			})
			if len(out.Items) >= MaxLensItems {
				out.Truncated = true
				return nil
			}
		}
	}
	return nil
}

// visibleAgents returns the case's agents the caller may read evidence of.
func visibleAgents(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *tapp.AgentScope, l links) ([]ids.UUID, error) {
	all, err := q.AgentsOfSubjects(ctx, dbq.AgentsOfSubjectsParams{OrgID: org, AgentIds: l.agents, RunIds: l.runs, TransactionIds: l.txns})
	if err != nil {
		return nil, err
	}
	out := []ids.UUID{}
	for _, a := range all {
		ok, err := ev.Can(ctx, a)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *Service) reachLens(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *tapp.AgentScope, l links, out *Lens) error {
	if s.Reach == nil {
		out.Available, out.Note = false, NoteNotAvailable
		return nil
	}
	agents, err := visibleAgents(ctx, q, org, ev, l)
	if err != nil {
		return err
	}
	rows, err := s.Reach.AgentReach(ctx, org, agents)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if !slices.Contains(agents, r.Agent) {
			continue
		}
		detail := fmt.Sprintf("resources=%d usable=%d conditional=%d uncertain=%d", r.Reach.Resources, r.Reach.Usable,
			r.Reach.Conditional, r.Reach.Uncertain)
		if r.Stale {
			detail += " stale"
		}
		if r.Note != "" {
			detail += " " + r.Note
		}
		out.Items = append(out.Items, LensItem{
			Kind: "REACH", Title: "reach", Detail: detail, Basis: reflexdomain.BasisInferred,
			Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: r.Agent.String()}},
		})
	}
	return nil
}

func (s *Service) responseLens(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *tapp.AgentScope, c ids.UUID, l links,
	out *Lens,
) error {
	if s.Response == nil {
		out.Available, out.Note = false, NoteNotAvailable
		return nil
	}
	agents, err := visibleAgents(ctx, q, org, ev, l)
	if err != nil {
		return err
	}
	// The view gets only subjects the caller may read: visible agents and
	// the case's runs and transactions of visible agents.
	subjects := make([]reflexdomain.Subject, 0, len(agents)+len(l.runs)+len(l.txns))
	for _, a := range agents {
		subjects = append(subjects, reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: a.String()})
	}
	for _, run := range l.runs {
		x, err := q.InvRun(ctx, org, run)
		if db.IsNoRows(err) {
			continue
		} else if err != nil {
			return err
		}
		if slices.Contains(agents, x.AgentID) {
			subjects = append(subjects, reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: run.String()})
		}
	}
	for _, t := range l.txns {
		x, err := q.InvTransaction(ctx, org, t)
		if db.IsNoRows(err) {
			continue
		} else if err != nil {
			return err
		}
		if slices.Contains(agents, x.AgentID) {
			subjects = append(subjects, reflexdomain.Subject{Type: reflexdomain.SubjectTransaction, ID: t.String()})
		}
	}
	rows, err := s.Response.CaseActions(ctx, org, c, subjects)
	if err != nil {
		return err
	}
	for _, a := range rows {
		detail := a.Status
		if open := countOpen(a.Paths); open > 0 {
			detail = fmt.Sprintf("%s (%d of %d paths unresolved)", a.Status, open, len(a.Paths))
		}
		out.Items = append(out.Items, LensItem{
			At: a.Requested, Kind: "CONTAINMENT", Title: a.Control, Detail: detail,
			Basis: reflexdomain.BasisObserved, Subjects: []reflexdomain.Subject{
				{Type: reflexdomain.SubjectType(domain.RefResponseAction), ID: a.ID.String()}, a.Scope,
			},
		})
	}
	return nil
}

// countOpen counts the paths not confirmed.
func countOpen(ps []ResponsePath) int {
	n := 0
	for _, p := range ps {
		if p.Status != "CONFIRMED" {
			n++
		}
	}
	return n
}
