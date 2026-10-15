// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"slices"
	"time"

	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/posture/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// API errors of the service.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"the posture remediation queue needs the Business edition or above")
	ErrFindingNotFound = pcerr.New(pcerr.NotFound, "POSTURE_FINDING_NOT_FOUND", "posture finding not found")
	ErrMove            = pcerr.New(pcerr.FailedPrecondition, "POSTURE_TRANSITION_INVALID",
		"the finding cannot move to that state from where it is; only a recomputation remediates")
	ErrAccept = pcerr.New(pcerr.InvalidArgument, "POSTURE_ACCEPTANCE_INVALID",
		"an acceptance needs a reason of 10-1000 characters and an expiry within 90 days")
	ErrNoteInvalid = pcerr.New(pcerr.InvalidArgument, "POSTURE_NOTE_INVALID", "a note is 1-1000 characters")
	ErrOwner       = pcerr.New(pcerr.InvalidArgument, "POSTURE_OWNER_INVALID", "the owner is not a user of this org")
)

// Service serves the posture queue under posture.read and posture.manage
// where each finding's agent lives (org scope for a finding with none),
// on editions with PostureRemediation.
type Service struct {
	Pool *db.Pool
	Ents exapp.Entitlements
}

// Finding is a finding with its history.
type Finding struct {
	Finding dbq.PcPostureFinding
	Events  []dbq.PcPostureFindingEvent
}

func (s *Service) entitled(ctx context.Context) error {
	if s.Ents == nil {
		return ErrEdition
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.PostureRemediation() {
		return ErrEdition
	}
	return nil
}

type session struct {
	c     tenancy.Caller
	tx    db.TenantTx
	q     *dbq.Queries
	scope *tapp.AgentScope
	perm  td.Permission
}

// can reports whether the caller holds the session's permission over f.
func (s *session) can(ctx context.Context, f dbq.PcPostureFinding) (bool, error) {
	if f.AgentID == nil {
		return s.c.Can(s.perm, td.OrgPath(s.c.Org)), nil
	}
	ok, err := s.scope.Can(ctx, *f.AgentID)
	if db.IsNoRows(err) {
		return false, nil
	}
	return ok, err
}

func (s *Service) run(ctx context.Context, perm td.Permission, ro bool, fn func(context.Context, *session) error) error {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if !c.CanAnywhere(perm) {
		return td.ErrPermissionDenied(perm)
	}
	if err := s.entitled(ctx); err != nil {
		return err
	}
	var opts []db.TxOption
	if ro {
		opts = append(opts, db.ReadOnly())
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		return fn(ctx, &session{c: c, tx: tx, q: q, scope: tapp.NewAgentScope(c, q, perm), perm: perm})
	}, opts...)
}

// List lists the findings the caller may read, newest first. A page holds
// fewer than its size when some are not readable.
func (s *Service) List(ctx context.Context, states []domain.State, kind, root string, size int32, token string,
) ([]dbq.PcPostureFinding, string, bool, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", false, err
	}
	var out []dbq.PcPostureFinding
	var next string
	restricted := false
	err = s.run(ctx, td.PermPostureRead, true, func(ctx context.Context, x *session) error {
		restricted = !x.c.Can(td.PermPostureRead, td.OrgPath(x.c.Org))
		st := make([]string, 0, len(states))
		for _, v := range states {
			st = append(st, string(v))
		}
		params := dbq.ListPostureFindingsParams{OrgID: x.c.Org, States: st, MaxRows: p.Limit()}
		if kind != "" {
			params.Kind = &kind
		}
		if root != "" {
			params.RootCause = &root
		}
		if !p.After.IsZero() {
			params.Before = &p.After
		}
		rows, err := x.q.ListPostureFindings(ctx, params)
		if err != nil {
			return err
		}
		rows, next = page.Finish(p, rows, func(f dbq.PcPostureFinding) ids.UUID { return f.ID })
		for _, f := range rows {
			ok, err := x.can(ctx, f)
			if err != nil {
				return err
			}
			if ok {
				out = append(out, f)
			}
		}
		return nil
	})
	return out, next, restricted, err
}

// RootCause is the active findings of one root cause.
type RootCause struct {
	RootCause   string
	Findings    int
	MaxSeverity string
	Kinds       []string
}

var severities = []string{"low", "medium", "high", "critical"}

// RootCauses groups the active findings the caller may read by root cause,
// counting only what the caller may read (D8).
func (s *Service) RootCauses(ctx context.Context) ([]RootCause, bool, error) {
	var out []RootCause
	restricted := false
	err := s.run(ctx, td.PermPostureRead, true, func(ctx context.Context, x *session) error {
		restricted = !x.c.Can(td.PermPostureRead, td.OrgPath(x.c.Org))
		by := map[string]*RootCause{}
		var before *ids.UUID
		for {
			rows, err := x.q.ListPostureFindings(ctx, dbq.ListPostureFindingsParams{
				OrgID: x.c.Org, States: []string{"OPEN", "ASSIGNED", "TESTING", "EVIDENCE_INCOMPLETE"}, Before: before, MaxRows: 1000,
			})
			if err != nil {
				return err
			}
			for _, f := range rows {
				ok, err := x.can(ctx, f)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
				g, seen := by[f.RootCause]
				if !seen {
					g = &RootCause{RootCause: f.RootCause, MaxSeverity: f.Severity}
					by[f.RootCause] = g
				}
				g.Findings++
				if slices.Index(severities, f.Severity) > slices.Index(severities, g.MaxSeverity) {
					g.MaxSeverity = f.Severity
				}
				if !slices.Contains(g.Kinds, f.Kind) {
					g.Kinds = append(g.Kinds, f.Kind)
					slices.Sort(g.Kinds)
				}
			}
			if len(rows) < 1000 {
				break
			}
			last := rows[len(rows)-1].ID
			before = &last
		}
		for _, g := range by {
			out = append(out, *g)
		}
		slices.SortFunc(out, func(a, b RootCause) int {
			if d := slices.Index(severities, b.MaxSeverity) - slices.Index(severities, a.MaxSeverity); d != 0 {
				return d
			}
			if d := b.Findings - a.Findings; d != 0 {
				return d
			}
			if a.RootCause < b.RootCause {
				return -1
			}
			return 1
		})
		return nil
	})
	return out, restricted, err
}

func (x *session) finding(ctx context.Context, id ids.UUID) (dbq.PcPostureFinding, error) {
	f, err := Get(ctx, x.tx, id)
	if errors.Is(err, ErrNotFound) {
		return f, ErrFindingNotFound
	} else if err != nil {
		return f, err
	}
	// A finding the caller may not read is not found (never disclosed).
	if ok, err := x.can(ctx, f); err != nil {
		return f, err
	} else if !ok {
		return f, ErrFindingNotFound
	}
	return f, nil
}

// Get returns a finding the caller may read, with its history.
func (s *Service) Get(ctx context.Context, id ids.UUID) (Finding, error) {
	var out Finding
	err := s.run(ctx, td.PermPostureRead, true, func(ctx context.Context, x *session) error {
		f, err := x.finding(ctx, id)
		if err != nil {
			return err
		}
		out.Finding = f
		out.Events, err = x.q.ListPostureFindingEvents(ctx, x.c.Org, id)
		return err
	})
	return out, err
}

// manage runs a lifecycle move under posture.manage over the finding and
// returns the finding after it.
func (s *Service) manage(ctx context.Context, id ids.UUID, fn func(ctx context.Context, x *session) error) (dbq.PcPostureFinding, error) {
	var out dbq.PcPostureFinding
	err := s.run(ctx, td.PermPostureManage, false, func(ctx context.Context, x *session) error {
		if _, err := x.finding(ctx, id); err != nil {
			return err
		}
		if err := fn(ctx, x); err != nil {
			return mapErr(err)
		}
		var err error
		out, err = Get(ctx, x.tx, id)
		return err
	})
	return out, err
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrTransition), db.IsCheckViolation(err):
		return ErrMove
	case errors.Is(err, ErrAcceptance):
		return ErrAccept
	case db.IsForeignKeyViolation(err):
		return ErrOwner
	}
	return err
}

// Assign gives an active finding an owner.
func (s *Service) Assign(ctx context.Context, id, owner ids.UUID) (dbq.PcPostureFinding, error) {
	return s.manage(ctx, id, func(ctx context.Context, x *session) error {
		return Assign(ctx, x.tx, id, owner, x.c.Actor())
	})
}

// StartTesting marks an assigned finding's fix under test.
func (s *Service) StartTesting(ctx context.Context, id ids.UUID, note string) (dbq.PcPostureFinding, error) {
	return s.manage(ctx, id, func(ctx context.Context, x *session) error {
		return StartTesting(ctx, x.tx, id, x.c.Actor(), note)
	})
}

// Accept accepts an active finding for a while.
func (s *Service) Accept(ctx context.Context, id ids.UUID, until time.Time, reason string) (dbq.PcPostureFinding, error) {
	return s.manage(ctx, id, func(ctx context.Context, x *session) error {
		return Accept(ctx, x.tx, id, until, reason, x.c.Actor())
	})
}

// MarkIncomplete marks an active finding evidence-incomplete.
func (s *Service) MarkIncomplete(ctx context.Context, id ids.UUID, note string) (dbq.PcPostureFinding, error) {
	return s.manage(ctx, id, func(ctx context.Context, x *session) error {
		return MarkEvidenceIncomplete(ctx, x.tx, id, note, x.c.Actor())
	})
}

// Reopen puts a finding back in the queue.
func (s *Service) Reopen(ctx context.Context, id ids.UUID, note string) (dbq.PcPostureFinding, error) {
	return s.manage(ctx, id, func(ctx context.Context, x *session) error {
		return Reopen(ctx, x.tx, id, note, x.c.Actor())
	})
}

// AddNote adds a note to a finding's history.
func (s *Service) AddNote(ctx context.Context, id ids.UUID, note string) (dbq.PcPostureFinding, error) {
	return s.manage(ctx, id, func(ctx context.Context, x *session) error {
		if err := Note(ctx, x.tx, id, note, x.c.Actor()); err != nil && !errors.Is(err, ErrTransition) {
			if errors.Is(err, errNote) {
				return ErrNoteInvalid
			}
			return err
		}
		return nil
	})
}
