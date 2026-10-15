// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// API errors of the reads.
var (
	ErrNotComputed = pcerr.New(pcerr.FailedPrecondition, "EXPOSURE_NOT_COMPUTED",
		"breach radius has not been computed for this org yet")
	ErrScope = pcerr.New(pcerr.InvalidArgument, "GRAPH_SCOPE_INVALID",
		"the graph scope names nothing this mode can start from")
	ErrNotFound = pcerr.New(pcerr.NotFound, "EXPOSURE_SUBJECT_NOT_FOUND", "not found")
)

// Window is the default graph window when the filter names none.
const Window = 7 * 24 * time.Hour

// maxActivity bounds the transactions one graph reads.
const maxActivity = 5000

// Service serves breach radius and graph reads under the caller's
// exposure.read (D8): every right is filtered by where its agent lives
// before anything is listed, counted or ranked.
type Service struct {
	Pool *db.Pool
	Ents Entitlements
}

// scopeViewer is the caller's Viewer through the agent scope.
type scopeViewer struct {
	scope *tapp.AgentScope
	org   bool
}

func (v scopeViewer) Agent(ctx context.Context, a ids.UUID) (bool, error) {
	ok, err := v.scope.Can(ctx, a)
	if db.IsNoRows(err) {
		return false, nil
	}
	return ok, err
}

func (v scopeViewer) Org() bool { return v.org }

// visible decides graph nodes: agents by scope, credential holders at org
// scope, everything else by the edges' owners.
func (v scopeViewer) visible(ctx context.Context) (domain.Visible, *error) {
	var failed error
	return func(n domain.Node) bool {
		switch n.Type {
		case "agent":
			id, err := ids.ParseUUID(n.ID)
			if err != nil {
				return false
			}
			ok, err := v.Agent(ctx, id)
			if err != nil {
				failed = err
			}
			return ok
		case domain.CredentialHolder:
			return v.org
		}
		return true
	}, &failed
}

type reader struct {
	c    tenancy.Caller
	tx   db.TenantTx
	q    *dbq.Queries
	view scopeViewer
}

func (s *Service) read(ctx context.Context, fn func(context.Context, *reader) error) error {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if !c.CanAnywhere(td.PermExposureRead) {
		return td.ErrPermissionDenied(td.PermExposureRead)
	}
	if err := Entitled(ctx, s.Ents); err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		return fn(ctx, &reader{c: c, tx: tx, q: q, view: scopeViewer{
			scope: tapp.NewAgentScope(c, q, td.PermExposureRead), org: c.Can(td.PermExposureRead, td.OrgPath(c.Org)),
		}})
	}, db.ReadOnly())
}

func (r *reader) current(ctx context.Context, f domain.Filter) (View, error) {
	v, err := Current(ctx, r.tx, r.view, f)
	if errors.Is(err, ErrNoSnapshot) {
		return v, ErrNotComputed
	}
	return v, err
}

func (r *reader) requireOrg() error {
	return r.c.Require(td.PermExposureRead, td.OrgPath(r.c.Org))
}

// Exposure lists the current rights the caller may see.
func (s *Service) Exposure(ctx context.Context, f domain.Filter) (View, error) {
	var out View
	err := s.read(ctx, func(ctx context.Context, r *reader) error {
		var err error
		out, err = r.current(ctx, f)
		return err
	})
	return out, err
}

// Matrix is the visible rights folded into a matrix (F256).
func (s *Service) Matrix(ctx context.Context, f domain.Filter) (View, domain.Matrix, error) {
	v, err := s.Exposure(ctx, f)
	if err != nil {
		return v, domain.Matrix{}, err
	}
	return v, domain.BuildMatrix(v.Rights), nil
}

// Rank ranks the visible agents (F257).
func (s *Service) Rank(ctx context.Context, limit int) (View, []domain.Ranked, error) {
	var v View
	var out []domain.Ranked
	err := s.read(ctx, func(ctx context.Context, r *reader) error {
		var err error
		if v, err = r.current(ctx, domain.Filter{}); err != nil {
			return err
		}
		agents, err := r.q.ExposureAgents(ctx, r.c.Org)
		if err != nil {
			return err
		}
		info := make([]domain.AgentInfo, 0, len(agents))
		for _, a := range agents {
			info = append(info, domain.AgentInfo{ID: a.ID, Owned: a.Owned})
		}
		irreversible := map[string]bool{}
		for _, x := range v.Rights {
			if x.Irreversible {
				irreversible[x.Operation] = true
			}
		}
		out = domain.Rank(v.Rights, info, irreversible)
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return nil
	})
	return v, out, err
}

// Dependents lists the workloads of a connection's credential (F430); the
// caller needs exposure.read at org scope, since a credential is shared.
func (s *Service) Dependents(ctx context.Context, connection ids.UUID) (View, []domain.Workload, error) {
	var v View
	var out []domain.Workload
	err := s.read(ctx, func(ctx context.Context, r *reader) error {
		if err := r.requireOrg(); err != nil {
			return err
		}
		var err error
		if v, err = r.current(ctx, domain.Filter{Connection: &connection}); err != nil {
			return err
		}
		out = domain.Dependents(v.Rights, connection)
		return nil
	})
	return v, out, err
}

// PreviewReduction previews a reduction for a caller with exposure.read at
// org scope (F259): the preview spans every agent.
func (s *Service) PreviewReduction(ctx context.Context, c reflexdomain.ReductionChange) (domain.Diff, string, error) {
	var d domain.Diff
	var note string
	err := s.read(ctx, func(ctx context.Context, r *reader) error {
		if err := r.requireOrg(); err != nil {
			return err
		}
		change, notes, err := ChangeOf(ctx, r.q, r.c.Org, c)
		if err != nil {
			return err
		}
		if d, err = Preview(ctx, r.tx, change); err != nil {
			return err
		}
		for i, n := range notes {
			if i > 0 {
				note += "; "
			}
			note += n
		}
		return nil
	})
	return d, note, err
}

// GraphScope is where a graph starts.
type GraphScope struct {
	Type string // run, agent, incident, resource
	ID   string
}

// GraphResult is a built graph with what it was read from.
type GraphResult struct {
	Graph      domain.Graph
	Snapshot   *Snapshot
	Restricted bool
	AsOf       time.Time
}

// Graph builds a graph for the caller (F272, F274, F289, F293, HR-254):
// candidate edges are read for the scope, then every edge the caller may
// not see is dropped before collapsing, capping and counting.
func (s *Service) Graph(ctx context.Context, mode domain.Mode, scope GraphScope, f domain.GraphFilter, collapse bool,
	lim domain.Limits,
) (GraphResult, error) {
	var out GraphResult
	err := s.read(ctx, func(ctx context.Context, r *reader) error {
		now, err := r.q.DBNow(ctx)
		if err != nil {
			return err
		}
		out.AsOf, out.Restricted = now, !r.view.org
		agents, run, err := r.scopeAgents(ctx, scope)
		if err != nil {
			return err
		}
		var edges []domain.Edge
		switch mode {
		case domain.ModeAuthority, domain.ModeExposure:
			v, err := r.current(ctx, domain.Filter{})
			if err != nil {
				return err
			}
			out.Snapshot = &v.Snapshot
			rights := domain.Select(v.Rights, domain.Filter{})
			rights = scoped(rights, scope, agents)
			if mode == domain.ModeAuthority {
				edges = domain.AuthorityEdges(rights)
			} else {
				edges = domain.ExposureEdges(rights)
			}
		case domain.ModeActivity, domain.ModeCausal, domain.ModeChange:
			if scope.Type == "resource" {
				return ErrScope
			}
			start, end := now.Add(-Window), now
			if f.Start != nil {
				start = *f.Start
			}
			if f.End != nil {
				end = *f.End
			}
			if mode == domain.ModeChange {
				edges, err = r.changes(ctx, agents, start, end)
			} else {
				var acts []domain.Activity
				if acts, err = r.activity(ctx, run, agents, start, end); err == nil {
					if mode == domain.ModeActivity {
						edges = domain.ActivityEdges(acts)
					} else {
						edges = domain.CausalEdges(acts)
					}
				}
			}
			if err != nil {
				return err
			}
		default:
			return ErrScope
		}
		visible, failed := r.view.visible(ctx)
		out.Graph = domain.Build(mode, edges, visible, f, collapse, lim)
		return *failed
	})
	return out, err
}

// scopeAgents resolves a scope to the agents it covers (nil: no agent
// restriction) and the run it names.
func (r *reader) scopeAgents(ctx context.Context, s GraphScope) ([]ids.UUID, *ids.UUID, error) {
	switch s.Type {
	case "resource":
		return nil, nil, nil
	case "agent":
		id, err := ids.ParseUUID(s.ID)
		if err != nil {
			return nil, nil, ErrScope
		}
		return []ids.UUID{id}, nil, nil
	case "run":
		id, err := ids.ParseUUID(s.ID)
		if err != nil {
			return nil, nil, ErrScope
		}
		g, err := r.q.ExposureRunGrant(ctx, r.c.Org, id)
		if db.IsNoRows(err) {
			return nil, nil, ErrNotFound
		} else if err != nil {
			return nil, nil, err
		}
		return []ids.UUID{g.AgentID}, &id, nil
	case "incident":
		id, err := ids.ParseUUID(s.ID)
		if err != nil {
			return nil, nil, ErrScope
		}
		rows, err := r.q.IncidentAgents(ctx, r.c.Org, &id)
		if err != nil {
			return nil, nil, err
		}
		out := []ids.UUID{}
		for _, x := range rows {
			if a, err := ids.ParseUUID(x); err == nil {
				out = append(out, a)
			}
		}
		return out, nil, nil
	}
	return nil, nil, ErrScope
}

func scoped(rights []domain.Right, s GraphScope, agents []ids.UUID) []domain.Right {
	var out []domain.Right
	for _, x := range rights {
		switch {
		case s.Type == "resource":
			if x.ResourceGroup == s.ID {
				out = append(out, x)
			}
		case x.Agent != nil && containsID(agents, *x.Agent):
			out = append(out, x)
		}
	}
	return out
}

func containsID(list []ids.UUID, id ids.UUID) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

func (r *reader) activity(ctx context.Context, run *ids.UUID, agents []ids.UUID, start, end time.Time) ([]domain.Activity, error) {
	ag := agents
	if run != nil {
		ag = []ids.UUID{}
	}
	if ag == nil {
		ag = []ids.UUID{}
	}
	rows, err := r.q.GraphActivity(ctx, dbq.GraphActivityParams{
		OrgID: r.c.Org, RunID: run, AgentIds: ag, StartTime: start, EndTime: end, MaxRows: maxActivity,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Activity, 0, len(rows))
	for _, x := range rows {
		a := domain.Activity{
			Run: x.RunID.String(), Agent: x.AgentID.String(), Transaction: x.ID.String(), Operation: x.Operation,
			Resource: x.TargetType, Decision: x.Decision, Execution: x.Outcome, At: x.CreatedAt,
		}
		if x.ParentRunID != nil {
			a.ParentRun = x.ParentRunID.String()
		}
		if x.PrincipalUserID != nil {
			a.Principal = x.PrincipalUserID.String()
		}
		if x.EffectState != nil {
			a.Effect = *x.EffectState
		}
		if !x.HasReceipt {
			a.Missing = "NO_DECISION_RECEIPT"
		}
		out = append(out, a)
	}
	return out, nil
}

func (r *reader) changes(ctx context.Context, agents []ids.UUID, start, end time.Time) ([]domain.Edge, error) {
	if agents == nil {
		agents = []ids.UUID{}
	}
	rows, err := r.q.GraphGrantChanges(ctx, dbq.GraphGrantChangesParams{
		OrgID: r.c.Org, AgentIds: agents, StartTime: start, EndTime: end, MaxRows: maxActivity,
	})
	if err != nil {
		return nil, err
	}
	cs := make([]domain.ChangeRecord, 0, len(rows))
	for _, x := range rows {
		owner := domain.Node{Type: "agent", ID: x.AgentID.String()}
		cs = append(cs, domain.ChangeRecord{
			Actor: domain.Node{Type: "actor", ID: x.CreatedBy}, Subject: domain.Node{Type: "grant", ID: x.GrantID.String()},
			Owner: &owner, Revision: int(x.Revision), What: "grant_revision", At: x.CreatedAt, Current: x.Current,
		})
	}
	return domain.ChangeEdges(cs), nil
}
