// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"slices"
	"strings"
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
	ErrNotFound      = pcerr.New(pcerr.NotFound, "EXPOSURE_SUBJECT_NOT_FOUND", "not found")
	ErrTooManyAgents = pcerr.New(pcerr.ResourceExhausted, "VISIBLE_AGENTS_EXHAUSTED",
		"the caller's scope covers more agents than one read filters; narrow the scope")
)

// Window is the default graph window when the filter names none.
const Window = 7 * 24 * time.Hour

// maxActivity bounds the transactions one graph reads.
const maxActivity = 5000

// MaxVisibleAgents bounds the agent ids a scoped read filters by (D60).
const MaxVisibleAgents = 10000

// Visible is the agents a caller may read: every one (All), or the listed
// ones (D60).
type Visible struct {
	All bool
	IDs []ids.UUID
}

// Has reports whether agent is visible.
func (v Visible) Has(agent ids.UUID) bool { return v.All || slices.Contains(v.IDs, agent) }

// Intersect keeps the agents of list that are visible; a nil list means
// every agent.
func (v Visible) Intersect(list []ids.UUID) Visible {
	if list == nil {
		return v
	}
	out := Visible{IDs: []ids.UUID{}}
	for _, a := range list {
		if v.Has(a) {
			out.IDs = append(out.IDs, a)
		}
	}
	return out
}

// VisibleAgents resolves the agents the caller holds perm over, for
// filtering in SQL before a page is cut (D60): every agent with perm at
// org scope, else the ids the agent scope allows, at most
// MaxVisibleAgents (RESOURCE_EXHAUSTED beyond).
func VisibleAgents(ctx context.Context, c tenancy.Caller, q *dbq.Queries, perm td.Permission) (Visible, error) {
	if c.Can(perm, td.OrgPath(c.Org)) {
		return Visible{All: true}, nil
	}
	agents, err := q.ExposureAgents(ctx, c.Org)
	if err != nil {
		return Visible{}, err
	}
	scope := tapp.NewAgentScope(c, q, perm)
	out := Visible{IDs: []ids.UUID{}}
	for _, a := range agents {
		ok, err := scope.Can(ctx, a.ID)
		if err != nil {
			return Visible{}, err
		}
		if ok {
			if len(out.IDs) == MaxVisibleAgents {
				return Visible{}, ErrTooManyAgents
			}
			out.IDs = append(out.IDs, a.ID)
		}
	}
	return out, nil
}

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
	// automations: the caller holds automation.read somewhere (D37a).
	automations bool
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
// scope, everything else by the edges' context.
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
		case domain.NodeAutomation:
			return v.automations
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

// read runs fn for a caller holding exposure.read somewhere; edition says
// whether the edition must offer breach radius (only the activity edge
// table, F298, is Community).
func (s *Service) read(ctx context.Context, edition bool, fn func(context.Context, *reader) error) error {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if !c.CanAnywhere(td.PermExposureRead) {
		return td.ErrPermissionDenied(td.PermExposureRead)
	}
	if edition {
		if err := Entitled(ctx, s.Ents); err != nil {
			return err
		}
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		return fn(ctx, &reader{c: c, tx: tx, q: q, view: scopeViewer{
			scope: tapp.NewAgentScope(c, q, td.PermExposureRead), org: c.Can(td.PermExposureRead, td.OrgPath(c.Org)),
			automations: c.CanAnywhere(td.PermAutomationRead),
		}})
	}, db.ReadOnly())
}

// current reads the snapshot. A grant whose window ended since the
// computation is EXPIRED at read time (L6): time passing is no feed event.
func (r *reader) current(ctx context.Context, f domain.Filter) (View, error) {
	v, err := Current(ctx, r.tx, r.view, domain.Filter{Agent: f.Agent, Connection: f.Connection, WithCeiling: true})
	if errors.Is(err, ErrNoSnapshot) {
		return v, ErrNotComputed
	} else if err != nil {
		return v, err
	}
	now, err := r.q.DBNow(ctx)
	if err != nil {
		return v, err
	}
	// Without automation.read, rights never name their automation (D37a).
	autoRead := r.automationRead()
	out := v.Rights[:0]
	for _, x := range v.Rights {
		if !autoRead {
			x.Automations = nil
		}
		if x.View == domain.Effective && x.Label.Current() && x.ExpiresAt != nil && !x.ExpiresAt.After(now) {
			x.Label = domain.Expired
			x.Reasons = append(slices.Clone(x.Reasons), domain.ReasonGrantExpired)
		}
		if f.Match(x) {
			out = append(out, x)
		}
	}
	v.Rights = out
	return v, nil
}

func (r *reader) requireOrg() error {
	return r.c.Require(td.PermExposureRead, td.OrgPath(r.c.Org))
}

// Exposure lists the current rights the caller may see. An automation
// filter or the issuance-ceiling view needs automation.read, the ceiling
// Business (D37a).
func (s *Service) Exposure(ctx context.Context, f domain.Filter) (View, error) {
	var out View
	err := s.read(ctx, true, func(ctx context.Context, r *reader) error {
		if err := r.automationFilter(ctx, s.Ents, f); err != nil {
			return err
		}
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
	v, out, _, err := s.RankWithAutomations(ctx, limit, false)
	return v, out, err
}

// RankWithAutomations ranks the visible agents and, when asked, the
// automations behind the visible rights (D37a): by their issuance ceiling
// on Business, never by activity; automations need automation.read.
func (s *Service) RankWithAutomations(ctx context.Context, limit int, automations bool) (View, []domain.Ranked, RankedAutomations, error) {
	var v View
	var out []domain.Ranked
	var autos RankedAutomations
	err := s.read(ctx, true, func(ctx context.Context, r *reader) error {
		var err error
		if v, err = r.current(ctx, domain.Filter{WithCeiling: automations}); err != nil {
			return err
		}
		if automations {
			if autos, err = r.rankAutomations(ctx, s.Ents, v.Rights, limit); err != nil {
				return err
			}
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
	return v, out, autos, err
}

// Dependents lists the workloads of a connection's credential (F430); the
// caller needs exposure.read at org scope, since a credential is shared.
func (s *Service) Dependents(ctx context.Context, connection ids.UUID) (View, []domain.Workload, error) {
	var v View
	var out []domain.Workload
	err := s.read(ctx, true, func(ctx context.Context, r *reader) error {
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
	err := s.read(ctx, true, func(ctx context.Context, r *reader) error {
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
		note = strings.Join(notes, "; ")
		return nil
	})
	return d, note, err
}

// GraphScope is where a graph starts.
type GraphScope struct {
	Type string // run, agent, incident, resource, automation
	ID   string
	// IncludeCeiling adds automations' issuance-ceiling edges to authority
	// and exposure graphs (D37a; Business, automation.read).
	IncludeCeiling bool
}

// GraphResult is a built graph with what it was read from.
type GraphResult struct {
	Graph      domain.Graph
	Snapshot   *Snapshot
	Restricted bool
	AsOf       time.Time
}

// Freshness values of graph edges (D29).
const (
	FreshCurrent = "CURRENT" // read from the current, up-to-date snapshot
	FreshStale   = "STALE"   // the snapshot predates a recorded change
	FreshLive    = "LIVE"    // read from the records as they are now
)

// Graph builds a graph for the caller (F272, F274, F289, F293, HR-254):
// candidate edges are read for the scope, limited in SQL to the agents the
// caller may see (D60), then every edge the caller may not see is dropped
// before collapsing, capping and counting. table marks the tabular twin:
// in activity mode it is Community (F298); everything else needs Team.
func (s *Service) Graph(ctx context.Context, mode domain.Mode, scope GraphScope, f domain.GraphFilter, collapse, table bool,
	lim domain.Limits,
) (GraphResult, error) {
	var out GraphResult
	edition := !table || mode != domain.ModeActivity
	err := s.read(ctx, edition, func(ctx context.Context, r *reader) error {
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
		var cut bool
		fresh := FreshLive
		switch mode {
		case domain.ModeAuthority, domain.ModeExposure:
			af := domain.Filter{WithCeiling: scope.IncludeCeiling}
			if scope.Type == domain.NodeAutomation {
				id, err := ids.ParseUUID(scope.ID)
				if err != nil {
					return ErrScope
				}
				af.Automation = &id
			}
			if err := r.automationFilter(ctx, s.Ents, af); err != nil {
				return err
			}
			v, err := r.current(ctx, af)
			if err != nil {
				return err
			}
			out.Snapshot = &v.Snapshot
			if fresh = FreshCurrent; v.Snapshot.Stale {
				fresh = FreshStale
			}
			cut = v.Snapshot.Truncated
			rights := scoped(v.Rights, scope, agents)
			held := domain.HeldReach(rights)
			var issued []domain.IssuedGrant
			if r.automationRead() {
				if issued, err = r.issued(ctx); err != nil {
					return err
				}
				issued = scopedIssued(issued, scope, agents)
			}
			autoEdges := domain.AutomationEdges(rights, issued, scope.IncludeCeiling, now)
			if mode == domain.ModeAuthority {
				edges = append(domain.AuthorityEdges(held), autoEdges...)
			} else {
				// The exposure graph shows what is reached: the ceiling, not
				// which grants an automation issued.
				edges = domain.ExposureEdges(held)
				for _, e := range autoEdges {
					if e.Kind == domain.EdgeCeiling {
						edges = append(edges, e)
					}
				}
			}
		case domain.ModeActivity, domain.ModeCausal, domain.ModeChange:
			if scope.Type == "resource" || scope.Type == domain.NodeAutomation {
				return ErrScope
			}
			vis, err := VisibleAgents(ctx, r.c, r.q, td.PermExposureRead)
			if err != nil {
				return err
			}
			// A run scope keeps every visible agent: the SQL limits it to the run
			// and its child runs, whoever runs them; the run itself was checked
			// visible above (L11).
			if run == nil || mode == domain.ModeChange {
				vis = vis.Intersect(agents)
			}
			start, end := now.Add(-Window), now
			if f.Start != nil {
				start = *f.Start
			}
			if f.End != nil {
				end = *f.End
			}
			if mode == domain.ModeChange {
				edges, cut, err = r.changes(ctx, vis, start, end)
			} else {
				var acts []domain.Activity
				if acts, cut, err = r.activity(ctx, run, vis, start, end); err == nil {
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
		for i := range edges {
			edges[i].Freshness = fresh
		}
		visible, failed := r.view.visible(ctx)
		out.Graph = domain.Build(mode, edges, visible, f, collapse, lim)
		out.Graph.Truncated = out.Graph.Truncated || cut
		return *failed
	})
	return out, err
}

// scopeAgents resolves a scope to the agents it covers (nil: no agent
// restriction; empty: none) and the run it names. A run the caller may not
// see is not found, the same as an unknown one (L11).
func (r *reader) scopeAgents(ctx context.Context, s GraphScope) ([]ids.UUID, *ids.UUID, error) {
	switch s.Type {
	case "resource", domain.NodeAutomation:
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
		if ok, err := r.view.Agent(ctx, g.AgentID); err != nil {
			return nil, nil, err
		} else if !ok {
			return nil, nil, ErrNotFound
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
		// An incident about no agent covers none, never the whole org.
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
		case s.Type == domain.NodeAutomation:
			if slices.ContainsFunc(x.Automations, func(a ids.UUID) bool { return a.String() == s.ID }) {
				out = append(out, x)
			}
		case x.Agent != nil && slices.Contains(agents, *x.Agent):
			out = append(out, x)
		}
	}
	return out
}

func (r *reader) activity(ctx context.Context, run *ids.UUID, vis Visible, start, end time.Time) ([]domain.Activity, bool, error) {
	if !vis.All && len(vis.IDs) == 0 {
		return nil, false, nil
	}
	rows, err := r.q.GraphActivity(ctx, dbq.GraphActivityParams{
		OrgID: r.c.Org, RunID: run, AllAgents: vis.All, AgentIds: orEmpty(vis.IDs), StartTime: start, EndTime: end,
		MaxRows: maxActivity,
	})
	if err != nil {
		return nil, false, err
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
		if x.ParentAgentID != nil {
			a.ParentAgent = x.ParentAgentID.String()
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
	return out, len(rows) == maxActivity, nil
}

func orEmpty(s []ids.UUID) []ids.UUID {
	if s == nil {
		return []ids.UUID{}
	}
	return s
}

func (r *reader) changes(ctx context.Context, vis Visible, start, end time.Time) ([]domain.Edge, bool, error) {
	if !vis.All && len(vis.IDs) == 0 {
		return nil, false, nil
	}
	rows, err := r.q.GraphGrantChanges(ctx, dbq.GraphGrantChangesParams{
		OrgID: r.c.Org, AllAgents: vis.All, AgentIds: orEmpty(vis.IDs), StartTime: start, EndTime: end, MaxRows: maxActivity,
	})
	if err != nil {
		return nil, false, err
	}
	cs := make([]domain.ChangeRecord, 0, len(rows))
	for _, x := range rows {
		cs = append(cs, domain.ChangeRecord{
			Actor: domain.Node{Type: "actor", ID: x.CreatedBy}, Subject: domain.Node{Type: "grant", ID: x.GrantID.String()},
			Context: []domain.Node{{Type: "agent", ID: x.AgentID.String()}}, Revision: int(x.Revision), What: "grant_revision",
			At: x.CreatedAt, Current: x.Current,
		})
	}
	return domain.ChangeEdges(cs), len(rows) == maxActivity, nil
}

// scopedIssued keeps the issued grants a graph scope covers: an
// automation's own, or those of the scope's agents.
func scopedIssued(gs []domain.IssuedGrant, s GraphScope, agents []ids.UUID) []domain.IssuedGrant {
	var out []domain.IssuedGrant
	for _, g := range gs {
		switch {
		case s.Type == domain.NodeAutomation:
			if g.Automation.String() == s.ID {
				out = append(out, g)
			}
		case s.Type == "resource":
		case slices.Contains(agents, g.Agent):
			out = append(out, g)
		}
	}
	return out
}
