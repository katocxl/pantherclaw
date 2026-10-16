// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	exdomain "github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// Blast-radius preview and restriction comparison (D37, F747–F750, Business,
// HR-289): what a version's authority could reach, computed from today's
// grants, connections, policy and coverage with the version's ceiling as
// if it were active, and filtered by the caller's exposure.read before
// anything is listed or counted.

// ErrNarrowed refuses a narrowed ceiling that cannot be read.
var ErrNarrowed = pcerr.New(pcerr.InvalidArgument, "CEILING_INVALID", "the narrowed ceiling is not a ceiling document")

// Reach is one right of a preview.
type Reach struct {
	ResourceGroup string
	Verb          exdomain.Verb
	Operation     string
	Connection    *ids.UUID
	Agent         *ids.UUID
	Irreversible  bool
	Coverage      exdomain.Coverage
}

// Budget is a per-day budget of a currency.
type Budget struct {
	Currency, MaxPerDay string
}

// SharedCredential is a connection the ceiling reaches through, with the
// other agents whose reach also goes through it.
type SharedCredential struct {
	Connection ids.UUID
	Operations []string
	Others     []ids.UUID
}

// BlastRadius is a version's preview.
type BlastRadius struct {
	Reach                []Reach
	Consequential        []string
	MaxSpend             []Budget
	MaxGrants, MaxRuns   int
	MaxConcurrency       int
	DelegationDepth      int
	DelegationChildren   int
	Shared               []SharedCredential
	Approvals            []string
	Restrictions         []string
	Uncovered            []string
	UncertainEffects     []string
	TriggeredAutomations []ids.UUID
	Restricted           bool
	Notes                []string
}

// viewer is the caller's exposure.read through the agent scope.
type viewer struct {
	scope *tapp.AgentScope
	org   bool
}

func (v viewer) Agent(ctx context.Context, a ids.UUID) (bool, error) {
	ok, err := v.scope.Can(ctx, a)
	if db.IsNoRows(err) {
		return false, nil
	}
	return ok, err
}

func (v viewer) Org() bool { return v.org }

func exposureViewer(c tenancy.Caller, q *dbq.Queries) (viewer, error) {
	if !c.CanAnywhere(td.PermExposureRead) {
		return viewer{}, td.ErrPermissionDenied(td.PermExposureRead)
	}
	return viewer{scope: tapp.NewAgentScope(c, q, td.PermExposureRead), org: c.Can(td.PermExposureRead, td.OrgPath(c.Org))}, nil
}

// ceilingOf is the version's ceiling as exposure computes it: active, so
// the preview shows what enabling it would allow.
func ceilingOf(automation ids.UUID, c *autodomain.Ceiling, now time.Time) exdomain.Ceiling {
	out := exdomain.Ceiling{ID: ids.NewV7(), Automation: automation, ReviewBy: now.Add(24 * time.Hour), Active: true}
	if c == nil {
		return out
	}
	for _, a := range c.Agents {
		out.Agents = append(out.Agents, a.UUID())
	}
	out.Bounds, out.DelegationDepth = c.Bounds, c.Delegation.Depth
	return out
}

// ceilingRights computes the ceiling view of one ceiling on the loaded
// inputs (every other automation's ceiling left out).
func ceilingRights(l exapp.Loaded, ce exdomain.Ceiling) []exdomain.Right {
	in := l.Inputs
	in.Ceilings = []exdomain.Ceiling{ce}
	var out []exdomain.Right
	for _, r := range exdomain.Compute(in).Rights {
		if r.View == exdomain.IssuanceCeiling {
			out = append(out, r)
		}
	}
	return out
}

// PreviewBlastRadius previews a version's authority (D37).
func (s *Service) PreviewBlastRadius(ctx context.Context, versionID ids.UUID) (BlastRadius, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return BlastRadius{}, err
	}
	if err := s.edition(ctx, true); err != nil {
		return BlastRadius{}, err
	}
	var out BlastRadius
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, def, err := version(ctx, q, c.Org, versionID)
		if err != nil {
			return err
		}
		view, err := exposureViewer(c, q)
		if err != nil {
			return err
		}
		l, err := exapp.Load(ctx, tx)
		if err != nil {
			return err
		}
		all := ceilingRights(l, ceilingOf(v.AutomationID, def.Authority.Ceiling, l.Inputs.Now))
		rights, err := exapp.FilterVisible(ctx, view, all)
		if err != nil {
			return err
		}
		held, err := exapp.FilterVisible(ctx, view, exdomain.HeldReach(exdomain.Compute(l.Inputs).Rights))
		if err != nil {
			return err
		}
		others, err := q.AssuranceEnabledDefinitions(ctx, c.Org)
		if err != nil {
			return err
		}
		envs, err := envelopes(ctx, q, c.Org)
		if err != nil {
			return err
		}
		out = blast(def, rights, held, l, triggered(def, v.AutomationID, others))
		out.Restrictions = append(out.Restrictions, guardrails(envs, operationsOf(rights))...)
		out.Restricted = len(rights) < len(all) || !view.org
		if def.Authority.Ceiling == nil {
			out.Notes = append(out.Notes, "the version has no ceiling: it issues no grant")
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// blast assembles the preview from the visible ceiling rights.
func blast(def *autodomain.Definition, rights, held []exdomain.Right, l exapp.Loaded, triggered []ids.UUID) BlastRadius {
	var out BlastRadius
	consequential, uncovered, uncertain := map[string]bool{}, map[string]bool{}, map[string]bool{}
	conns := map[ids.UUID]map[string]bool{}
	ceilingAgents := map[ids.UUID]bool{}
	for _, r := range rights {
		out.Reach = append(out.Reach, Reach{
			ResourceGroup: r.ResourceGroup, Verb: r.Verb, Operation: r.Operation, Connection: r.Connection, Agent: r.Agent,
			Irreversible: r.Irreversible, Coverage: r.Coverage,
		})
		if r.Agent != nil {
			ceilingAgents[*r.Agent] = true
		}
		if r.Operation == "" {
			continue
		}
		if r.Irreversible || r.Verb != exdomain.VerbRead {
			consequential[r.Operation] = true
		}
		if r.Coverage == exdomain.CoverageUnknown && r.Agent != nil && r.Connection != nil {
			uncovered[r.Agent.String()+" "+r.Connection.String()+" "+r.Operation] = true
		}
		if l.Unverified[r.Operation] && r.Verb != exdomain.VerbRead {
			uncertain[r.Operation] = true
		}
		if r.Connection != nil {
			if conns[*r.Connection] == nil {
				conns[*r.Connection] = map[string]bool{}
			}
			conns[*r.Connection][r.Operation] = true
		}
	}
	out.Consequential, out.Uncovered, out.UncertainEffects = keys(consequential), keys(uncovered), keys(uncertain)
	for conn, ops := range conns {
		sc := SharedCredential{Connection: conn, Operations: keys(ops)}
		seen := map[ids.UUID]bool{}
		for _, r := range held {
			if r.Connection == nil || *r.Connection != conn || r.Agent == nil || ceilingAgents[*r.Agent] || seen[*r.Agent] ||
				!r.Label.Current() {
				continue
			}
			seen[*r.Agent] = true
			sc.Others = append(sc.Others, *r.Agent)
		}
		slices.SortFunc(sc.Others, func(a, b ids.UUID) int { return cmp.Compare(a.String(), b.String()) })
		out.Shared = append(out.Shared, sc)
	}
	slices.SortFunc(out.Shared, func(a, b SharedCredential) int { return cmp.Compare(a.Connection.String(), b.Connection.String()) })
	if c := def.Authority.Ceiling; c != nil {
		for _, b := range c.PerDay.Budget {
			out.MaxSpend = append(out.MaxSpend, Budget{Currency: b.Currency, MaxPerDay: b.Amount})
		}
		out.MaxGrants, out.MaxRuns = c.PerDay.Grants, c.PerDay.Runs
		out.MaxConcurrency = c.ConcurrencyOrDefault()
		out.DelegationDepth, out.DelegationChildren = c.Delegation.Depth, c.Delegation.MaxChildren
		for _, r := range c.Requirements {
			out.Approvals = append(out.Approvals, requirementText(r))
		}
	}
	ops := operationsOf(rights)
	restr := map[string]bool{}
	for _, rule := range l.Inputs.Policy.Rules {
		if rule.Kind == "ANNOTATE" {
			continue
		}
		if slices.ContainsFunc(ops, func(op string) bool {
			return slices.ContainsFunc(rule.Operations, func(p string) bool { return patternMatches(p, op) })
		}) {
			restr["policy "+rule.Kind+" "+rule.ID] = true
		}
	}
	out.Restrictions = keys(restr)
	out.TriggeredAutomations = triggered
	return out
}

func patternMatches(pattern, op string) bool {
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(op, p)
	}
	return pattern == op
}

func requirementText(r gdomain.Requirement) string {
	var what []string
	if r.Approval != nil {
		what = append(what, "approval")
	}
	if r.StepUp != nil {
		what = append(what, "step-up")
	}
	if len(what) == 0 {
		what = []string{"requirement"}
	}
	return strings.Join(what, "+") + " for " + strings.Join(r.Operations, ",") + ": " + r.Reason
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// triggered lists the other enabled automations whose event or threshold
// trigger names an event this version's steps can produce.
func triggered(def *autodomain.Definition, self ids.UUID, others []dbq.AssuranceEnabledDefinitionsRow) []ids.UUID {
	produced := Produces(def)
	var out []ids.UUID
	for _, o := range others {
		if o.AutomationID == self {
			continue
		}
		d, err := autodomain.Parse(o.Definition)
		if err != nil {
			continue
		}
		var on string
		switch {
		case d.When.Event != nil:
			on = d.When.Event.On
		case d.When.Threshold != nil:
			on = d.When.Threshold.On
		default:
			continue
		}
		if produced[on] {
			out = append(out, o.AutomationID)
		}
	}
	return out
}

// produces maps step kinds to the platform events (D18 vocabulary) their
// effects can put on the feed. Every execution produces
// automation.finished.
var produces = map[string][]string{
	"launch_run": {
		"run.ended", "grant.issued", "grant.revoked", "action.decided", "action.held", "action.denied",
		"effect.recorded", "approval.expired",
	},
	"revoke_grant": {"grant.revoked"},
}

// Produces is the set of events a version's steps can produce.
func Produces(def *autodomain.Definition) map[string]bool {
	out := map[string]bool{"automation.finished": true}
	for _, s := range def.Do {
		for _, e := range produces[s.Step] {
			out[e] = true
		}
	}
	return out
}

// Comparison is a restriction's effect on the ceiling.
type Comparison struct {
	Before, After int
	Removed       []Reach
	Failing       []ids.UUID
	Truncated     bool
	Restricted    bool
}

// maxCompareGrants bounds the history a comparison reads.
const maxCompareGrants = 5000

// CompareRestriction compares a version's ceiling with a narrower one: the
// reach it removes and the executions of the last 30 days whose grants the
// narrowed ceiling would not have allowed (D37).
func (s *Service) CompareRestriction(ctx context.Context, versionID ids.UUID, narrowedDoc []byte) (Comparison, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return Comparison{}, err
	}
	if err := s.edition(ctx, true); err != nil {
		return Comparison{}, err
	}
	var narrowed autodomain.Ceiling
	if err := json.Unmarshal(narrowedDoc, &narrowed, json.RejectUnknownMembers(true)); err != nil {
		return Comparison{}, ErrNarrowed
	}
	var out Comparison
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, def, err := version(ctx, q, c.Org, versionID)
		if err != nil {
			return err
		}
		view, err := exposureViewer(c, q)
		if err != nil {
			return err
		}
		l, err := exapp.Load(ctx, tx)
		if err != nil {
			return err
		}
		now := l.Inputs.Now
		before := ceilingRights(l, ceilingOf(v.AutomationID, def.Authority.Ceiling, now))
		after := ceilingRights(l, ceilingOf(v.AutomationID, &narrowed, now))
		vb, err := exapp.FilterVisible(ctx, view, before)
		if err != nil {
			return err
		}
		va, err := exapp.FilterVisible(ctx, view, after)
		if err != nil {
			return err
		}
		out.Before, out.After = len(vb), len(va)
		out.Restricted = len(vb) < len(before) || !view.org
		for _, r := range exdomain.Compare(vb, va, exdomain.Change{}).Removed {
			out.Removed = append(out.Removed, Reach{
				ResourceGroup: r.ResourceGroup, Verb: r.Verb, Operation: r.Operation, Connection: r.Connection, Agent: r.Agent,
				Irreversible: r.Irreversible, Coverage: r.Coverage,
			})
		}
		grants, err := q.AssuranceIssuedGrants(ctx, dbq.AssuranceIssuedGrantsParams{
			OrgID: c.Org, AutomationID: v.AutomationID, Since: now.Add(-30 * 24 * time.Hour), MaxRows: maxCompareGrants + 1,
		})
		if err != nil {
			return err
		}
		if len(grants) > maxCompareGrants {
			grants, out.Truncated = grants[:maxCompareGrants], true
		}
		out.Failing, err = failing(ctx, view, narrowed, grants)
		return err
	}, db.ReadOnly())
	return out, err
}

// failing lists the executions (of agents the caller may see) with a grant
// the narrowed ceiling would not have allowed: an agent outside it, or
// bounds beyond it.
func failing(ctx context.Context, view viewer, narrowed autodomain.Ceiling, grants []dbq.AssuranceIssuedGrantsRow) ([]ids.UUID, error) {
	agents := map[ids.UUID]bool{}
	for _, a := range narrowed.Agents {
		agents[a.UUID()] = true
	}
	seen := map[ids.UUID]bool{}
	var out []ids.UUID
	for _, g := range grants {
		if g.AutomationExecutionID == nil || seen[*g.AutomationExecutionID] {
			continue
		}
		ok, err := view.Agent(ctx, g.AgentID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		var b gdomain.Bounds
		bad := json.Unmarshal(g.Bounds, &b) != nil || !agents[g.AgentID] || b.Within(narrowed.Bounds) != nil
		if bad {
			seen[*g.AutomationExecutionID] = true
			out = append(out, *g.AutomationExecutionID)
		}
	}
	return out, nil
}

// operationsOf lists the distinct operations of rights, sorted.
func operationsOf(rights []exdomain.Right) []string {
	set := map[string]bool{}
	for _, r := range rights {
		if r.Operation != "" {
			set[r.Operation] = true
		}
	}
	return keys(set)
}

// maxEnvelopes bounds the guardrails a preview reads.
const maxEnvelopes = 1000

func envelopes(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]dbq.ListEnvelopesRow, error) {
	var out []dbq.ListEnvelopesRow
	var after *ids.UUID
	for len(out) < maxEnvelopes {
		rows, err := q.ListEnvelopes(ctx, dbq.ListEnvelopesParams{OrgID: org, After: after, PageLimit: 200})
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if len(rows) < 200 {
			break
		}
		after = &rows[len(rows)-1].ID
	}
	return out, nil
}

// guardrails names the guardrails (envelopes) the ceiling cannot override
// on its operations: one that leaves an operation out of its bounds, or
// adds a requirement to it.
func guardrails(envs []dbq.ListEnvelopesRow, ops []string) []string {
	var out []string
	for _, e := range envs {
		var b gdomain.Bounds
		var reqs []gdomain.Requirement
		_ = json.Unmarshal(e.Bounds, &b)          // an unreadable part restricts nothing we can name
		_ = json.Unmarshal(e.Requirements, &reqs)
		touches := slices.ContainsFunc(ops, func(op string) bool {
			if b.Operations != nil && !b.Operations.Matches(op) {
				return true
			}
			return slices.ContainsFunc(reqs, func(r gdomain.Requirement) bool { return r.Operations.Matches(op) })
		})
		if touches {
			out = append(out, "guardrail "+e.Name+" ("+e.ScopeKind+" "+e.ScopeKey+")")
		}
	}
	return out
}
