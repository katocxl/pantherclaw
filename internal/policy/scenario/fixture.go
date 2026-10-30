// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scenario

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// The fixture's fixed ids. A case can choose only the agent (given.agent);
// everything else around the action is the same for every case, so a
// condition on any of these ids is pinned by them.
var (
	// DefaultAgentID is the agent of a case that gives none (M11.1 D20).
	DefaultAgentID = mustUUID("00000000-0000-7000-8000-0000000000a1")
	// DefaultEnvironmentID is the environment of a case that gives none.
	DefaultEnvironmentID = mustUUID("00000000-0000-7000-8000-0000000000e1")

	instanceID   = mustUUID("00000000-0000-7000-8000-0000000000b1")
	runID        = mustUUID("00000000-0000-7000-8000-0000000000c1")
	actionID     = mustUUID("00000000-0000-7000-8000-0000000000d1")
	gatewayID    = mustUUID("00000000-0000-7000-8000-0000000000f1")
	connectionID = mustUUID("00000000-0000-7000-8000-0000000000f2")
	teamID       = mustUUID("00000000-0000-7000-8000-0000000000f3")
	unitID       = mustUUID("00000000-0000-7000-8000-0000000000f4")
	providerID   = mustUUID("00000000-0000-7000-8000-0000000000f5")
	holdID       = mustUUID("00000000-0000-7000-8000-0000000000f6")
	grantID      = mustGrantID("00000000-0000-7000-8000-0000000000f7")
	person       = gdomain.Principal{Kind: gdomain.PrincipalUser, ID: mustUUID("00000000-0000-7000-8000-0000000000f8")}
)

// fixturePackage and fixtureVersion pin the definition in the fixture's
// actions; the fixture serves the definition by its digest.
const (
	fixturePackage = "policy-scenario"
	fixtureVersion = "0.0.0"
	fixtureJKT     = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	attestation    = 2
)

// caseError is a case the fixture cannot build; it fails with this detail.
type caseError struct{ detail string }

func (e caseError) Error() string { return e.detail }

func caseErr(format string, args ...any) error { return caseError{fmt.Sprintf(format, args...)} }

// fixture is the in-memory pipeline.Reader one case is evaluated with: no
// containment, a VERIFIED agent at attestation level 2 with an active run,
// one root grant covering the operation, the case's facts and budget usage,
// an ACTIVE connection in enforce mode, and the case's approval request.
type fixture struct {
	org ids.OrgID
	// limits bound the consequence rules, as the runner's compile does.
	limits  celenv.Limits
	now     time.Time
	def     *defs.Definition
	rules   []consequences.Rule
	policy  *pipeline.Policy
	agentID ids.UUID
	env     ids.UUID
	grant   gdomain.Grant
	facts   map[string]fdomain.Fact
	budget  *pdomain.TestBudget
	conn    pipeline.Connection
	hold    *pipeline.HoldRequest
	runs    pipeline.RunConsequenceCounts
	req     pipeline.Request
}

var _ pipeline.Reader = (*fixture)(nil)

// build turns a case into a fixture and its request. reads are the HTTP
// GET reads of the active definitions, which the fixture connection serves.
func build(org ids.OrgID, now time.Time, def *defs.Definition, rules []consequences.Rule, catalog map[string]fdomain.Type, reads []string,
	tc *pdomain.TestCase,
) (*fixture, error) {
	g := tc.Given
	if g == nil {
		g = &pdomain.TestGiven{}
	}
	f := &fixture{org: org, now: now, def: def, rules: rules, agentID: DefaultAgentID, env: DefaultEnvironmentID, budget: g.Budget}
	if c := g.RunConsequences; c != nil {
		if c.Pending < 0 || c.Unconfirmed < 0 {
			return nil, caseErr("given.run_consequences: a count cannot be negative")
		}
		f.runs = pipeline.RunConsequenceCounts{Pending: c.Pending, Unconfirmed: c.Unconfirmed}
	}
	if g.Agent != "" {
		id, err := ids.ParseUUID(g.Agent)
		if err != nil {
			return nil, caseErr("given.agent %q is not a canonical UUID", g.Agent)
		}
		f.agentID = id
	}
	if e := tc.Action.Environment; e != "" {
		id, err := ids.ParseUUID(e)
		if err != nil {
			return nil, caseErr("action.environment %q is not a canonical UUID (environment ids are UUIDs)", e)
		}
		f.env = id
	}
	if err := f.buildGrant(g); err != nil {
		return nil, err
	}
	if err := f.buildFacts(g, catalog, tc.Action.Target); err != nil {
		return nil, err
	}
	if err := checkApproval(g); err != nil {
		return nil, err
	}
	kind, channel, access := "local", string(defs.ChannelHook), "none"
	switch d := def.Dispatch; {
	case d != nil && d.SQL != nil:
		// A structured read the gateway runs itself, where a data scope
		// is enforced (G0 M14 D108).
		kind, channel, access = "postgres", string(defs.ChannelHTTP), "pantherclaw_held"
	case d != nil && d.HTTP != nil && len(def.Scoping) > 0:
		// A read whose answer the gateway reads (D108).
		kind, channel, access = "http", string(defs.ChannelHTTP), "pantherclaw_held"
	case d != nil && d.HTTP != nil:
		kind, channel = "http", string(defs.ChannelSDK)
	case d != nil && d.MCP != nil:
		kind, channel = "mcp", string(defs.ChannelSDK)
	}
	if len(def.Mappings) == 0 {
		return nil, caseErr("the definition of %s has no route", def.Operation)
	}
	route := def.Mappings[0].Route
	if channel == string(defs.ChannelHTTP) {
		// The route of a mapping on a gateway face: http, else mcp.
		if i := slices.IndexFunc(def.Mappings, func(m defs.Mapping) bool { return m.Channel == defs.ChannelHTTP }); i >= 0 {
			route = def.Mappings[i].Route
		} else if i := slices.IndexFunc(def.Mappings, func(m defs.Mapping) bool { return m.Channel == defs.ChannelMCP }); i >= 0 {
			channel, route = string(defs.ChannelMCP), def.Mappings[i].Route
		} else {
			kind, channel, access = "local", string(defs.ChannelHook), "none"
		}
	}
	f.conn = pipeline.Connection{
		ID: connectionID, Gateway: gatewayID, Kind: kind, Package: fixturePackage, State: "ACTIVE", AccessMode: access,
		DefaultMode: pipeline.ModeEnforce, DestinationClass: g.DestinationClass, Modes: map[string]string{}, Reads: reads,
	}
	target := actionir.Target{Type: def.Target.Type}
	if tc.Action.Target != nil {
		target = *tc.Action.Target
	}
	params := tc.Action.Params
	if len(params) == 0 {
		params = []byte("{}")
	}
	parsed, err := actionir.Encode(actionir.ActionIR{
		V: actionir.Version, Org: org.String(), Env: f.env.String(), RunID: runID.String(), ActionID: actionID.String(),
		AgentInstance: instanceID.String(), Operation: tc.Action.Operation,
		Definition: actionir.Definition{Package: fixturePackage, Version: fixtureVersion, Digest: def.Digest},
		Channel:    channel, Route: route, Connection: connectionID.String(), Target: target, Params: params,
	})
	if err != nil {
		return nil, caseErr("the action is not a valid action: %v", err)
	}
	f.req = pipeline.Request{
		Org: org, Action: parsed, Gateway: gatewayID.String(),
		Identity: pipeline.Identity{InstanceID: instanceID, AgentID: f.agentID, AttestationLevel: attestation, JKT: fixtureJKT},
	}
	return f, nil
}

// buildGrant is the root grant: the operation and its consequences,
// narrowed by the case's grant constraints, with its budget.
func (f *fixture) buildGrant(g *pdomain.TestGiven) error {
	op := f.def.Operation
	// The grant also covers what the action's consequences do, which the
	// pipeline decides with it (D28).
	ops := gdomain.Ops{op}
	for _, r := range f.rules {
		if c := r.Consequence.Operation; !slices.Contains(ops, c) {
			ops = append(ops, c)
		}
	}
	b := gdomain.Bounds{Operations: &ops}
	param := func(name string, pb gdomain.ParamBound) {
		if b.Params == nil {
			b.Params = map[string]map[string]gdomain.ParamBound{op: {}}
		}
		b.Params[op][name] = pb
	}
	if g.Grant != nil {
		for _, c := range g.Grant.Constraints {
			switch c.Kind {
			case pdomain.AmountMax, pdomain.CountMax:
				if c.Currency != "" {
					param(c.Param, gdomain.ParamBound{Max: gdomain.Amounts{c.Currency: c.Max}})
				} else {
					param(c.Param, gdomain.ParamBound{Range: &gdomain.Range{Max: c.Max}})
				}
			case pdomain.AllowedValues:
				param(c.Param, gdomain.ParamBound{Values: &gdomain.Match{IDs: c.Values}})
			case pdomain.TargetSet:
				t := map[string]gdomain.Match{f.def.Target.Type: {IDs: c.Values}}
				b.Targets = &t
			case pdomain.DestinationSet:
				b.Destinations = &gdomain.Match{IDs: c.Values}
			case pdomain.RecordScope, pdomain.DataClasses:
				// A grant's data scope on the operation (G0 M14 D11).
				if b.Scope == nil {
					b.Scope = map[string]gdomain.ScopeBound{}
				}
				sb := b.Scope[op]
				if c.Kind == pdomain.RecordScope {
					sb.Records = &gdomain.RecordScope{Key: c.Param, Values: slices.Clone(c.Values)}
				} else {
					sb.Classes = &gdomain.Match{IDs: slices.Clone(c.Values), Prefixes: []string{}}
				}
				b.Scope[op] = sb
			case pdomain.Verify, pdomain.DisclosureLimits:
				return caseErr("given.grant: a grant has no %q constraint", c.Kind)
			default:
				return caseErr("given.grant: a grant has no %q constraint", c.Kind)
			}
		}
	}
	f.grant = gdomain.Grant{
		ID: grantID, Org: f.org, Revision: 1, State: gdomain.StateActive, AgentID: f.agentID, Principal: person,
		EnvironmentID: f.env, NotBefore: f.now.Add(-time.Hour), ExpiresAt: f.now.Add(48 * time.Hour), Bounds: b,
		Delegation: gdomain.Delegation{Depth: 2, MaxChildren: 10}, Grantor: person, Basis: "policy scenario test",
	}
	if bud := g.Budget; bud != nil {
		r := gdomain.BudgetRule{ID: "scenario-budget", Grouping: bdomain.GroupTask, Operations: gdomain.Ops{op}, Period: bdomain.PeriodNone}
		if bud.Currency != "" {
			if _, err := money.ParseMoney(bud.Limit, bud.Currency); err != nil {
				return caseErr("given.budget.limit %q %s is not an amount", bud.Limit, bud.Currency)
			}
			if _, err := money.Parse(bud.Used); err != nil {
				return caseErr("given.budget.used %q is not an amount", bud.Used)
			}
			r.Currency, r.Limit = bud.Currency, bud.Limit
		} else {
			if _, err := strconv.ParseInt(bud.Limit, 10, 64); err != nil {
				return caseErr("given.budget.limit %q is not a count", bud.Limit)
			}
			if _, err := strconv.ParseInt(bud.Used, 10, 64); err != nil {
				return caseErr("given.budget.used %q is not a count", bud.Used)
			}
			r.MaxCount = bud.Limit
		}
		f.grant.Limits.Budgets = []gdomain.BudgetRule{r}
	}
	return nil
}

// buildFacts records the case's facts. Every subject the pipeline asks
// about (the action's target and a consequence's target) is served the
// same facts by name (M11.1 D28). A fact the org's catalog declares is
// typed by it. A fact no provider declares yet may still be given when the
// definitions read it: a prerequisite of the action's definition or of a
// consequence's, or a fact a consequence rule requires (D26, D28). Its
// presence and age count, and its value, when given, is typed by its wire
// form ({"bool": ...}, {"object": ...}); no policy rule can read it (that
// is FACT_UNKNOWN). A fact the case does not give is missing.
func (f *fixture) buildFacts(g *pdomain.TestGiven, catalog map[string]fdomain.Type, target *actionir.Target) error {
	f.facts = map[string]fdomain.Fact{}
	read := f.definitionFacts()
	for _, name := range slices.Sorted(maps.Keys(g.Facts)) {
		tf := g.Facts[name]
		var v fdomain.Value
		t, declared := catalog[name]
		switch {
		case !declared && !read[name]:
			return caseErr("given.facts: %s is neither a fact this org's providers declare nor one the definitions of %s read", name, f.def.Operation)
		case !declared && len(tf.Value) > 0:
			if t = wireType(tf.Value); t == "" {
				return caseErr("given.facts: %s has no typed value such as {\"bool\": true} or {\"object\": {...}}", name)
			}
			fallthrough
		case declared:
			var err error
			if v, err = fdomain.DecodeValue(t, tf.Value); err != nil {
				return caseErr("given.facts: %s is not a %s: %v", name, t, err)
			}
		}
		if tf.AgeSeconds < 0 {
			return caseErr("given.facts: %s has a negative age", name)
		}
		fact := fdomain.Fact{
			Name: name, Value: v, ObservedAt: f.now.Add(-time.Duration(tf.AgeSeconds) * time.Second), RecordedAt: f.now, ProviderID: providerID,
		}
		if target != nil {
			fact.SubjectType, fact.SubjectID = target.Type, target.ID
		}
		f.facts[name] = fact
	}
	return nil
}

func checkApproval(g *pdomain.TestGiven) error {
	switch g.Approval {
	case "", pdomain.ApprovalNone, pdomain.ApprovalApproved, pdomain.ApprovalApprovedOtherAction, pdomain.ApprovalExpired:
	default:
		return caseErr("given.approval %q is not none, approved, approved_other_action or expired", g.Approval)
	}
	switch g.StepUp {
	case "", pdomain.StepUpNone, pdomain.StepUpDone:
	default:
		return caseErr("given.step_up %q is not none or done", g.StepUp)
	}
	return nil
}

// Containment implements pipeline.Reader: nothing is contained.
func (f *fixture) Containment(context.Context, ids.OrgID) (pipeline.Containment, error) {
	return pipeline.Containment{Epoch: 1, Now: f.now}, nil
}

// Controls implements pipeline.Reader: a scenario test decides the policy
// alone, with no containment control.
func (f *fixture) Controls(context.Context, ids.OrgID, pipeline.ControlKeys) ([]pipeline.Control, error) {
	return nil, nil
}

// Definition implements pipeline.Reader: the org's ACTIVE definition.
func (f *fixture) Definition(_ context.Context, org ids.OrgID, pin actionir.Definition) (pipeline.Pinned, error) {
	if org != f.org || pin.Package != fixturePackage || pin.Version != fixtureVersion || pin.Digest != f.def.Digest {
		return pipeline.Pinned{}, pipeline.ErrNotFound
	}
	return pipeline.Pinned{Definition: f.def, State: defs.StateActive, Consequences: f.rules}, nil
}

// Policy implements pipeline.Reader: the version under test (or a mutant).
func (f *fixture) Policy(context.Context, ids.OrgID, ids.UUID) (*pipeline.Policy, error) {
	return f.policy, nil
}

// Run implements pipeline.Reader.
func (f *fixture) Run(_ context.Context, _ ids.OrgID, id ids.UUID) (pipeline.Run, error) {
	if id != runID {
		return pipeline.Run{}, pipeline.ErrNotFound
	}
	return pipeline.Run{
		AgentID: f.agentID, InstanceID: instanceID, Launcher: person, Principal: person, EnvironmentID: f.env, GrantID: grantID, Active: true,
	}, nil
}

// Agent implements pipeline.Reader.
func (f *fixture) Agent(_ context.Context, _ ids.OrgID, id ids.UUID) (pipeline.Agent, error) {
	if id != f.agentID {
		return pipeline.Agent{}, pipeline.ErrNotFound
	}
	return pipeline.Agent{State: "VERIFIED", BusinessUnitID: unitID, TeamID: teamID}, nil
}

// Chain implements pipeline.Reader.
func (f *fixture) Chain(_ context.Context, _ ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error) {
	if id != grantID {
		return nil, pipeline.ErrNotFound
	}
	return []gdomain.Grant{f.grant}, nil
}

// Envelopes implements pipeline.Reader: no guardrails.
func (f *fixture) Envelopes(context.Context, ids.OrgID, []gdomain.Scope) ([]gdomain.Envelope, error) {
	return nil, nil
}

// Facts implements pipeline.Reader.
func (f *fixture) Facts(_ context.Context, _ ids.OrgID, _ ids.UUID, _, _ string, names []string) (map[string]fdomain.Fact, error) {
	out := map[string]fdomain.Fact{}
	for _, n := range names {
		if fact, ok := f.facts[n]; ok {
			out[n] = fact
		}
	}
	return out, nil
}

// Usage implements pipeline.Reader: the case's budget usage.
func (f *fixture) Usage(_ context.Context, _ ids.OrgID, plan gdomain.Plan) (pipeline.Usage, error) {
	u := pipeline.Usage{Accounts: map[bdomain.Ref]bdomain.Account{}, Counters: map[bdomain.Ref]bdomain.Counter{}, CounterRows: map[bdomain.Ref]int{}}
	if f.budget == nil {
		return u, nil
	}
	for _, d := range plan.Budgets {
		var a bdomain.Account
		if f.budget.Currency != "" {
			used, err := money.Parse(f.budget.Used)
			if err != nil {
				return u, err
			}
			a.Reserved = used
		} else {
			n, err := strconv.ParseInt(f.budget.Used, 10, 64)
			if err != nil {
				return u, err
			}
			a.ReservedCount = n
		}
		u.Accounts[d.Ref] = a
	}
	return u, nil
}

// Claim implements pipeline.Reader: no earlier attempt.
func (f *fixture) Claim(context.Context, ids.OrgID, string) (*pipeline.Claim, error) { return nil, nil }

// Connection implements pipeline.Reader.
func (f *fixture) Connection(_ context.Context, _ ids.OrgID, id ids.UUID) (pipeline.Connection, error) {
	if id != connectionID {
		return pipeline.Connection{}, pipeline.ErrNotFound
	}
	return f.conn, nil
}

// Hold implements pipeline.Reader: the case's approval request.
func (f *fixture) Hold(context.Context, ids.OrgID, ids.UUID, ids.UUID) (*pipeline.HoldRequest, error) {
	return f.hold, nil
}

// Variants implements pipeline.Reader: no earlier requests.
func (f *fixture) Variants(context.Context, ids.OrgID, [32]byte, string, actionir.Target, time.Time) (
	[]apdomain.VariantLine, []apdomain.ContextLine, error,
) {
	return nil, nil, nil
}

// HoldSettings implements pipeline.Reader: the defaults.
func (f *fixture) HoldSettings(context.Context, ids.OrgID) (pipeline.HoldSettings, error) {
	return pipeline.HoldSettings{}, nil
}

// CustomerRules implements pipeline.Reader: a scenario test decides a
// policy version over the package's own rules; the org's customer
// consequence rules only add to what it decides (G0 M17 D108).
func (f *fixture) CustomerRules(context.Context, ids.OrgID) ([]consequences.Rule, error) {
	return nil, nil
}

// evaluate decides the case's action under policy, answering its approval
// state: "expired" is a request past its deadline; "approved_other_action"
// an approval bound to another action; "approved" (and step_up "done") an
// approval of exactly this action, when it covers every requirement the
// action has. It returns the evaluation and how many evaluations it made.
func (f *fixture) evaluate(ctx context.Context, policy *pipeline.Policy, g *pdomain.TestGiven) (*pipeline.Evaluation, int, error) {
	if g == nil {
		g = &pdomain.TestGiven{}
	}
	f.policy, f.hold = policy, nil
	p := &pipeline.Pipeline{Reader: f, Limits: f.limits}
	switch g.Approval {
	case pdomain.ApprovalExpired:
		f.hold = &pipeline.HoldRequest{ID: holdID, State: apdomain.StatePending, Deadline: f.now.Add(-time.Minute)}
	case pdomain.ApprovalApprovedOtherAction:
		f.hold = &pipeline.HoldRequest{ID: holdID, State: apdomain.StateApproved, Binding: [32]byte{1}, Deadline: f.now.Add(time.Hour)}
	}
	ev, err := p.EvaluateWith(ctx, f, f.req)
	if err != nil || f.hold != nil || ev.Hold == nil || len(ev.Hold.Requirements) == 0 {
		return ev, 1, err
	}
	if g.Approval != pdomain.ApprovalApproved && g.StepUp != pdomain.StepUpDone {
		return ev, 1, nil
	}
	covered := !slices.ContainsFunc(ev.Hold.Requirements, func(r apdomain.Requirement) bool {
		return (r.Kind == apdomain.KindApproval && g.Approval != pdomain.ApprovalApproved) ||
			(r.Kind == apdomain.KindStepUp && g.StepUp != pdomain.StepUpDone)
	})
	if !covered {
		return ev, 1, nil
	}
	f.hold = &pipeline.HoldRequest{ID: holdID, State: apdomain.StateApproved, Binding: ev.Hold.Binding.Hash, Deadline: ev.Hold.Deadline}
	ev, err = p.EvaluateWith(ctx, f, f.req)
	return ev, 2, err
}

func mustUUID(s string) ids.UUID {
	u, err := ids.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

func mustGrantID(s string) gdomain.GrantID {
	g, err := gdomain.ParseGrantID(s)
	if err != nil {
		panic(err)
	}
	return g
}

// definitionFacts are the facts the definitions read for the case's action:
// its prerequisites, its consequence rules' facts and their consequence
// definitions' prerequisites.
func (f *fixture) definitionFacts() map[string]bool {
	out := map[string]bool{}
	add := func(d *defs.Definition) {
		if d == nil {
			return
		}
		for _, p := range d.Prerequisites {
			out[p.Fact] = true
		}
	}
	add(f.def)
	for _, r := range f.rules {
		for _, n := range r.RequiresFacts {
			out[n] = true
		}
		add(r.Definition)
	}
	return out
}

// wireType is the type a fact value's wire form names by its one member,
// or "".
func wireType(raw jsontext.Value) fdomain.Type {
	var members map[string]jsontext.Value
	if err := json.Unmarshal(raw, &members); err != nil {
		return ""
	}
	byMember := map[string]fdomain.Type{
		"bool": fdomain.TypeBoolean, "int": fdomain.TypeInteger, "decimal": fdomain.TypeDecimal, "amount": fdomain.TypeMoney,
		"id": fdomain.TypeIdentifier, "time": fdomain.TypeTimestamp, "object": fdomain.TypeObject,
	}
	var out fdomain.Type
	for m := range members {
		t, ok := byMember[m]
		if m == "currency" {
			continue
		}
		if !ok || out != "" {
			return ""
		}
		out = t
	}
	return out
}

// SensitiveReads implements pipeline.Reader: a policy test case has no
// read history.
func (f *fixture) SensitiveReads(context.Context, ids.OrgID, ids.UUID) ([]pipeline.SensitiveRead, error) {
	return nil, nil
}

// RunConsequences implements pipeline.Reader: the case's counts.
func (f *fixture) RunConsequences(context.Context, ids.OrgID, ids.UUID) (pipeline.RunConsequenceCounts, error) {
	return f.runs, nil
}
