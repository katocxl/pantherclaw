// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain computes breach radius (G0 M10, coordinator decisions
// D27–D31; F253–F260): what each agent can reach, in three views that stay
// separate (HR-253):
//
//   - OBSERVED: effects actually dispatched through a connection;
//   - EFFECTIVE: active grant bounds, intersected with the published policy
//     (a rule that may restrict makes a right CONDITIONAL) and labeled with
//     the path's coverage;
//   - CREDENTIAL: reach outside PantherClaw's decisions: agent-held access,
//     what a connection's credential can do at the target, and routes that
//     are observe-only, unknown or not a channel.
//
// Every right is labeled USABLE, CONDITIONAL, EXPIRED or UNCERTAIN. What
// cannot be read (a credential's scope, a connection's package) is
// UNCERTAIN, never left out: the computation errs toward more reach, never
// less (T-111). Everything here is pure: no I/O, clock or randomness.
package domain

import (
	"cmp"
	"slices"
	"strings"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// View is one of the three exposure views (HR-253).
type View string

// Views.
const (
	Observed   View = "OBSERVED"
	Effective  View = "EFFECTIVE"
	Credential View = "CREDENTIAL"
)

// Views lists the views in display order.
var Views = []View{Observed, Effective, Credential}

// Label says how usable a right is now.
type Label string

// Labels, most usable first.
const (
	Usable      Label = "USABLE"
	Conditional Label = "CONDITIONAL"
	Uncertain   Label = "UNCERTAIN"
	Expired     Label = "EXPIRED"
)

// Rank orders labels by present usability: lower is more usable. An
// UNCERTAIN right ranks above an EXPIRED one: it may well be usable.
func (l Label) Rank() int {
	//exhaustive:ignore // every other label ranks last
	switch l {
	case Usable:
		return 0
	case Conditional:
		return 1
	case Uncertain:
		return 2
	default:
		return 3
	}
}

// Current reports whether the label counts as present reach. EXPIRED is
// history (D31): kept, never counted as current authority.
func (l Label) Current() bool { return l != Expired }

// Coverage is a path's coverage state (M9 vocabulary).
type Coverage string

// Coverage states, weakest first.
const (
	CoverageUnknown     Coverage = "UNKNOWN"
	CoverageObserveOnly Coverage = "OBSERVE_ONLY"
	CoveragePartial     Coverage = "PARTIAL"
	CoverageEnforced    Coverage = "ENFORCED"
)

// Rank orders coverage by enforceability: lower is weaker.
func (c Coverage) Rank() int {
	//exhaustive:ignore // UNKNOWN and anything unrecognized rank weakest
	switch c {
	case CoverageEnforced:
		return 3
	case CoveragePartial:
		return 2
	case CoverageObserveOnly:
		return 1
	default:
		return 0
	}
}

// Reason codes a right carries.
const (
	ReasonGrant                 = "GRANT"
	ReasonGrantExpired          = "GRANT_EXPIRED"
	ReasonGrantNotYetValid      = "GRANT_NOT_YET_VALID"
	ReasonPolicyCondition       = "POLICY_CONDITION"
	ReasonPolicyForbid          = "POLICY_FORBID"
	ReasonPolicyUnknown         = "POLICY_UNKNOWN"
	ReasonConnectionQuarantined = "CONNECTION_QUARANTINED"
	ReasonPackageUnknown        = "PACKAGE_UNKNOWN"
	ReasonDefinitionUnknown     = "DEFINITION_UNKNOWN"
	ReasonAgentHeld             = "AGENT_HELD"
	ReasonCredentialScope       = "CREDENTIAL_SCOPE" //nolint:gosec // G101: a reason code, not a credential
	ReasonScopeUnknown          = "CREDENTIAL_SCOPE_UNKNOWN"
	ReasonOverreach             = "CREDENTIAL_OVERREACH"
	ReasonCapability            = "HELD_CAPABILITY"
	ReasonRouteObserveOnly      = "ROUTE_OBSERVE_ONLY"
	ReasonRouteUnknown          = "ROUTE_UNKNOWN"
	ReasonRouteOutside          = "ROUTE_OUTSIDE_CHANNEL"
	ReasonDispatched            = "DISPATCHED"
	ReasonNoLongerAuthorized    = "NO_LONGER_AUTHORIZED"
	ReasonDelegable             = "DELEGABLE"
)

// Right is one thing an agent (or a credential's holder) can do.
type Right struct {
	View  View
	Label Label
	// Agent is nil only for a credential right: every holder of it.
	Agent      *ids.UUID
	Connection *ids.UUID
	Grant      *ids.UUID
	// Operation is empty for a credential scope that names none.
	Operation     string
	ResourceGroup string
	Verb          Verb
	Coverage      Coverage
	Reasons       []string
	Depth         int
	ExpiresAt     *time.Time
	ObservedAt    *time.Time
	Observations  int
	// Basis says why the right has its verb (D45): ACCESS, EFFECT_KIND:<kind>,
	// DEFAULT_UPDATE, DELEGATION or SCOPE_LEVEL.
	Basis string
	// Irreversible flags an operation whose definition is irreversible.
	Irreversible bool
}

// Key identifies a right within a view.
func (r Right) Key() string {
	return string(r.View) + "|" + r.PathKey()
}

// PathKey identifies the path a right travels, whatever the view: the agent
// (or "*"), the connection, the operation or resource group and the verb.
// A posture finding lists the path keys a remediation must reach (HR-255).
func (r Right) PathKey() string {
	return PathKey(r.Agent, r.Connection, r.Operation, r.ResourceGroup, r.Verb)
}

// PathKey builds a path key.
func PathKey(agent, connection *ids.UUID, operation, group string, verb Verb) string {
	a, c := "*", "*"
	if agent != nil {
		a = agent.String()
	}
	if connection != nil {
		c = connection.String()
	}
	return a + "|" + c + "|" + operation + "|" + group + "|" + string(verb)
}

// Operation is what the computation knows of one operation a connection's
// package defines.
type Operation struct {
	Name          string
	Access        defs.Access
	TargetType    string
	Effects       []string
	Reversibility defs.Reversibility
	// Verified reports a verifier the definition declares.
	Verified bool
}

// OperationOf reduces a definition to what exposure reads.
func OperationOf(d defs.Definition) Operation {
	o := Operation{
		Name: d.Operation, Access: d.Access, TargetType: d.Target.Type, Reversibility: d.Reversibility,
		Verified: d.Verifier != nil,
	}
	for _, e := range slices.Concat(d.Effects, d.SideEffects) {
		o.Effects = append(o.Effects, e.Kind)
	}
	return o
}

// Connection is a connection and what reaches through it.
type Connection struct {
	ID               ids.UUID
	Name             string
	State            string // ACTIVE, QUARANTINED, RETIRED
	AccessMode       string // pantherclaw_held, agent_held, target_enforced, none
	DestinationClass string // public, internal
	// Operations are its pinned package's; Known is false when the package
	// could not be read (no pin, undecodable), so reach through it is
	// UNCERTAIN.
	Operations []Operation
	Known      bool
	// RouteAgents are the agents with coverage routes on it. They add
	// holders of agent-held access; they never limit what a grant reaches
	// through the connection (any agent with a grant can call it).
	RouteAgents []ids.UUID
	// Credential is the active credential, if any.
	Credential *CredentialInfo
	// Capabilities the connection's approved declaration says it holds, as
	// "name:level" (empty when none is approved).
	Capabilities []string
}

// CredentialInfo describes the active credential, never its secret.
type CredentialInfo struct {
	Kind      string // static, github_app
	Version   int32
	CreatedAt time.Time
	// Scopes the credential holds at the target ("permission" -> level), as
	// last read; ScopeKnown is false when nothing could be read.
	Scopes     map[string]string
	ScopeKnown bool
	// Overreach is the excess an open coverage finding records.
	Overreach []string
}

// Grant is an active grant with its current revision.
type Grant struct {
	ID              ids.UUID
	Agent           ids.UUID
	Bounds          gdomain.Bounds
	NotBefore       time.Time
	ExpiresAt       time.Time
	DelegationDepth int
	CreatedAt       time.Time
}

// PolicyRule is what exposure reads of a published policy rule.
type PolicyRule struct {
	ID         string
	Kind       string
	Operations []string
	// Unconditional is a rule with no condition, environment or facts.
	Unconditional bool
}

// Policy is the org's published policy.
type Policy struct {
	// Known is false when the published bundle could not be read; every
	// effective right is then CONDITIONAL with POLICY_UNKNOWN.
	Known bool
	Rules []PolicyRule
}

// opMatches reports whether a rule's operation pattern covers op.
func opMatches(pattern, op string) bool {
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(op, p)
	}
	return pattern == op
}

// restriction returns the reason the policy may restrict op, if any.
func (p Policy) restriction(op string) string {
	if !p.Known {
		return ReasonPolicyUnknown
	}
	reason := ""
	for _, r := range p.Rules {
		if r.Kind == "ANNOTATE" || !slices.ContainsFunc(r.Operations, func(x string) bool { return opMatches(x, op) }) {
			continue
		}
		if r.Kind == "FORBID" && r.Unconditional {
			return ReasonPolicyForbid
		}
		reason = ReasonPolicyCondition
	}
	return reason
}

// CoverageKey names a coverage snapshot's path.
type CoverageKey struct {
	Agent      ids.UUID
	Connection ids.UUID
	Operation  string
}

// Route is a coverage route that is not a channel: a way to the target
// outside PantherClaw's decisions (direct API, host, credential, ...).
type Route struct {
	Agent      *ids.UUID
	Connection ids.UUID
	Kind       string
	Operation  string
}

// Dispatch is the observed use of one operation through a connection.
type Dispatch struct {
	Agent      ids.UUID
	Connection ids.UUID
	Operation  string
	Count      int
	Last       time.Time
}

// Inputs are what one computation reads.
type Inputs struct {
	Now         time.Time
	Grants      []Grant
	Connections []Connection
	Policy      Policy
	Coverage    map[CoverageKey]Coverage
	Routes      []Route
	Dispatches  []Dispatch
	// Restrictions are containment controls a preview applies to the
	// effective view (D23, D27). The credential view never changes with
	// them: a control stops decisions, not what a credential can do.
	Restrictions []Restriction
}

// Result is a computation's rights, sorted, with what it could not read.
type Result struct {
	Rights []Right
	Gaps   []string
}

// Compute derives the three views. Duplicate paths within a view keep the
// most usable label and its grant; reasons are merged.
func Compute(in Inputs) Result {
	b := builder{idx: map[string]int{}}
	conns := map[ids.UUID]*Connection{}
	for i := range in.Connections {
		c := &in.Connections[i]
		if c.State == "RETIRED" {
			continue
		}
		conns[c.ID] = c
		if !c.Known {
			b.gap("PACKAGE_UNKNOWN:" + c.ID.String())
		}
	}
	if !in.Policy.Known {
		b.gap("POLICY_UNKNOWN")
	}
	effective(&b, in, conns)
	credential(&b, in, conns)
	observed(&b, in, conns)
	slices.SortFunc(b.out, compareRights)
	slices.Sort(b.gaps)
	return Result{Rights: b.out, Gaps: slices.Compact(b.gaps)}
}

func sortedConns(m map[ids.UUID]*Connection) []*Connection {
	out := make([]*Connection, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b *Connection) int { return cmp.Compare(a.ID.String(), b.ID.String()) })
	return out
}

func ptr[T any](v T) *T { return &v }

// grantAllows reports whether the grant's bounds admit op (operations,
// access class and target type); envelopes only narrow further, so
// leaving them out can only overstate reach.
func grantAllows(b gdomain.Bounds, op Operation) bool {
	if b.Operations != nil && !b.Operations.Matches(op.Name) {
		return false
	}
	if b.Access != nil && op.Access != "" && !b.Access.Matches(string(op.Access)) {
		return false
	}
	if b.Targets != nil && op.TargetType != "" {
		if _, ok := (*b.Targets)[op.TargetType]; !ok {
			return false
		}
	}
	return true
}

func effective(b *builder, in Inputs, conns map[ids.UUID]*Connection) {
	addEff := func(r Right) {
		if r, ok := in.restrict(r); ok {
			b.add(r)
		}
	}
	for _, g := range in.Grants {
		label, reasons := Usable, []string{ReasonGrant}
		var expires *time.Time
		switch {
		case !in.Now.Before(g.ExpiresAt):
			label, reasons = Expired, []string{ReasonGrantExpired}
		case in.Now.Before(g.NotBefore):
			label, reasons = Conditional, []string{ReasonGrantNotYetValid}
		}
		expires = ptr(g.ExpiresAt)
		for _, c := range sortedConns(conns) {
			base, baseReasons := label, slices.Clone(reasons)
			if c.State == "QUARANTINED" && base == Usable {
				base = Conditional
			}
			if c.State == "QUARANTINED" {
				baseReasons = append(baseReasons, ReasonConnectionQuarantined)
			}
			if !c.Known {
				// The package is unknown: whatever the grant allows through
				// this connection is uncertain, never absent.
				l := base
				if l.Rank() < Uncertain.Rank() {
					l = Uncertain
				}
				for _, v := range []Verb{VerbRead, VerbUpdate} {
					addEff(Right{
						View: Effective, Label: l, Agent: ptr(g.Agent), Connection: ptr(c.ID), Grant: ptr(g.ID),
						ResourceGroup: "connection:" + c.Name, Verb: v, Coverage: CoverageUnknown,
						Reasons: append(slices.Clone(baseReasons), ReasonPackageUnknown), ExpiresAt: expires,
					})
				}
				continue
			}
			for _, op := range c.Operations {
				if !grantAllows(g.Bounds, op) {
					continue
				}
				l, rs := base, slices.Clone(baseReasons)
				if why := in.Policy.restriction(op.Name); why != "" {
					rs = append(rs, why)
					if l == Usable {
						l = Conditional
					}
				}
				cov, ok := in.Coverage[CoverageKey{Agent: g.Agent, Connection: c.ID, Operation: op.Name}]
				if !ok {
					cov = CoverageUnknown
				}
				for _, cl := range Classify(op, *c) {
					v := cl.Verb
					addEff(Right{
						View: Effective, Label: l, Agent: ptr(g.Agent), Connection: ptr(c.ID), Grant: ptr(g.ID),
						Operation: op.Name, ResourceGroup: Group(op, *c), Verb: v, Basis: cl.Explain(), Irreversible: op.Reversibility == defs.Irreversible, Coverage: cov, Reasons: rs,
						ExpiresAt: expires,
					})
				}
				if g.DelegationDepth > 0 {
					addEff(Right{
						View: Effective, Label: l, Agent: ptr(g.Agent), Connection: ptr(c.ID), Grant: ptr(g.ID),
						ResourceGroup: Group(op, *c), Verb: VerbDelegate, Basis: BasisDelegation, Coverage: cov,
						Reasons: append(slices.Clone(rs), ReasonDelegable), Depth: g.DelegationDepth, ExpiresAt: expires,
					})
				}
			}
		}
	}
}

// scopeVerbs maps a credential scope level to verbs: read reads; write
// updates; admin (or a level not known) updates and deletes.
func scopeVerbs(level string) []Verb {
	switch level {
	case "read":
		return []Verb{VerbRead}
	case "write":
		return []Verb{VerbRead, VerbUpdate}
	default:
		return []Verb{VerbRead, VerbUpdate, VerbDelete}
	}
}

func credential(b *builder, in Inputs, conns map[ids.UUID]*Connection) {
	for _, c := range sortedConns(conns) {
		cov := func(agent ids.UUID, op string) Coverage {
			if v, ok := in.Coverage[CoverageKey{Agent: agent, Connection: c.ID, Operation: op}]; ok {
				return v
			}
			return CoverageUnknown
		}
		// Agent-held access: the agent uses its own credential at the
		// target, outside every decision; its scope is not known.
		if c.AccessMode == "agent_held" {
			agents := agentsOf(c, in.Grants)
			for _, a := range agents {
				if !c.Known {
					for _, v := range []Verb{VerbRead, VerbUpdate, VerbDelete} {
						b.add(Right{
							View: Credential, Label: Uncertain, Agent: ptr(a), Connection: ptr(c.ID),
							ResourceGroup: "connection:" + c.Name, Verb: v, Coverage: CoverageUnknown,
							Reasons: []string{ReasonAgentHeld, ReasonPackageUnknown},
						})
					}
					continue
				}
				for _, op := range c.Operations {
					for _, cl := range Classify(op, *c) {
						v := cl.Verb
						b.add(Right{
							View: Credential, Label: Uncertain, Agent: ptr(a), Connection: ptr(c.ID), Operation: op.Name,
							ResourceGroup: Group(op, *c), Verb: v, Basis: cl.Explain(), Irreversible: op.Reversibility == defs.Irreversible, Coverage: cov(a, op.Name), Reasons: []string{ReasonAgentHeld},
						})
					}
				}
			}
		}
		// What the connection's credential can do at the target, whoever
		// holds it: its scopes as last read, else uncertain.
		if cr := c.Credential; cr != nil {
			switch {
			case cr.ScopeKnown:
				over := map[string]bool{}
				for _, x := range cr.Overreach {
					k, _, _ := strings.Cut(x, ":")
					over[k] = true
				}
				for _, k := range sortedKeys(cr.Scopes) {
					rs := []string{ReasonCredentialScope}
					if over[k] {
						rs = append(rs, ReasonOverreach)
					}
					for _, v := range scopeVerbs(cr.Scopes[k]) {
						b.add(Right{
							View: Credential, Label: Usable, Connection: ptr(c.ID), ResourceGroup: "scope:" + k, Verb: v,
							Coverage: CoverageUnknown, Reasons: rs,
						})
					}
				}
			default:
				for _, v := range []Verb{VerbRead, VerbUpdate, VerbDelete} {
					b.add(Right{
						View: Credential, Label: Uncertain, Connection: ptr(c.ID), ResourceGroup: "credential:" + c.Name,
						Verb: v, Coverage: CoverageUnknown, Reasons: []string{ReasonScopeUnknown},
					})
				}
			}
		}
		for _, capa := range c.Capabilities {
			k, level, _ := strings.Cut(capa, ":")
			for _, v := range scopeVerbs(level) {
				b.add(Right{
					View: Credential, Label: Usable, Connection: ptr(c.ID), ResourceGroup: "capability:" + k, Verb: v,
					Coverage: CoverageUnknown, Reasons: []string{ReasonCapability},
				})
			}
		}
	}
	// Coverage paths that are observe-only or unknown on an operation a
	// grant reaches: the agent can act there without an enforced decision.
	for _, g := range in.Grants {
		if !in.Now.Before(g.ExpiresAt) {
			continue
		}
		for _, c := range sortedConns(conns) {
			if !c.Known || c.AccessMode == "agent_held" {
				continue
			}
			for _, op := range c.Operations {
				if !grantAllows(g.Bounds, op) {
					continue
				}
				cv, ok := in.Coverage[CoverageKey{Agent: g.Agent, Connection: c.ID, Operation: op.Name}]
				var label Label
				var reason string
				switch {
				case ok && cv == CoverageObserveOnly:
					label, reason = Usable, ReasonRouteObserveOnly
				case !ok || cv == CoverageUnknown:
					label, reason, cv = Uncertain, ReasonRouteUnknown, CoverageUnknown
				default:
					continue
				}
				for _, cl := range Classify(op, *c) {
					v := cl.Verb
					b.add(Right{
						View: Credential, Label: label, Agent: ptr(g.Agent), Connection: ptr(c.ID), Operation: op.Name,
						ResourceGroup: Group(op, *c), Verb: v, Basis: cl.Explain(), Irreversible: op.Reversibility == defs.Irreversible, Coverage: cv, Reasons: []string{reason},
					})
				}
			}
		}
	}
	// Routes outside a channel: direct API, host, git, a credential.
	for _, r := range in.Routes {
		c, ok := conns[r.Connection]
		if !ok || r.Kind == "channel" {
			continue
		}
		var agents []*ids.UUID
		if r.Agent != nil {
			agents = []*ids.UUID{r.Agent}
		} else {
			for _, a := range agentsOf(c, in.Grants) {
				agents = append(agents, ptr(a))
			}
			if len(agents) == 0 {
				agents = []*ids.UUID{nil}
			}
		}
		for _, a := range agents {
			for _, v := range []Verb{VerbRead, VerbUpdate} {
				b.add(Right{
					View: Credential, Label: Uncertain, Agent: a, Connection: ptr(c.ID), Operation: r.Operation,
					ResourceGroup: "route:" + r.Kind, Verb: v, Coverage: CoverageUnknown,
					Reasons: []string{ReasonRouteOutside},
				})
			}
		}
	}
}

// agentsOf lists the agents that may use c: its route agents and every
// agent with a grant (a grant reaches any connection its bounds allow).
func agentsOf(c *Connection, grants []Grant) []ids.UUID {
	seen := map[ids.UUID]bool{}
	var out []ids.UUID
	for _, a := range c.RouteAgents {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, g := range grants {
		if !seen[g.Agent] {
			seen[g.Agent] = true
			out = append(out, g.Agent)
		}
	}
	slices.SortFunc(out, func(a, b ids.UUID) int { return cmp.Compare(a.String(), b.String()) })
	return out
}

func observed(b *builder, in Inputs, conns map[ids.UUID]*Connection) {
	current := map[string]bool{}
	for _, r := range b.out {
		if r.View == Effective && r.Label.Current() {
			current[PathKey(r.Agent, r.Connection, r.Operation, r.ResourceGroup, r.Verb)] = true
		}
	}
	for _, d := range in.Dispatches {
		c, ok := conns[d.Connection]
		op, known := Operation{Name: d.Operation, Access: defs.AccessWrite}, false
		if ok {
			if i := slices.IndexFunc(c.Operations, func(o Operation) bool { return o.Name == d.Operation }); i >= 0 {
				op, known = c.Operations[i], true
			}
		}
		conn := Connection{DestinationClass: "public"}
		group := "operation:" + d.Operation
		if ok {
			conn = *c
		}
		if known {
			group = Group(op, conn)
		}
		for _, cl := range Classify(op, conn) {
			v := cl.Verb
			label, rs := Usable, []string{ReasonDispatched}
			if !known {
				rs = append(rs, ReasonDefinitionUnknown)
			}
			if !current[PathKey(ptr(d.Agent), ptr(d.Connection), d.Operation, group, v)] {
				label, rs = Expired, append(rs, ReasonNoLongerAuthorized)
			}
			b.add(Right{
				View: Observed, Label: label, Agent: ptr(d.Agent), Connection: ptr(d.Connection), Operation: d.Operation,
				ResourceGroup: group, Verb: v, Basis: cl.Explain(), Irreversible: op.Reversibility == defs.Irreversible, Coverage: CoverageUnknown, Reasons: rs, ObservedAt: ptr(d.Last),
				Observations: d.Count,
			})
		}
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

type builder struct {
	out  []Right
	idx  map[string]int
	gaps []string
}

func (b *builder) gap(g string) { b.gaps = append(b.gaps, g) }

func (b *builder) add(r Right) {
	if r.Basis == "" {
		r.Basis = defaultBasis(r)
	}
	k := r.Key()
	i, ok := b.idx[k]
	if !ok {
		r.Reasons = sortedUnique(r.Reasons)
		b.idx[k] = len(b.out)
		b.out = append(b.out, r)
		return
	}
	cur := &b.out[i]
	if r.Label.Rank() < cur.Label.Rank() {
		cur.Label, cur.Grant, cur.ExpiresAt = r.Label, r.Grant, r.ExpiresAt
	}
	if r.Coverage.Rank() < cur.Coverage.Rank() {
		cur.Coverage = r.Coverage // the weakest path's coverage is what a bypass meets
	}
	cur.Depth = max(cur.Depth, r.Depth)
	cur.Irreversible = cur.Irreversible || r.Irreversible
	cur.Observations += r.Observations
	if r.ObservedAt != nil && (cur.ObservedAt == nil || r.ObservedAt.After(*cur.ObservedAt)) {
		cur.ObservedAt = r.ObservedAt
	}
	cur.Reasons = sortedUnique(append(cur.Reasons, r.Reasons...))
}

func sortedUnique(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}

func compareRights(a, b Right) int {
	return cmp.Or(
		cmp.Compare(slices.Index(Views, a.View), slices.Index(Views, b.View)),
		cmp.Compare(a.PathKey(), b.PathKey()),
	)
}

// defaultBasis explains a right no definition classified: a credential
// scope's level, a read's access class, or a write taken as an update.
func defaultBasis(r Right) string {
	switch {
	case slices.Contains(r.Reasons, ReasonCredentialScope) || slices.Contains(r.Reasons, ReasonCapability):
		return BasisScope
	case r.Verb == VerbRead:
		return BasisAccess
	case r.Verb == VerbDelegate:
		return BasisDelegation
	default:
		return BasisDefaultUpdate
	}
}

// ReasonContainedHold marks a write held by a containment control.
const ReasonContainedHold = "CONTAINED_HOLD"

// Restriction is a containment control as a preview applies it: on rights
// of an agent, a connection or a grant (nil fields match any), and of one
// operation when set. Hold holds writes for approval (CONDITIONAL);
// otherwise matching rights are gone (WritesOnly limits it to writes).
type Restriction struct {
	Agent, Connection, Grant *ids.UUID
	Operation                string
	WritesOnly               bool
	Hold                     bool
}

func (x Restriction) matches(r Right) bool {
	switch {
	case x.Agent != nil && (r.Agent == nil || *r.Agent != *x.Agent):
		return false
	case x.Connection != nil && (r.Connection == nil || *r.Connection != *x.Connection):
		return false
	case x.Grant != nil && (r.Grant == nil || *r.Grant != *x.Grant):
		return false
	case x.Operation != "" && r.Operation != x.Operation:
		return false
	case (x.WritesOnly || x.Hold) && r.Verb == VerbRead:
		return false
	}
	return true
}

// restrict applies the restrictions to an effective right; ok is false
// when one removes it.
func (in Inputs) restrict(r Right) (Right, bool) {
	for _, x := range in.Restrictions {
		if !x.matches(r) {
			continue
		}
		if !x.Hold {
			return r, false
		}
		if r.Label == Usable {
			r.Label = Conditional
		}
		r.Reasons = append(slices.Clone(r.Reasons), ReasonContainedHold)
	}
	return r, true
}
