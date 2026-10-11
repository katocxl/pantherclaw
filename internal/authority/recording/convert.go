// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording

import (
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// errRecordedFailure is what a replayed read returns where the original
// read failed: the pipeline treats both as missing evidence.
var errRecordedFailure = errors.New("recording: the original read failed")

func errKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, pipeline.ErrNotFound):
		return errNotFound
	}
	return errFailed
}

func errOf(kind string) error {
	switch kind {
	case "":
		return nil
	case errNotFound:
		return pipeline.ErrNotFound
	case errFailed:
		return errRecordedFailure
	}
	return fmt.Errorf("unknown read outcome %q", kind)
}

func uid(u ids.UUID) string {
	if u.IsZero() {
		return ""
	}
	return u.String()
}

func parseUID(s string) (ids.UUID, error) {
	if s == "" {
		return ids.UUID{}, nil
	}
	return ids.ParseUUID(s)
}

func principalOf(p gdomain.Principal) string {
	if p == (gdomain.Principal{}) {
		return ""
	}
	return string(p.Kind) + ":" + p.ID.String()
}

func parsePrincipal(s string) (gdomain.Principal, error) {
	if s == "" {
		return gdomain.Principal{}, nil
	}
	kind, id, ok := strings.Cut(s, ":")
	if !ok {
		return gdomain.Principal{}, fmt.Errorf("principal %q", s)
	}
	u, err := ids.ParseUUID(id)
	return gdomain.Principal{Kind: gdomain.PrincipalKind(kind), ID: u}, err
}

func parseHash(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(out) {
		return out, fmt.Errorf("hash %q", s)
	}
	copy(out[:], b)
	return out, nil
}

func (r *Recording) identity() (pipeline.Identity, error) {
	inst, err1 := parseUID(r.Request.Instance)
	agent, err2 := parseUID(r.Request.Agent)
	if err := errors.Join(err1, err2); err != nil {
		return pipeline.Identity{}, err
	}
	return pipeline.Identity{InstanceID: inst, AgentID: agent, AttestationLevel: r.Request.Attestation, JKT: r.Request.JKT}, nil
}

func fromContainment(c pipeline.Containment, err error) *Containment {
	return &Containment{Epoch: c.Epoch, KillSwitch: c.KillSwitch, Now: c.Now, Err: errKind(err)}
}

func (c Containment) value() (pipeline.Containment, error) {
	return pipeline.Containment{Epoch: c.Epoch, KillSwitch: c.KillSwitch, Now: c.Now}, errOf(c.Err)
}

func fromPolicy(p *pipeline.Policy, err error) *Policy {
	switch {
	case err != nil:
		return &Policy{Err: errKind(err)}
	case p == nil:
		return &Policy{None: true}
	}
	l := p.Compiled.Limits()
	out := &Policy{
		Ref: p.Version, Bundle: p.Compiled.Bundle.ID, Version: p.Compiled.Bundle.Version, Budget: p.Budget,
		Limits: Limits{
			MaxExpressionBytes: l.MaxExpressionBytes, MaxCost: l.MaxCost, MaxComprehensionNesting: l.MaxComprehensionNesting,
			EstimatedCollectionSize: l.EstimatedCollectionSize,
		},
		Catalog: map[string]string{},
	}
	for name, t := range p.Compiled.Catalog() {
		out.Catalog[name] = string(t)
	}
	return out
}

func fromRun(id ids.UUID, run pipeline.Run, err error) Run {
	out := Run{ID: id.String(), Err: errKind(err)}
	if err != nil {
		return out
	}
	out.Agent, out.Instance, out.Environment = uid(run.AgentID), uid(run.InstanceID), uid(run.EnvironmentID)
	out.Launcher, out.Principal, out.Active, out.TaskRef = principalOf(run.Launcher), principalOf(run.Principal), run.Active, run.TaskRef
	if !run.GrantID.IsZero() {
		out.Grant = run.GrantID.String()
	}
	for _, a := range run.Ancestors {
		out.Ancestors = append(out.Ancestors, principalOf(a))
	}
	return out
}

func (r Run) value() (pipeline.Run, error) {
	if err := errOf(r.Err); err != nil {
		return pipeline.Run{}, err
	}
	var out pipeline.Run
	var errs [7]error
	out.AgentID, errs[0] = parseUID(r.Agent)
	out.InstanceID, errs[1] = parseUID(r.Instance)
	out.EnvironmentID, errs[2] = parseUID(r.Environment)
	out.Launcher, errs[3] = parsePrincipal(r.Launcher)
	out.Principal, errs[4] = parsePrincipal(r.Principal)
	if r.Grant != "" {
		out.GrantID, errs[5] = gdomain.ParseGrantID(r.Grant)
	}
	for _, a := range r.Ancestors {
		p, err := parsePrincipal(a)
		errs[6] = errors.Join(errs[6], err)
		out.Ancestors = append(out.Ancestors, p)
	}
	out.Active, out.TaskRef = r.Active, r.TaskRef
	return out, errors.Join(errs[:]...)
}

func fromAgent(id ids.UUID, a pipeline.Agent, err error) Agent {
	if err != nil {
		return Agent{ID: id.String(), Err: errKind(err)}
	}
	return Agent{ID: id.String(), State: a.State, BusinessUnit: uid(a.BusinessUnitID), Team: uid(a.TeamID)}
}

func (a Agent) value() (pipeline.Agent, error) {
	if err := errOf(a.Err); err != nil {
		return pipeline.Agent{}, err
	}
	bu, err1 := parseUID(a.BusinessUnit)
	team, err2 := parseUID(a.Team)
	return pipeline.Agent{State: a.State, BusinessUnitID: bu, TeamID: team}, errors.Join(err1, err2)
}

func fromGrant(g gdomain.Grant) (Grant, error) {
	bounds, err := gdomain.EncodeBounds(g.Bounds)
	if err != nil {
		return Grant{}, err
	}
	reqs, err := json.Marshal(g.Requirements, json.Deterministic(true))
	if err != nil {
		return Grant{}, err
	}
	lim, err := json.Marshal(g.Limits, json.Deterministic(true))
	if err != nil {
		return Grant{}, err
	}
	out := Grant{
		ID: g.ID.String(), Revision: g.Revision, State: string(g.State), Agent: uid(g.AgentID), Instance: uid(g.InstanceID),
		Principal: principalOf(g.Principal), Environment: uid(g.EnvironmentID), TaskRef: g.TaskRef, NotBefore: g.NotBefore,
		ExpiresAt: g.ExpiresAt, Bounds: bounds, Requirements: reqs, Limits: lim, DelegationDepth: g.Delegation.Depth,
		MaxChildren: g.Delegation.MaxChildren, MinAttestation: g.MinAttestation, Depth: g.Depth, Grantor: principalOf(g.Grantor),
		Basis: g.Basis, RevisedAt: g.RevisedAt,
	}
	if !g.Parent.IsZero() {
		out.Parent = g.Parent.String()
	}
	return out, nil
}

func (g Grant) value(org ids.OrgID) (gdomain.Grant, error) {
	out := gdomain.Grant{
		Org: org, Revision: g.Revision, State: gdomain.State(g.State), TaskRef: g.TaskRef, NotBefore: g.NotBefore,
		ExpiresAt: g.ExpiresAt, Delegation: gdomain.Delegation{Depth: g.DelegationDepth, MaxChildren: g.MaxChildren},
		MinAttestation: g.MinAttestation, Depth: g.Depth, Basis: g.Basis, RevisedAt: g.RevisedAt,
	}
	var errs [10]error
	out.ID, errs[0] = gdomain.ParseGrantID(g.ID)
	out.AgentID, errs[1] = parseUID(g.Agent)
	out.InstanceID, errs[2] = parseUID(g.Instance)
	out.Principal, errs[3] = parsePrincipal(g.Principal)
	out.EnvironmentID, errs[4] = parseUID(g.Environment)
	out.Grantor, errs[5] = parsePrincipal(g.Grantor)
	if g.Parent != "" {
		out.Parent, errs[6] = gdomain.ParseGrantID(g.Parent)
	}
	out.Bounds, errs[7] = gdomain.DecodeBounds(g.Bounds)
	errs[8] = json.Unmarshal(g.Requirements, &out.Requirements, json.RejectUnknownMembers(true))
	out.Limits, errs[9] = gdomain.DecodeLimits(g.Limits)
	return out, errors.Join(errs[:]...)
}

func fromScope(s gdomain.Scope) Scope {
	return Scope{Kind: string(s.Kind), ID: uid(s.ID), Principal: principalOf(s.Principal)}
}

func (s Scope) value() (gdomain.Scope, error) {
	id, err1 := parseUID(s.ID)
	p, err2 := parsePrincipal(s.Principal)
	return gdomain.Scope{Kind: gdomain.ScopeKind(s.Kind), ID: id, Principal: p}, errors.Join(err1, err2)
}

func durationNS(d *time.Duration) *int64 {
	if d == nil {
		return nil
	}
	n := int64(*d)
	return &n
}

func duration(n *int64) *time.Duration {
	if n == nil {
		return nil
	}
	d := time.Duration(*n)
	return &d
}

func fromEnvelope(e gdomain.Envelope) (Envelope, error) {
	bounds, err := gdomain.EncodeBounds(e.Bounds)
	if err != nil {
		return Envelope{}, err
	}
	reqs, err := json.Marshal(e.Requirements, json.Deterministic(true))
	if err != nil {
		return Envelope{}, err
	}
	lim, err := json.Marshal(e.Limits, json.Deterministic(true))
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		ID: e.ID.String(), Revision: e.Revision, Scope: fromScope(e.Scope), Name: e.Name, Bounds: bounds, Requirements: reqs,
		Limits: lim, MaxDepth: e.Settings.MaxDepth, MaxChildren: e.Settings.MaxChildren,
		MaxRootLifetimeNS: durationNS(e.Settings.MaxRootLifetime), RepeatWindowNS: durationNS(e.Settings.RepeatWindow),
		MinAttestation: e.MinAttestation, ChangedBy: e.ChangedBy, RevisedAt: e.RevisedAt,
	}, nil
}

func (e Envelope) value(org ids.OrgID) (gdomain.Envelope, error) {
	out := gdomain.Envelope{
		Org: org, Revision: e.Revision, Name: e.Name, MinAttestation: e.MinAttestation, ChangedBy: e.ChangedBy, RevisedAt: e.RevisedAt,
		Settings: gdomain.Settings{
			MaxDepth: e.MaxDepth, MaxChildren: e.MaxChildren, MaxRootLifetime: duration(e.MaxRootLifetimeNS),
			RepeatWindow: duration(e.RepeatWindowNS),
		},
	}
	var errs [5]error
	out.ID, errs[0] = gdomain.ParseEnvelopeID(e.ID)
	out.Scope, errs[1] = e.Scope.value()
	out.Bounds, errs[2] = gdomain.DecodeBounds(e.Bounds)
	errs[3] = json.Unmarshal(e.Requirements, &out.Requirements, json.RejectUnknownMembers(true))
	out.Limits, errs[4] = gdomain.DecodeLimits(e.Limits)
	return out, errors.Join(errs[:]...)
}

func fromFacts(subjectType, subjectID string, names []string, found map[string]fdomain.Fact, err error) (Facts, error) {
	out := Facts{SubjectType: subjectType, SubjectID: subjectID, Names: slices.Clone(names), Err: errKind(err)}
	if out.Names == nil {
		out.Names = []string{}
	}
	if out.Err != "" { // the read failed: nothing found to keep
		return out, nil
	}
	for _, name := range slices.Sorted(maps.Keys(found)) {
		f := found[name]
		v, err := fdomain.EncodeValue(f.Value)
		if err != nil {
			return Facts{}, err
		}
		out.Facts = append(out.Facts, Fact{
			Name: name, Type: string(f.Value.Type), Value: v, ObservedAt: f.ObservedAt, RecordedAt: f.RecordedAt,
			Provider: uid(f.ProviderID),
		})
	}
	return out, nil
}

func (f Facts) value() (map[string]fdomain.Fact, error) {
	if err := errOf(f.Err); err != nil {
		return nil, err
	}
	out := make(map[string]fdomain.Fact, len(f.Facts))
	for _, x := range f.Facts {
		v, err := fdomain.DecodeValue(fdomain.Type(x.Type), x.Value)
		if err != nil {
			return nil, err
		}
		p, err := parseUID(x.Provider)
		if err != nil {
			return nil, err
		}
		if _, dup := out[x.Name]; dup || !slices.Contains(f.Names, x.Name) {
			return nil, fmt.Errorf("fact %q was not asked for once", x.Name)
		}
		out[x.Name] = fdomain.Fact{
			Name: x.Name, SubjectType: f.SubjectType, SubjectID: f.SubjectID, Value: v, ObservedAt: x.ObservedAt,
			RecordedAt: x.RecordedAt, ProviderID: p,
		}
	}
	return out, nil
}

func fromRef(r bdomain.Ref) Ref {
	return Ref{
		OwnerKind: r.Owner.Kind, OwnerID: r.Owner.ID.String(), OwnerRank: r.Owner.Rank, Rule: r.Rule,
		Key: hex.EncodeToString(r.Key[:]), Start: r.Start,
	}
}

func (r Ref) value() (bdomain.Ref, error) {
	owner, err1 := ids.ParseUUID(r.OwnerID)
	key, err2 := parseHash(r.Key)
	return bdomain.Ref{Owner: bdomain.Owner{Kind: r.OwnerKind, ID: owner, Rank: r.OwnerRank}, Rule: r.Rule, Key: key, Start: r.Start},
		errors.Join(err1, err2)
}

// sameRef compares refs as values: window starts are instants, whatever
// their location.
func sameRef(a, b bdomain.Ref) bool {
	return a.Owner == b.Owner && a.Rule == b.Rule && a.Key == b.Key && a.Start.Equal(b.Start)
}

func fromAccount(ref bdomain.Ref, a bdomain.Account) AccountUsage {
	out := AccountUsage{
		Ref: fromRef(ref), ID: uid(a.ID), Rank: a.Rank, Currency: string(a.Currency), Reserved: a.Reserved.String(),
		Spent: a.Spent.String(), MaxCount: a.MaxCount, ReservedCount: a.ReservedCount, SpentCount: a.SpentCount,
	}
	if a.Limit != nil {
		s := a.Limit.String()
		out.Limit = &s
	}
	return out
}

func (a AccountUsage) value() (bdomain.Account, error) {
	out := bdomain.Account{
		Rank: a.Rank, Currency: money.Currency(a.Currency), MaxCount: a.MaxCount, ReservedCount: a.ReservedCount,
		SpentCount: a.SpentCount,
	}
	var errs [4]error
	out.ID, errs[0] = parseUID(a.ID)
	out.Reserved, errs[1] = money.Parse(a.Reserved)
	out.Spent, errs[2] = money.Parse(a.Spent)
	if a.Limit != nil {
		l, err := money.Parse(*a.Limit)
		out.Limit, errs[3] = &l, err
	}
	return out, errors.Join(errs[:]...)
}

func fromCounter(ref bdomain.Ref, c bdomain.Counter) CounterUsage {
	return CounterUsage{
		Ref: fromRef(ref), ID: uid(c.ID), Rank: c.Rank, Max: c.Max, MaxOutstanding: c.MaxOutstanding, Reserved: c.Reserved,
		Spent: c.Spent,
	}
}

func (c CounterUsage) value() (bdomain.Counter, error) {
	id, err := parseUID(c.ID)
	return bdomain.Counter{ID: id, Rank: c.Rank, Max: c.Max, MaxOutstanding: c.MaxOutstanding, Reserved: c.Reserved, Spent: c.Spent}, err
}

func fromUsage(plan gdomain.Plan, u pipeline.Usage, err error) Usage {
	out := Usage{Err: errKind(err)}
	for _, d := range plan.Budgets {
		out.Budgets = append(out.Budgets, fromRef(d.Ref))
	}
	for _, d := range plan.Counters {
		out.Counters = append(out.Counters, fromRef(d.Ref))
	}
	if err != nil {
		return out
	}
	// In plan order, so the same plan gives the same recording.
	for _, d := range plan.Budgets {
		if a, ok := u.Accounts[d.Ref]; ok {
			out.Accounts = append(out.Accounts, fromAccount(d.Ref, a))
		}
	}
	seen := map[bdomain.Ref]bool{}
	for _, d := range plan.Counters {
		if c, ok := u.Counters[d.Ref]; ok {
			out.CounterUse = append(out.CounterUse, fromCounter(d.Ref, c))
		}
		capRef := d.Ref
		capRef.Key = [32]byte{}
		if n, ok := u.CounterRows[capRef]; ok && !seen[capRef] {
			seen[capRef] = true
			out.CounterRows = append(out.CounterRows, RowCount{Ref: fromRef(capRef), Rows: n})
		}
	}
	return out
}

func fromClaim(key string, c *pipeline.Claim, err error) Claim {
	out := Claim{Key: key, Err: errKind(err)}
	if err == nil && c != nil {
		at := c.At
		out.Transaction, out.State, out.At = c.TransactionID.String(), string(c.State), &at
	}
	return out
}

func (c Claim) value() (*pipeline.Claim, error) {
	if err := errOf(c.Err); err != nil {
		return nil, err
	}
	if c.Transaction == "" {
		if c.State != "" || c.At != nil {
			return nil, errors.New("claim without a transaction")
		}
		return nil, nil //nolint:nilnil // no earlier attempt
	}
	txn, err := ids.ParseUUID(c.Transaction)
	if err != nil || c.At == nil {
		return nil, errors.Join(err, errors.New("claim"))
	}
	return &pipeline.Claim{TransactionID: txn, State: pipeline.ClaimState(c.State), At: *c.At}, nil
}

func fromConnection(id ids.UUID, c pipeline.Connection, err error) Connection {
	if err != nil {
		return Connection{ID: id.String(), Err: errKind(err)}
	}
	return Connection{
		ID: id.String(), Gateway: uid(c.Gateway), Kind: c.Kind, Package: c.Package, State: c.State, AccessMode: c.AccessMode,
		DefaultMode: c.DefaultMode, DestinationClass: c.DestinationClass, Modes: maps.Clone(c.Modes), Reads: slices.Clone(c.Reads),
	}
}

func (c Connection) value() (pipeline.Connection, error) {
	if err := errOf(c.Err); err != nil {
		return pipeline.Connection{}, err
	}
	id, err1 := ids.ParseUUID(c.ID)
	gw, err2 := parseUID(c.Gateway)
	modes := maps.Clone(c.Modes)
	if modes == nil {
		modes = map[string]string{}
	}
	return pipeline.Connection{
		ID: id, Gateway: gw, Kind: c.Kind, Package: c.Package, State: c.State, AccessMode: c.AccessMode,
		DefaultMode: c.DefaultMode, DestinationClass: c.DestinationClass, Modes: modes, Reads: slices.Clone(c.Reads),
	}, errors.Join(err1, err2)
}

func fromHold(run, action ids.UUID, h *pipeline.HoldRequest, err error) Hold {
	out := Hold{Run: run.String(), Action: action.String(), Err: errKind(err)}
	if err != nil || h == nil {
		return out
	}
	out.Request = &HoldRequest{
		ID: h.ID.String(), State: string(h.State), EndReason: h.EndReason, Binding: hex.EncodeToString(h.Binding[:]),
		Deadline: h.Deadline, EvidenceDeadline: h.EvidenceDeadline, ConsumeBy: h.ConsumeBy, Variants: h.Variants,
		Context: h.Context, Question: h.Question, ProposedParams: h.ProposedParams,
	}
	return out
}

func (h Hold) value() (*pipeline.HoldRequest, error) {
	if err := errOf(h.Err); err != nil {
		return nil, err
	}
	r := h.Request
	if r == nil {
		return nil, nil //nolint:nilnil // no request
	}
	id, err1 := ids.ParseUUID(r.ID)
	binding, err2 := parseHash(r.Binding)
	return &pipeline.HoldRequest{
		ID: id, State: apdomain.State(r.State), EndReason: r.EndReason, Binding: binding, Deadline: r.Deadline,
		EvidenceDeadline: r.EvidenceDeadline, ConsumeBy: r.ConsumeBy, Variants: r.Variants, Context: r.Context,
		Question: r.Question, ProposedParams: r.ProposedParams,
	}, errors.Join(err1, err2)
}

// check converts every read back (Decode): a read that failed holds only a
// known outcome, and every other read converts.
func (r Reads) check() error {
	var errs []error
	ok := func(kind string) bool {
		if kind != "" && kind != errNotFound && kind != errFailed {
			errs = append(errs, fmt.Errorf("unknown read outcome %q", kind))
		}
		return kind == ""
	}
	add := func(_ any, err error) { errs = append(errs, err) }
	if c := r.Containment; c != nil && ok(c.Err) {
		add(c.value())
	}
	for _, d := range r.Definitions {
		if ok(d.Err) && (d.Digest == "" || d.Digest != d.Pin.Digest) {
			errs = append(errs, fmt.Errorf("definition %q", d.Pin.Digest))
		}
	}
	if p := r.Policy; p != nil && ok(p.Err) && !p.None && (p.Bundle == "" || p.Version < 1) {
		errs = append(errs, errors.New("policy reference"))
	}
	for _, x := range r.Runs {
		add(ids.ParseUUID(x.ID))
		if ok(x.Err) {
			add(x.value())
		}
	}
	for _, x := range r.Agents {
		add(ids.ParseUUID(x.ID))
		if ok(x.Err) {
			add(x.value())
		}
	}
	for _, c := range r.Chains {
		add(gdomain.ParseGrantID(c.Grant))
		if ok(c.Err) {
			for _, g := range c.Grants {
				add(g.value(ids.OrgID{}))
			}
		}
	}
	for _, e := range r.Envelopes {
		for _, s := range e.Scopes {
			add(s.value())
		}
		if ok(e.Err) {
			for _, x := range e.Envelopes {
				add(x.value(ids.OrgID{}))
			}
		}
	}
	for _, f := range r.Facts {
		if ok(f.Err) {
			add(f.value())
		}
	}
	for _, u := range r.Usage {
		for _, ref := range slices.Concat(u.Budgets, u.Counters) {
			add(ref.value())
		}
		if !ok(u.Err) {
			continue
		}
		for _, a := range u.Accounts {
			add(a.Ref.value())
			add(a.value())
		}
		for _, c := range u.CounterUse {
			add(c.Ref.value())
			add(c.value())
		}
		for _, n := range u.CounterRows {
			add(n.Ref.value())
		}
	}
	for _, c := range r.Claims {
		if ok(c.Err) {
			add(c.value())
		}
	}
	for _, c := range r.Connections {
		add(ids.ParseUUID(c.ID))
		if ok(c.Err) {
			add(c.value())
		}
	}
	for _, h := range r.Holds {
		add(ids.ParseUUID(h.Run))
		add(ids.ParseUUID(h.Action))
		if ok(h.Err) {
			add(h.value())
		}
	}
	for _, v := range r.Variants {
		add(parseHash(v.Key))
		ok(v.Err)
	}
	if h := r.HoldSettings; h != nil {
		ok(h.Err)
	}
	return errors.Join(errs...)
}
