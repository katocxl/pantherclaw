// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Builtin names a built-in investigative query (F306–F315).
type Builtin string

// Built-in queries over search's own tables; who_can_write (F308) and
// widest_exposure (F313) read the exposure views (exposure.go).
const (
	BuiltinProductionAccess      Builtin = "production_access"        // F306
	BuiltinWhyAllowed            Builtin = "why_allowed"              // F307
	BuiltinToolCapability        Builtin = "tool_capability"          // F309
	BuiltinUnusedGrants          Builtin = "unused_grants"            // F310
	BuiltinActionsForPrincipal   Builtin = "actions_for_principal"    // F311
	BuiltinConnectionDependents  Builtin = "connection_dependents"    // F312
	BuiltinDenials               Builtin = "denials"                  // F314
	BuiltinRecentAuthorityChange Builtin = "recent_authority_changes" // F315
)

// Params are a built-in query's parameters; each query reads only its own
// and refuses the rest.
type Params struct {
	Transaction   *ids.UUID  `json:"transaction,omitzero"`
	Agent         *ids.UUID  `json:"agent,omitzero"`
	Connection    *ids.UUID  `json:"connection,omitzero"`
	PrincipalUser *ids.UUID  `json:"principal_user,omitzero"`
	PrincipalSA   *ids.UUID  `json:"principal_service_account,omitzero"`
	Effect        string     `json:"effect,omitzero"`
	TargetType    string     `json:"target_type,omitzero"`
	Resource      string     `json:"resource,omitzero"`
	Days          int        `json:"days,omitzero"`
	Start         *time.Time `json:"start,omitzero"`
	End           *time.Time `json:"end,omitzero"`
}

// BuiltinQuery is one built-in query with its parameters.
type BuiltinQuery struct {
	Name   Builtin `json:"builtin"`
	Params Params  `json:"params,omitzero"`
}

// Limits on built-in parameters.
const (
	defaultUnusedDays = 30
	maxUnusedDays     = 365
	defaultRecent     = 7 * 24 * time.Hour
)

// BuiltinInfo describes a built-in query for listings.
type BuiltinInfo struct {
	Name        Builtin
	Feature     string
	Description string
	Params      []string
}

// Builtins lists the built-in queries, in catalog order.
func Builtins() []BuiltinInfo {
	return []BuiltinInfo{
		{BuiltinProductionAccess, "F306", "Actions by agents in production environments, attempts apart from confirmed effects.", []string{"agent", "start", "end"}},
		{BuiltinWhyAllowed, "F307", "One transaction with links to the conditions retained when it was decided.", []string{"transaction"}},
		{BuiltinToolCapability, "F309", "Operations able to cause an effect (for example funds.), verified apart from unclassified.", []string{"effect"}},
		{BuiltinUnusedGrants, "F310", "Active grants with no recorded use in the last N days (default 30).", []string{"agent", "days"}},
		{BuiltinActionsForPrincipal, "F311", "Actions performed for a represented person or service account, never its launcher.", []string{"principal_user", "principal_service_account", "start", "end"}},
		{BuiltinConnectionDependents, "F312", "Agents that used a connection, with what PantherClaw cannot see.", []string{"connection", "start", "end"}},
		{BuiltinDenials, "F314", "Denied actions, enforced denials apart from shadow predictions.", []string{"agent", "connection", "target_type", "start", "end"}},
		{BuiltinRecentAuthorityChange, "F315", "New and widened grants, material changes apart from narrowing or metadata.", []string{"agent", "start", "end"}},
		{BuiltinWhoCanWrite, "F308", "Agents able to write a resource group or through a connection, grant-constrained authority apart from technical reach.", []string{"resource", "connection"}},
		{BuiltinWidestExposure, "F313", "Agents ranked by widest exposure on explicit keys: consequence, scope, usability, enforceability, ownership, remediation readiness.", []string{}},
	}
}

// expand turns b into the structured query it runs, plus the omissions it
// always carries. now anchors default windows.
func (b BuiltinQuery) expand(now time.Time) (Query, []Omission, error) {
	p := b.Params
	allowed := map[Builtin][]string{}
	for _, i := range Builtins() {
		allowed[i.Name] = i.Params
	}
	names, ok := allowed[b.Name]
	if !ok {
		return Query{}, nil, ErrInvalidQuery("unknown built-in query")
	}
	for _, used := range p.used() {
		if !slices.Contains(names, used) {
			return Query{}, nil, ErrInvalidQuery("parameter " + used + " does not apply to " + string(b.Name))
		}
	}
	unobserved := Omission{
		Code:   omissionUnobservedUse,
		Detail: "use through routes PantherClaw does not observe (OBSERVE_ONLY or UNKNOWN coverage) is not recorded",
	}
	switch b.Name {
	case BuiltinProductionAccess:
		return Query{Entity: EntityTransactions, Filters: Filters{
			Agent: p.Agent, EnvKinds: []string{"PRODUCTION"}, Start: p.Start, End: p.End,
		}}, []Omission{unobserved}, nil
	case BuiltinWhyAllowed:
		if p.Transaction == nil {
			return Query{}, nil, ErrInvalidQuery("transaction is required")
		}
		return Query{Entity: EntityTransactions, Filters: Filters{ID: p.Transaction}}, nil, nil
	case BuiltinToolCapability:
		if p.Effect == "" {
			return Query{}, nil, ErrInvalidQuery("effect is required")
		}
		return Query{Entity: EntityOperations, Filters: Filters{EffectPrefix: p.Effect}}, nil, nil
	case BuiltinUnusedGrants:
		days := p.Days
		if days == 0 {
			days = defaultUnusedDays
		}
		if days < 1 || days > maxUnusedDays {
			return Query{}, nil, ErrInvalidQuery("days must be between 1 and 365")
		}
		since := now.Add(-time.Duration(days) * 24 * time.Hour)
		return Query{Entity: EntityGrants, Filters: Filters{
			Agent: p.Agent, States: []string{"ACTIVE"}, UnusedSince: &since,
		}}, []Omission{unobserved}, nil
	case BuiltinActionsForPrincipal:
		if (p.PrincipalUser == nil) == (p.PrincipalSA == nil) {
			return Query{}, nil, ErrInvalidQuery("one of principal_user or principal_service_account is required")
		}
		return Query{Entity: EntityTransactions, Filters: Filters{
			PrincipalUser: p.PrincipalUser, PrincipalSA: p.PrincipalSA, Start: p.Start, End: p.End,
		}}, nil, nil
	case BuiltinConnectionDependents:
		if p.Connection == nil {
			return Query{}, nil, ErrInvalidQuery("connection is required")
		}
		return Query{Entity: EntityAgents, Filters: Filters{UsedConnection: p.Connection, Start: p.Start, End: p.End}},
			[]Omission{{
				Code:   omissionUnknownDependents,
				Detail: "workloads that hold the connection's credential or reach its target directly are not listed",
			}}, nil
	case BuiltinDenials:
		return Query{Entity: EntityTransactions, Filters: Filters{
			Agent: p.Agent, Connection: p.Connection, TargetType: p.TargetType,
			Decisions: []string{"DENY", "CANNOT_AUTHORIZE"}, Start: p.Start, End: p.End,
		}}, nil, nil
	case BuiltinRecentAuthorityChange:
		start := p.Start
		if start == nil {
			s := now.Add(-defaultRecent)
			start = &s
		}
		return Query{Entity: EntityGrantChanges, Filters: Filters{Agent: p.Agent, Start: start, End: p.End}}, nil, nil
	case BuiltinWhoCanWrite, BuiltinWidestExposure:
		return Query{}, nil, ErrInvalidQuery(string(b.Name) + " reads the exposure views, not a structured query")
	default:
		return Query{}, nil, ErrInvalidQuery("unknown built-in query")
	}
}

func (p Params) used() []string {
	var out []string
	add := func(set bool, n string) {
		if set {
			out = append(out, n)
		}
	}
	add(p.Transaction != nil, "transaction")
	add(p.Agent != nil, "agent")
	add(p.Connection != nil, "connection")
	add(p.PrincipalUser != nil, "principal_user")
	add(p.PrincipalSA != nil, "principal_service_account")
	add(p.Effect != "", "effect")
	add(p.TargetType != "", "target_type")
	add(p.Resource != "", "resource")
	add(p.Days != 0, "days")
	add(p.Start != nil, "start")
	add(p.End != nil, "end")
	return out
}

// RunBuiltin runs a built-in query under the caller's permissions.
func (s *Service) RunBuiltin(ctx context.Context, b BuiltinQuery, pr page.Request) (Result, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Result{}, err
	}
	if !c.CanAnywhere(PermSearch) {
		return Result{}, td.ErrPermissionDenied(PermSearch)
	}
	if exposureBuiltin(b.Name) {
		return s.runExposure(ctx, b, pr)
	}
	q, notes, err := b.expand(s.now())
	if err != nil {
		return Result{}, err
	}
	if err := q.Validate(); err != nil {
		return Result{}, err
	}
	var out Result
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.run(ctx, c, tx, q, pr)
		return err
	}, db.ReadOnly())
	if err != nil {
		return Result{}, err
	}
	out.Omissions = append(out.Omissions, notes...)
	return out, nil
}
