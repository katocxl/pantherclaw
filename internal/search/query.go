// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package search is permission-safe structured search (G0 M10 D34; F304,
// F306, F317, F627; HR-257, T-042). A query names one entity and typed
// filters, or one built-in investigative query and its parameters; there is
// no free text and nothing a caller writes ever becomes SQL. Every search
// runs under the viewer's own permissions: rows the viewer may not read are
// filtered in the database before paging and counting, so neither the rows
// nor the counts include them (D8). Results state their scope, evidence
// range, freshness and permission-derived omissions, and an empty result
// says why it is empty.
package search

import (
	"regexp"
	"slices"
	"strings"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Entity is what a structured query searches.
type Entity string

// Entities searchable in this release (G0 M10 D34; G0 M11 part 2 D44).
const (
	EntityTransactions   Entity = "transactions"
	EntityRuns           Entity = "runs"
	EntityAgents         Entity = "agents"
	EntityGrants         Entity = "grants"
	EntityGrantChanges   Entity = "grant_changes"
	EntityConnections    Entity = "connections"
	EntityApprovals      Entity = "approvals"
	EntityAudit          Entity = "audit"
	EntityOperations     Entity = "operations"
	EntityAlerts         Entity = "alerts"
	EntityIncidents      Entity = "incidents"
	EntityCases          Entity = "cases"
	EntityFindings       Entity = "findings"
	EntityPolicyVersions Entity = "policy_versions"
	EntityPackages       Entity = "packages"
	EntityGateways       Entity = "gateways"
)

// entities lists the entities a structured query may name.
var entities = []Entity{
	EntityTransactions, EntityRuns, EntityAgents, EntityGrants, EntityGrantChanges, EntityConnections,
	EntityApprovals, EntityAudit, EntityOperations, EntityAlerts, EntityIncidents, EntityCases, EntityFindings,
	EntityPolicyVersions, EntityPackages, EntityGateways,
}

// Filters are the typed filters of a structured query. Each entity accepts
// only the filters listed for it in allowedFilters; anything else is
// refused, never ignored.
type Filters struct {
	ID              *ids.UUID  `json:"id,omitzero"`
	Agent           *ids.UUID  `json:"agent,omitzero"`
	Run             *ids.UUID  `json:"run,omitzero"`
	Grant           *ids.UUID  `json:"grant,omitzero"`
	Connection      *ids.UUID  `json:"connection,omitzero"`
	Gateway         *ids.UUID  `json:"gateway,omitzero"`
	Alert           *ids.UUID  `json:"alert,omitzero"`
	Incident        *ids.UUID  `json:"incident,omitzero"`
	Team            *ids.UUID  `json:"team,omitzero"`
	PrincipalUser   *ids.UUID  `json:"principal_user,omitzero"`
	PrincipalSA     *ids.UUID  `json:"principal_service_account,omitzero"`
	UsedConnection  *ids.UUID  `json:"used_connection,omitzero"`
	Operation       string     `json:"operation,omitzero"`
	OperationPrefix string     `json:"operation_prefix,omitzero"`
	TargetType      string     `json:"target_type,omitzero"`
	EffectPrefix    string     `json:"effect_prefix,omitzero"`
	KindPrefix      string     `json:"kind_prefix,omitzero"`
	Actor           string     `json:"actor,omitzero"`
	Decisions       []string   `json:"decisions,omitzero"`
	Modes           []string   `json:"modes,omitzero"`
	States          []string   `json:"states,omitzero"`
	Kinds           []string   `json:"kinds,omitzero"`
	AccessModes     []string   `json:"access_modes,omitzero"`
	EnvKinds        []string   `json:"environment_kinds,omitzero"`
	Severities      []string   `json:"severities,omitzero"`
	EffectStates    []string   `json:"effect_states,omitzero"`
	UnusedSince     *time.Time `json:"unused_since,omitzero"`
	WidensOnly      bool       `json:"widens_only,omitzero"`
	Start           *time.Time `json:"start,omitzero"`
	End             *time.Time `json:"end,omitzero"`
}

// Query is one structured query.
type Query struct {
	Entity  Entity  `json:"entity"`
	Filters Filters `json:"filters,omitzero"`
}

// Limits on filter values.
const (
	maxListValues = 16
	maxTextLen    = 200
	// MaxCount is where counts stop: a count above it reads "more than
	// 10000".
	MaxCount = 10000
	// liveLag is how far before the as-of time a range's end must lie for
	// the range to be stable: newer ranges are marked changing.
	liveLag = 5 * time.Minute
)

var (
	opRe     = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,7}$`)
	prefixRe = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,199}$`)
	codeRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	actorRe  = regexp.MustCompile(`^[A-Za-z0-9_:.@-]{1,200}$`)
)

// ErrInvalidQuery reports a malformed query; the message names the field.
func ErrInvalidQuery(msg string) error {
	return pcerr.New(pcerr.InvalidArgument, "INVALID_QUERY", msg)
}

// field names a filter for allowedFilters.
type field string

const (
	fID, fAgent, fRun, fGrant, fConnection, fGateway, fTeam                  field = "id", "agent", "run", "grant", "connection", "gateway", "team"
	fPrincipal, fUsedConnection, fOperation, fTargetType, fEffect, fKind     field = "principal", "used_connection", "operation", "target_type", "effect_prefix", "kind_prefix"
	fActor, fDecisions, fModes, fStates, fKinds, fAccessModes, fEnv, fUnused field = "actor", "decisions", "modes", "states", "kinds", "access_modes", "environment_kinds", "unused_since"
	fWidens, fRange, fAlert, fIncident, fSeverities, fEffectStates           field = "widens_only", "range", "alert", "incident", "severities", "effect_states"
)

// allowedFilters lists, per entity, the filters it accepts.
var allowedFilters = map[Entity][]field{
	EntityTransactions: {fID, fAgent, fRun, fGrant, fConnection, fPrincipal, fOperation, fTargetType, fDecisions, fModes, fEffectStates, fEnv, fRange},
	EntityRuns:         {fID, fAgent, fGrant, fPrincipal, fStates, fRange},
	EntityAgents:       {fID, fTeam, fStates, fEnv, fUsedConnection, fRange},
	EntityGrants:       {fID, fAgent, fPrincipal, fStates, fUnused, fRange},
	EntityGrantChanges: {fAgent, fGrant, fWidens, fRange},
	EntityConnections:  {fID, fGateway, fStates, fKinds, fAccessModes, fRange},
	EntityApprovals:    {fID, fAgent, fRun, fOperation, fStates, fRange},
	EntityAudit:        {fID, fKind, fActor, fRange},
	EntityOperations:   {fOperation, fEffect},
	// An alert's kinds are its sources; a finding's are its finding kinds.
	EntityAlerts:         {fID, fAgent, fIncident, fStates, fSeverities, fKinds, fRange},
	EntityIncidents:      {fID, fAgent, fStates, fSeverities, fRange},
	EntityCases:          {fID, fAgent, fAlert, fIncident, fStates, fRange},
	EntityFindings:       {fID, fAgent, fConnection, fGrant, fStates, fKinds, fSeverities, fRange},
	EntityPolicyVersions: {fID, fStates, fRange},
	EntityPackages:       {fID, fStates, fRange},
	EntityGateways:       {fID, fStates, fRange},
}

// used lists the filters f sets.
func (f Filters) used() []field {
	var out []field
	add := func(set bool, n field) {
		if set {
			out = append(out, n)
		}
	}
	add(f.ID != nil, fID)
	add(f.Agent != nil, fAgent)
	add(f.Run != nil, fRun)
	add(f.Grant != nil, fGrant)
	add(f.Connection != nil, fConnection)
	add(f.Gateway != nil, fGateway)
	add(f.Alert != nil, fAlert)
	add(f.Incident != nil, fIncident)
	add(f.Team != nil, fTeam)
	add(f.PrincipalUser != nil || f.PrincipalSA != nil, fPrincipal)
	add(f.UsedConnection != nil, fUsedConnection)
	add(f.Operation != "" || f.OperationPrefix != "", fOperation)
	add(f.TargetType != "", fTargetType)
	add(f.EffectPrefix != "", fEffect)
	add(f.KindPrefix != "", fKind)
	add(f.Actor != "", fActor)
	add(len(f.Decisions) > 0, fDecisions)
	add(len(f.Modes) > 0, fModes)
	add(len(f.States) > 0, fStates)
	add(len(f.Kinds) > 0, fKinds)
	add(len(f.AccessModes) > 0, fAccessModes)
	add(len(f.EnvKinds) > 0, fEnv)
	add(len(f.Severities) > 0, fSeverities)
	add(len(f.EffectStates) > 0, fEffectStates)
	add(f.UnusedSince != nil, fUnused)
	add(f.WidensOnly, fWidens)
	add(f.Start != nil || f.End != nil, fRange)
	return out
}

// Validate checks q: a known entity, only the filters it accepts, and
// bounded, well-formed values.
func (q Query) Validate() error {
	allowed, ok := allowedFilters[q.Entity]
	if !ok {
		return ErrInvalidQuery("unknown entity")
	}
	for _, f := range q.Filters.used() {
		if !slices.Contains(allowed, f) {
			return ErrInvalidQuery("filter " + string(f) + " does not apply to " + string(q.Entity))
		}
	}
	return q.Filters.validate()
}

func (f Filters) validate() error {
	switch {
	case f.PrincipalUser != nil && f.PrincipalSA != nil:
		return ErrInvalidQuery("principal: a user or a service account, not both")
	case f.Operation != "" && f.OperationPrefix != "":
		return ErrInvalidQuery("operation: exact or prefix, not both")
	case f.Operation != "" && !opRe.MatchString(f.Operation):
		return ErrInvalidQuery("operation is malformed")
	case f.OperationPrefix != "" && !prefixRe.MatchString(f.OperationPrefix):
		return ErrInvalidQuery("operation_prefix is malformed")
	case f.EffectPrefix != "" && !prefixRe.MatchString(f.EffectPrefix):
		return ErrInvalidQuery("effect_prefix is malformed")
	case f.KindPrefix != "" && (!prefixRe.MatchString(f.KindPrefix) || !strings.HasPrefix(f.KindPrefix, "audit.")):
		return ErrInvalidQuery("kind_prefix must start with audit.")
	case f.TargetType != "" && !prefixRe.MatchString(f.TargetType):
		return ErrInvalidQuery("target_type is malformed")
	case f.Actor != "" && !actorRe.MatchString(f.Actor):
		return ErrInvalidQuery("actor is malformed")
	case f.Start != nil && f.End != nil && !f.End.After(*f.Start):
		return ErrInvalidQuery("range: end must be after start")
	}
	for name, vs := range map[string][]string{
		"decisions": f.Decisions, "modes": f.Modes, "states": f.States, "kinds": f.Kinds,
		"access_modes": f.AccessModes, "environment_kinds": f.EnvKinds, "severities": f.Severities, "effect_states": f.EffectStates,
	} {
		if len(vs) > maxListValues {
			return ErrInvalidQuery(name + ": too many values")
		}
		for _, v := range vs {
			if !codeRe.MatchString(v) {
				return ErrInvalidQuery(name + ": malformed value")
			}
		}
	}
	return nil
}

// list returns vs, never nil (sqlc array parameters).
func list(vs []string) []string {
	if vs == nil {
		return []string{}
	}
	return vs
}
