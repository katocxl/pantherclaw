// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ScopeType is a level of the hierarchy a role can be bound at.
type ScopeType string

// Scope types, from the root down.
const (
	ScopeOrg          ScopeType = "ORG"
	ScopeBusinessUnit ScopeType = "BUSINESS_UNIT"
	ScopeTeam         ScopeType = "TEAM"
	ScopeEnvironment  ScopeType = "ENVIRONMENT"
)

// Valid reports whether t is a known scope type.
func (t ScopeType) Valid() bool {
	return t == ScopeOrg || t == ScopeBusinessUnit || t == ScopeTeam || t == ScopeEnvironment
}

// Scope is one node of the hierarchy. For ScopeOrg the id is the org id.
type Scope struct {
	Type ScopeType
	ID   ids.UUID
}

// Path lists the scopes from the org down to a resource, for example
// [org, business unit, team, environment]. A binding on any scope of the
// path applies to the resource (inheritance downwards only).
type Path []Scope

// OrgPath is the path of an org-level resource.
func OrgPath(org ids.OrgID) Path { return Path{{Type: ScopeOrg, ID: org.UUID()}} }

// Child returns a new path extended by one scope.
func (p Path) Child(t ScopeType, id ids.UUID) Path {
	out := make(Path, len(p), len(p)+1)
	copy(out, p)
	return append(out, Scope{Type: t, ID: id})
}

// Contains reports whether s is on the path.
func (p Path) Contains(s Scope) bool { return slices.Contains(p, s) }

// PrincipalKind distinguishes humans from service accounts.
type PrincipalKind string

// Principal kinds.
const (
	KindUser           PrincipalKind = "user"
	KindServiceAccount PrincipalKind = "service_account"
)

// PrincipalRef identifies a user or a service account within an org.
type PrincipalRef struct {
	Kind PrincipalKind
	ID   ids.UUID
}

// String renders the reference as "<kind>:<id>" (audit actors, created_by).
func (r PrincipalRef) String() string { return string(r.Kind) + ":" + r.ID.String() }

// Binding is one role at one scope, as loaded for a principal.
type Binding struct {
	Role  RoleName
	Scope Scope
	// BreakGlass is the break-glass activation this binding comes from
	// (G0 M13 D33): set only on a holder's emergency role while their
	// activation is in force; zero for stored bindings.
	BreakGlass ids.UUID
}

// BreakGlassActivation returns the break-glass activation among the
// subject's bindings, if one is in force.
func (s Subject) BreakGlassActivation() (ids.UUID, bool) {
	for _, b := range s.Bindings {
		if !b.BreakGlass.IsZero() {
			return b.BreakGlass, true
		}
	}
	return ids.UUID{}, false
}

// Subject is an authenticated principal with its bindings, ready for
// authorization decisions. It is built per request; nothing is cached.
type Subject struct {
	Org       ids.OrgID
	Principal PrincipalRef
	Bindings  []Binding
	// Scopes restricts the subject to these permissions (API keys). Nil
	// means unrestricted; an empty non-nil slice permits nothing.
	Scopes []Permission
}

// Human reports whether the subject is a person.
func (s Subject) Human() bool { return s.Principal.Kind == KindUser }

// eligible applies the subject-wide restrictions: human-only permissions
// for non-humans, service-only permissions for humans, API key scopes, and gateway permissions (never held by
// users or service accounts).
func (s Subject) eligible(p Permission) bool {
	switch {
	case !p.Known():
		return false
	case p.HumanOnly() && !s.Person():
		return false
	case p.ServiceOnly() && s.Person():
		return false
	case s.Scopes != nil && !slices.Contains(s.Scopes, p):
		return false
	}
	return true
}

// Can reports whether the subject holds p on the resource at path. Unknown
// role names (for example from a newer version) grant nothing.
func (s Subject) Can(p Permission, path Path) bool {
	if !s.eligible(p) || len(path) == 0 || path[0].Type != ScopeOrg || path[0].ID != s.Org.UUID() {
		return false
	}
	for _, b := range s.Bindings {
		if r, ok := s.roleForCheck(b.Role); ok && r.Has(p) && path.Contains(b.Scope) {
			return true
		}
	}
	return false
}

// CanAnywhere reports whether the subject holds p at some scope. The RPC
// interceptor uses it to refuse early; use cases always call Can (or
// Require) with the resource's path.
func (s Subject) CanAnywhere(p Permission) bool {
	if !s.eligible(p) {
		return false
	}
	for _, b := range s.Bindings {
		if r, ok := s.roleForCheck(b.Role); ok && r.Has(p) {
			return true
		}
	}
	return false
}

// Permissions returns the permissions the subject holds anywhere, in catalog
// order ("who am I").
func (s Subject) Permissions() []Permission {
	var out []Permission
	for _, p := range catalog {
		if s.CanAnywhere(p) {
			out = append(out, p)
		}
	}
	return out
}

// ErrPermissionDenied is returned when a subject lacks a permission. The
// message names the permission, never the resource (no existence oracle
// beyond what NotFound already gives).
func ErrPermissionDenied(p Permission) error {
	return pcerr.New(pcerr.PermissionDenied, "PERMISSION_DENIED", "missing permission "+string(p))
}

// Require returns ErrPermissionDenied unless s.Can(p, path).
func (s Subject) Require(p Permission, path Path) error {
	if !s.Can(p, path) {
		return ErrPermissionDenied(p)
	}
	return nil
}
