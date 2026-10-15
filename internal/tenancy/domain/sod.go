// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"

// Separation-of-duties primitives (F581–F583). Approval-time checks
// (initiator ≠ approver, two distinct approvers) build on Distinct in M5.

// Errors returned by the SoD checks.
var (
	ErrUnknownRole       = pcerr.New(pcerr.InvalidArgument, "UNKNOWN_ROLE", "unknown role")
	ErrHumanOnlyRole     = pcerr.New(pcerr.FailedPrecondition, "HUMAN_ONLY_ROLE", "this role can only be bound to users")
	ErrServiceOnlyRole   = pcerr.New(pcerr.FailedPrecondition, "SERVICE_ONLY_ROLE", "this role can only be bound to service accounts")
	ErrScopeNotAllowed   = pcerr.New(pcerr.InvalidArgument, "SCOPE_NOT_ALLOWED", "this role cannot be bound at that scope")
	ErrLastOrgAdmin      = pcerr.New(pcerr.FailedPrecondition, "LAST_ORG_ADMIN", "the organization must keep at least one active Org Admin")
	ErrHumanOnlyScope    = pcerr.New(pcerr.InvalidArgument, "HUMAN_ONLY_SCOPE", "API keys cannot carry human-only permissions")
	ErrUnknownPermission = pcerr.New(pcerr.InvalidArgument, "UNKNOWN_PERMISSION", "unknown permission")
)

// CheckBindable validates binding role at scope type t to a principal of
// kind k: the role must exist, allow that scope, and must not contain a
// human-only permission when bound to a service account; a service-only
// role is never bound to a user (G0 M10 D4).
func CheckBindable(role RoleName, k PrincipalKind, t ScopeType) (Role, error) {
	r, ok := LookupRole(role)
	if !ok {
		return Role{}, ErrUnknownRole
	}
	if !t.Valid() || !r.BindableAt(t) {
		return Role{}, ErrScopeNotAllowed
	}
	if k == KindUser && r.ServiceOnly {
		return Role{}, ErrServiceOnlyRole
	}
	if k != KindUser && r.HumanOnly() {
		return Role{}, ErrHumanOnlyRole
	}
	return r, nil
}

// CheckAPIKeyScopes validates API key scopes: known, not human-only, no
// duplicates.
func CheckAPIKeyScopes(scopes []Permission) error {
	if len(scopes) == 0 || len(scopes) > 64 {
		return pcerr.New(pcerr.InvalidArgument, "INVALID_SCOPES", "an API key needs 1-64 scopes")
	}
	seen := map[Permission]bool{}
	for _, p := range scopes {
		switch {
		case !p.Known():
			return ErrUnknownPermission
		case p.HumanOnly():
			return ErrHumanOnlyScope
		case seen[p]:
			return pcerr.New(pcerr.InvalidArgument, "DUPLICATE_SCOPE", "duplicate scope "+string(p))
		}
		seen[p] = true
	}
	return nil
}

// Distinct reports whether a and b are different principals. Approval
// checks use it so that an initiator cannot satisfy their own independent
// approval requirement.
func Distinct(a, b PrincipalRef) bool { return a.Kind != b.Kind || a.ID != b.ID }

// SelfGrant reports whether actor is granting a role to itself. Self-grants
// are allowed (founder decision 2026-10-08, ADR-0016) and always audited
// with self_grant=true.
func SelfGrant(actor, subject PrincipalRef) bool { return !Distinct(actor, subject) }
