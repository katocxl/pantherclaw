// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
)

// M13 support access and break-glass (G0 M13 D32, D33, D38; HR-385..389).
//
//   - support.read: see the org's support requests and grants.
//   - support.manage: revoke support grants; approving and denying a
//     request also need a person's security-key step-up on its page
//     (HR-386), so a service account holding Org Admin can revoke but
//     never approve.
//   - breakglass.read: see the break-glass holders and activations.
//   - breakglass.manage: designate holders and end any activation.
const (
	PermSupportRead      Permission = "support.read"
	PermSupportManage    Permission = "support.manage"
	PermBreakGlassRead   Permission = "breakglass.read"
	PermBreakGlassManage Permission = "breakglass.manage"
)

// m13SupportCatalog are the permissions in catalog order.
var m13SupportCatalog = []Permission{PermSupportRead, PermSupportManage, PermBreakGlassRead, PermBreakGlassManage}

// KindSupport is a support session's principal: a member of the
// operator's support staff, identified by their hosted account, inside a
// customer's org under an approved support grant (D32). It is a person for
// the human-only permission checks only; Human() stays users-only, so no
// code path that reads a user row ever sees it.
const KindSupport PrincipalKind = "support"

// Person reports whether the subject is a person: a user or support staff.
func (s Subject) Person() bool { return s.Human() || s.Principal.Kind == KindSupport }

// Support reports whether the subject is a support session.
func (s Subject) Support() bool { return s.Principal.Kind == KindSupport }

// The support roles (D32, D38) are internal: they are never in Roles(),
// LookupRole never finds them, so no binding can ever name them, and only
// a support session's subject holds them, from its grant.
const (
	// RoleSupportReadOnly is every read except restricted evidence
	// (HR-387).
	RoleSupportReadOnly RoleName = "support_readonly"
	// RoleSupportEvidence adds restricted evidence, for a grant whose scope
	// is READ_ONLY_PLUS_EVIDENCE.
	RoleSupportEvidence RoleName = "support_restricted_evidence"
)

// supportExcluded are the reads a support session never holds, whatever
// its scope adds: none today beyond restricted evidence, which only the
// evidence scope adds.
var supportExcluded = []Permission{PermEvidenceReadRestricted}

// supportReads is every grantable read permission ("*.read") except the
// excluded ones.
func supportReads() []Permission {
	var out []Permission
	for _, p := range catalog {
		if strings.HasSuffix(string(p), ".read") && !slices.Contains(supportExcluded, p) && !p.ServiceOnly() {
			out = append(out, p)
		}
	}
	return out
}

var internalRoles = []Role{
	{
		Name: RoleSupportReadOnly, Title: "Support (read only)",
		Description: "A support session under an approved support grant: reads, never changes, never restricted evidence, credentials, sealed material or payload captures (HR-387). Never bindable.",
		Permissions: supportReads(),
	},
	{
		Name: RoleSupportEvidence, Title: "Support (restricted evidence)",
		Description: "Adds restricted evidence to a support session whose grant's scope is READ_ONLY_PLUS_EVIDENCE. Never bindable.",
		Permissions: []Permission{PermEvidenceReadRestricted},
	},
}

// roleForCheck finds a role for an authorization check: the default roles
// and, for a support subject only, the internal support roles.
func (s Subject) roleForCheck(n RoleName) (Role, bool) {
	if r, ok := LookupRole(n); ok {
		return r, true
	}
	if !s.Support() {
		return Role{}, false
	}
	i := slices.IndexFunc(internalRoles, func(r Role) bool { return r.Name == n })
	if i < 0 {
		return Role{}, false
	}
	return internalRoles[i], true
}

// SupportRoleNames are the internal roles of a support grant's scope.
func SupportRoleNames(withEvidence bool) []RoleName {
	if withEvidence {
		return []RoleName{RoleSupportReadOnly, RoleSupportEvidence}
	}
	return []RoleName{RoleSupportReadOnly}
}

// SupportReadOnlyPermissions returns the permissions of a support session
// (tests and docs).
func SupportReadOnlyPermissions(withEvidence bool) []Permission {
	out := slices.Clone(internalRoles[0].Permissions)
	if withEvidence {
		out = append(out, PermEvidenceReadRestricted)
	}
	return out
}

// BreakGlassRoleAllowed reports whether r may be a break-glass holder's
// emergency role (D33): a default role bindable at the org, held by
// people, never org_admin.
func BreakGlassRoleAllowed(n RoleName) bool {
	r, ok := LookupRole(n)
	return ok && n != RoleOrgAdmin && !r.ServiceOnly && r.BindableAt(ScopeOrg)
}

func init() {
	for i := range roles {
		r := &roles[i]
		switch r.Name { //nolint:exhaustive // only these roles gain the M13 support permissions
		case RoleOrgAdmin:
			r.Permissions = append(r.Permissions, m13SupportCatalog...)
			r.Description += " Approves, denies and revokes the support staff's access requests (approving and denying with a security key) and designates the break-glass holders."
		case RoleSecurityAdmin, RoleAuditor:
			r.Permissions = append(r.Permissions, PermSupportRead, PermBreakGlassRead)
			r.Description += " Reads the support access requests and grants and the break-glass holders and activations."
		}
	}
}
