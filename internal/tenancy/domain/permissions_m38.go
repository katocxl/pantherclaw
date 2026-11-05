// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
	"sync"
)

// M38 MSSP partner permissions (G0 M38 D1100, D1100a, D1101; FQ38-1;
// HR-810..816):
//
//   - partner.manage: in a partner org, ask customers for links, renew
//     them, propose rollouts to many customers and withdraw proposals. Org
//     Admin holds it; only a person can exercise it.
//   - partner.approve: in a customer org, decide link requests (on the
//     page, with a security key) and revoke links. Org Admin and Security
//     Admin hold it; only a person can exercise it.
//   - partner.operate: in a partner org, open a partner session in a
//     customer org under an ACTIVE link (on the page, with a security key).
//     Security Admin and Org Admin hold it; custom roles may grant it; only
//     a person can exercise it.
//   - partner.read: in either org, list the links and proposals, and in a
//     partner org the cross-customer summary (counts only). Org Admin,
//     Security Admin and Auditor hold it.
const (
	PermPartnerManage  Permission = "partner.manage"
	PermPartnerApprove Permission = "partner.approve"
	PermPartnerOperate Permission = "partner.operate"
	PermPartnerRead    Permission = "partner.read"
)

// m38PartnerCatalog are the M38 partner permissions in catalog order.
var m38PartnerCatalog = []Permission{PermPartnerManage, PermPartnerApprove, PermPartnerOperate, PermPartnerRead}

// KindPartner is a partner session's principal: a person of an MSSP
// partner org, identified by their user id in that org, inside a customer
// org under an ACTIVE partner link (D1101). Human() and Person() stay
// false, so every human-only path, approvals and step-ups included,
// refuses it (HR-812).
const KindPartner PrincipalKind = "partner"

// Partner reports whether the subject is a partner session.
func (s Subject) Partner() bool { return s.Principal.Kind == KindPartner }

// RolePartnerReadOnly is a partner session's only role: the reads a support
// session holds (FQ38-1), never restricted evidence. Like the support
// roles it is internal: never in Roles(), never bindable, held only by a
// partner subject.
const RolePartnerReadOnly RoleName = "partner_readonly"

// partnerRole is built on first use, after every init has added its
// permissions to the catalog.
var partnerRole = sync.OnceValue(func() Role {
	var perms []Permission
	for _, p := range catalog {
		if strings.HasSuffix(string(p), ".read") && !slices.Contains(supportExcluded, p) && !p.ServiceOnly() &&
			!p.HumanOnly() {
			perms = append(perms, p)
		}
	}
	return Role{
		Name: RolePartnerReadOnly, Title: "MSSP partner (read only)",
		Description: "A partner session under an ACTIVE partner link: the reads a support session holds, never changes, " +
			"never restricted evidence, credentials, sealed material or payload captures (HR-811). Never bindable.",
		Permissions: perms,
	}
})

// partnerRoleForCheck finds the partner role for a partner subject's
// authorization check.
func partnerRoleForCheck(n RoleName) (Role, bool) {
	if n != RolePartnerReadOnly {
		return Role{}, false
	}
	return partnerRole(), true
}

// PartnerReadOnlyPermissions returns a partner session's permissions
// (tests and docs).
func PartnerReadOnlyPermissions() []Permission { return slices.Clone(partnerRole().Permissions) }

func init() {
	catalog = append(catalog, m38PartnerCatalog...)
	humanOnly = append(humanOnly, PermPartnerManage, PermPartnerApprove, PermPartnerOperate)
	for i := range roles {
		r := &roles[i]
		switch r.Name { //nolint:exhaustive // only these roles gain the M38 partner permissions
		case RoleOrgAdmin:
			r.Permissions = append(r.Permissions, PermPartnerManage, PermPartnerApprove, PermPartnerOperate, PermPartnerRead)
			r.Description += " As an MSSP partner, asks customers for partner links and opens partner sessions; as a customer, decides partner links (with a security key) and revokes them."
		case RoleSecurityAdmin:
			r.Permissions = append(r.Permissions, PermPartnerApprove, PermPartnerOperate, PermPartnerRead)
			r.Description += " Decides and revokes partner links (deciding with a security key) and, in a partner org, opens partner sessions."
		case RoleAuditor:
			r.Permissions = append(r.Permissions, PermPartnerRead)
			r.Description += " Reads the partner links, proposals and the partner's customer summary."
		}
	}
}
