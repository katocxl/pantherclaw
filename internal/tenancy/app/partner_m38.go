// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// CredPartnerSession is a partner session of a person of an MSSP partner
// org inside a customer org, under an ACTIVE partner link (G0 M38 D1101).
// Its principal is td.KindPartner, which is never a person here.
const CredPartnerSession Credential = "partner_session"

// PartnerSessionBindings are a partner session's bindings in the customer
// org: the internal partner role only, at the org (HR-811), never anything
// a stored binding could name.
func PartnerSessionBindings(org ids.OrgID) []td.Binding {
	return []td.Binding{{Role: td.RolePartnerReadOnly, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}
}

// PartnerSession reports whether the caller is a partner session.
func (c Caller) PartnerSession() bool {
	return c.Credential == CredPartnerSession && c.Partner()
}
