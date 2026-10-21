// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Support grant scopes (G0 M13 D32).
const (
	SupportScopeReadOnly         = "READ_ONLY"
	SupportScopeReadPlusEvidence = "READ_ONLY_PLUS_EVIDENCE"
)

// SupportScopeBindings are the internal support roles of one grant scope,
// at the org (HR-387): never anything a stored binding could name.
func SupportScopeBindings(org ids.OrgID, scope string) []td.Binding {
	var out []td.Binding
	for _, r := range td.SupportRoleNames(scope == SupportScopeReadPlusEvidence) {
		out = append(out, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
	}
	return out
}

// SupportBindings are a support principal's bindings in org: the support
// roles of the account's grants in force, nothing without one (HR-385).
// A support session itself uses its own grant's scope only.
func SupportBindings(ctx context.Context, q *dbq.Queries, org ids.OrgID, account ids.UUID) ([]td.Binding, error) {
	scopes, err := q.LiveSupportScopesOfAccount(ctx, org, account)
	if err != nil {
		return nil, err
	}
	scope := ""
	for _, s := range scopes {
		if scope == "" || s == SupportScopeReadPlusEvidence {
			scope = s
		}
	}
	if scope == "" {
		return nil, nil
	}
	return SupportScopeBindings(org, scope), nil
}
