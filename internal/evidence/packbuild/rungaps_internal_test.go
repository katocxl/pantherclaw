// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestRunPackCoverageGapsNeedCoverageRead: a run's pack lists its coverage
// and telemetry gaps only for a creator holding coverage.read where the
// run's agent lives; otherwise one gap says they are left out, with no
// count (D21a, rows26 D25).
// Covers: F065, F227, F229
func TestRunPackCoverageGapsNeedCoverageRead(t *testing.T) {
	org, run := ids.New[ids.Org](), ids.NewV7()
	path := td.OrgPath(org)
	caller := func(scopes ...td.Permission) tenancy.Caller {
		return tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
			Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
			Scopes:   scopes,
		}}
	}
	if g := coverageGapsOmitted(caller(), path, run); g != nil {
		t.Errorf("an auditor: %+v", g)
	}
	g := coverageGapsOmitted(caller(td.PermEvidenceRead, td.PermEvidenceExport), path, run)
	if g == nil || g.Subject != "run "+run.String() || g.Reason != "coverage_gaps_omitted" ||
		g.Detail != "the pack's creator cannot read coverage where the run's agent lives" {
		t.Errorf("without coverage.read: %+v", g)
	}
	elsewhere := td.Path{{Type: td.ScopeOrg, ID: org.UUID()}, {Type: td.ScopeTeam, ID: ids.NewV7()}}
	team := caller()
	team.Bindings[0].Scope = td.Scope{Type: td.ScopeTeam, ID: ids.NewV7()}
	if coverageGapsOmitted(team, elsewhere, run) == nil {
		t.Error("coverage.read held only on another team")
	}
}
