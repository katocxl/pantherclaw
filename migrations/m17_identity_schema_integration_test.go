// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// TestHR140_OnlyPresetKindsInSchema: the M17 presets are accepted kinds
// (migration 00210); any other kind is refused by the schema too.
// Covers: PN-002.3
func TestHR140_OnlyPresetKindsInSchema(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	const insert = `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience,
		algorithms, binding, state, proposed_by) VALUES ($1, $2, $3, 1, $4, $5, 'https://issuer.example', $6,
		'{RS256}', '{"project_id":"1"}', 'PROPOSED', 'test')`
	aud := "pantherclaw:" + f.org.String()
	for _, kind := range []string{"gitlab_ci", "spiffe_jwt", "gcp_workload", "aws_iam"} {
		f.mustExec(t, insert, f.org, newID(), newID(), f.agent, kind, aud)
	}
	for _, kind := range []string{"oidc", "custom", "GITLAB_CI", ""} {
		f.wantState(t, checkViolation, "kind "+kind, insert, f.org, newID(), newID(), f.agent, kind, aud)
	}
}
