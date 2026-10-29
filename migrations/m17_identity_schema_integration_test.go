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

// TestHR469_EntraAudienceOnlyForAzureKinds: an Entra app id may stand in
// for the audience of the azure_mi and entra_agent_id kinds only
// (migration 00211); every other kind keeps pantherclaw:<org> (HR-140).
// Covers: PN-002.3
func TestHR469_EntraAudienceOnlyForAzureKinds(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	const insert = `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience,
		algorithms, binding, state, proposed_by) VALUES ($1, $2, $3, 1, $4, $5, 'https://issuer.example', $6,
		'{RS256}', '{"object_id":"1"}', 'PROPOSED', 'test')`
	const app = "00001111-aaaa-2222-bbbb-3333cccc4444"
	for _, kind := range []string{"azure_mi", "entra_agent_id"} {
		f.mustExec(t, insert, f.org, newID(), newID(), f.agent, kind, app)
		f.mustExec(t, insert, f.org, newID(), newID(), f.agent, kind, "pantherclaw:"+f.org.String())
		for _, aud := range []string{"api://" + app, "pantherclaw:" + newID(), "anything"} {
			f.wantState(t, checkViolation, kind+" audience "+aud, insert, f.org, newID(), newID(), f.agent, kind, aud)
		}
	}
	for _, kind := range []string{"github_actions", "kubernetes", "gitlab_ci", "spiffe_jwt", "gcp_workload", "aws_iam"} {
		f.wantState(t, checkViolation, kind+" with an app id audience", insert, f.org, newID(), newID(), f.agent, kind, app)
	}
}
