// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/migrations"
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

// downOf returns the Up and Down sections of a migration file.
func downOf(t *testing.T, name string) (string, string) {
	t.Helper()
	b, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatalf("%s: no Down section", name)
	}
	return up, down
}

// TestM17_IdentityDownsRefuseM17EntriesAndApplyAgain: the Downs of 00211
// and 00210 refuse to run while an entry their narrower CHECKs would
// refuse exists, deleting nothing; on a database without such entries they
// restore the old CHECKs, and the Ups apply again.
// Covers: PN-002.3
func TestM17_IdentityDownsRefuseM17EntriesAndApplyAgain(t *testing.T) {
	ctx := context.Background()
	up210, down210 := downOf(t, "00210_identity_presets.sql")
	up211, down211 := downOf(t, "00211_identity_entra.sql")
	const insert = `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience,
		algorithms, binding, state, proposed_by) VALUES ($1, $2, $3, 1, $4, $5, 'https://issuer.example', $6,
		$7, '{"object_id":"1"}', 'PROPOSED', 'test')`
	for name, row := range map[string]struct {
		kind, aud  string
		algs       []string
		down, fail string
	}{
		"azure kind":      {"azure_mi", "00001111-aaaa-2222-bbbb-3333cccc4444", []string{"RS256"}, down211, ""},
		"gitlab kind":     {"gitlab_ci", "", []string{"RS256"}, down210, down211},
		"five algorithms": {"github_actions", "", []string{"RS256", "RS384", "RS512", "PS256", "PS384"}, down210, down211},
	} {
		t.Run(name, func(t *testing.T) {
			d := dbtest.New(t)
			fx := newFixture(t, d.AppPool(t))
			aud := row.aud
			if aud == "" {
				aud = "pantherclaw:" + fx.org.String()
			}
			fx.mustExec(t, insert, fx.org, newID(), newID(), fx.agent, row.kind, aud, row.algs)
			m := d.Pool(t, d.Migrator)
			if row.fail != "" {
				// The later migration's Down runs first and has nothing to refuse.
				if _, err := m.Pgx().Exec(ctx, row.fail); err != nil {
					t.Fatalf("earlier Down: %v", err)
				}
			}
			_, err := m.Pgx().Exec(ctx, row.down)
			if err == nil || !strings.Contains(err.Error(), "remove the M17 issuer entries first") {
				t.Fatalf("Down with an M17 entry: %v", err)
			}
			var n int
			if err := m.Pgx().QueryRow(ctx, "SELECT count(*) FROM pc.trusted_issuers").Scan(&n); err != nil || n != 1 {
				t.Fatalf("%d entries after the refused Down, %v", n, err)
			}
		})
	}

	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	for _, sql := range []string{down211, down210, up210, up211} {
		if _, err := m.Pgx().Exec(ctx, sql); err != nil {
			t.Fatalf("Down then Up on an empty table: %v", err)
		}
	}
}
