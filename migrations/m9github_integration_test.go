// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// TestHR211_AGitHubInstallationChangeIsACredentialChange: recording the
// GitHub App installation behind a connection, changing its permissions,
// account or repository selection, or removing it records a credential
// invalidation in the same transaction; reading it again unchanged records
// none (G0 M9 slice A9, migration 00092).
func TestHR211_AGitHubInstallationChangeIsACredentialChange(t *testing.T) {
	d := dbtest.New(t)
	f := m9cFixture{m7Fixture: newM7Fixture(t, d.AppPool(t)), version: m5ID()}
	steps := []struct {
		name, want, sql string
		admin           bool
	}{
		{"recorded", "credential", `INSERT INTO pc.connection_github (org_id, connection_id, app_client_id, installation_id,
			account_login, permissions, repository_selection, read_at, updated_by)
			VALUES ($1, $2, 'Iv1.abc', 42, 'acme', '{"contents": "read"}', 'all', now(), 'test')`, false},
		{"read again, unchanged", "", `UPDATE pc.connection_github SET read_at = now() + interval '1 minute', updated_by = 'scan',
			updated_at = now() WHERE org_id = $1 AND connection_id = $2`, false},
		{"permissions widened", "credential", `UPDATE pc.connection_github SET permissions = '{"contents": "write"}'
			WHERE org_id = $1 AND connection_id = $2`, false},
		{"repositories selected", "credential", `UPDATE pc.connection_github SET repository_selection = 'selected'
			WHERE org_id = $1 AND connection_id = $2`, false},
		{"removed", "credential", `DELETE FROM pc.connection_github WHERE org_id = $1 AND connection_id = $2`, true},
	}
	var want []string
	for _, s := range steps {
		if s.admin {
			d.AdminExec(t, s.sql, f.org, f.connection)
		} else {
			f.mustExec(t, s.sql, f.org, f.connection)
		}
		if s.want != "" {
			want = append(want, s.want)
		}
		if got := f.m9iKinds(t); !slices.Equal(got, want) {
			t.Fatalf("after %s: invalidations %v, want %v", s.name, got, want)
		}
	}
}
