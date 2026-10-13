// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for G0 M8 track P
// (migration 00082): the application enforces the same rules first. Names
// are prefixed m8p so that they never collide with other milestones'
// schema tests in this package.

const m8pWindow = `INSERT INTO pc.change_windows (org_id, id, environment, repository, time_zone, weekly, revision, created_by)
	VALUES ($1, $2, $3, $4, 'Europe/London', '[{"day":"mon","start":"09:00","minutes":480}]', $5, 'test')`

// TestHR207_OneActiveChangeWindowPerEnvironmentAndRepository: an
// environment and a repository have at most one ACTIVE window, and each
// revision once; an environment is stored in lowercase; a retired window
// names who retired it and when. pc_app only retires a window, once: it
// never makes a retired window ACTIVE again, never changes what a window
// allows, and never deletes one.
func TestHR207_OneActiveChangeWindowPerEnvironmentAndRepository(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	first := m5ID()
	f.mustExec(t, m8pWindow, f.org, first, "production", nil, 1)
	f.mustExec(t, m8pWindow, f.org, m5ID(), "production", "acme/payments", 1) // a repository's own window
	f.mustExec(t, m8pWindow, f.org, m5ID(), "staging", nil, 1)
	f.want(t, m5Unique, "a second active window", m8pWindow, f.org, m5ID(), "production", nil, 2)
	f.want(t, m5Check, "a repository not in lowercase", m8pWindow, f.org, m5ID(), "production", "Acme/Payments", 1)
	f.want(t, m5Check, "a control in the environment", m8pWindow, f.org, m5ID(), "prod\nuction", nil, 1)
	f.want(t, m5Check, "an environment not in lowercase", m8pWindow, f.org, m5ID(), "Production", nil, 1)
	f.want(t, m5Check, "retired without who", "UPDATE pc.change_windows SET state = 'RETIRED', retired_at = now() WHERE id = $1", first)
	f.mustExec(t, "UPDATE pc.change_windows SET state = 'RETIRED', retired_at = now(), retired_by = 'test' WHERE id = $1", first)
	f.want(t, m5Check, "a retired window made ACTIVE again",
		"UPDATE pc.change_windows SET state = 'ACTIVE', retired_at = NULL, retired_by = NULL WHERE id = $1", first)
	f.want(t, m5Check, "a retirement rewritten", "UPDATE pc.change_windows SET retired_by = 'someone else' WHERE id = $1", first)
	f.want(t, m5Unique, "a revision again", m8pWindow, f.org, m5ID(), "production", nil, 1)
	f.mustExec(t, m8pWindow, f.org, m5ID(), "production", nil, 2)
	f.want(t, m5Denied, "change the weekly entries", "UPDATE pc.change_windows SET weekly = '[]'")
	f.want(t, m5Denied, "change the environment", "UPDATE pc.change_windows SET environment = 'staging'")
	f.want(t, m5Denied, "DELETE change_windows", "DELETE FROM pc.change_windows")
}
