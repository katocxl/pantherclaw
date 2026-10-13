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
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/migrations"
)

// TestHR207_LinksMadeBeforeTheHistoryJoinIt (G0 M8 P2f, review
// 2026-10-13): a GitHub link that existed before 00083_consequences.sql created
// github_identity_history is copied into it, so whoever was linked stays
// excluded as independent after unlinking. The Up section, run as
// pc_migrator after its Down section, copies the link, and the links table
// is forced under row-level security again afterwards.
func TestHR207_LinksMadeBeforeTheHistoryJoinIt(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00083_consequences.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("no Down section")
	}
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	if _, err := m.Pgx().Exec(ctx, down); err != nil {
		t.Fatalf("Down: %v", err)
	}
	org, user := ids.New[ids.Org](), ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'p2f')", org)
	d.AdminExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", org, user)
	d.AdminExec(t, `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by)
		VALUES ($1, $2, $3, 'bob-gh', 42, 'test')`, org, ids.NewV7(), user)
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	var n int
	var forced bool
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.github_identity_history WHERE org_id = $1 AND github_user_id = 42 AND user_id = $2",
		[]any{org, user}, &n)
	d.AdminQueryRow(t, "SELECT relforcerowsecurity FROM pg_class WHERE oid = 'pc.github_identities'::regclass", nil, &forced)
	if n != 1 || !forced {
		t.Fatalf("history rows %d, links forced under RLS %v", n, forced)
	}
}
