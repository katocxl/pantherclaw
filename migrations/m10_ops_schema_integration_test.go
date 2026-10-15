// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestM10Ops_SavedQueriesAndMetricSamplesGrants (G0 M10 D33, D34, 00125):
// pc_app may change a saved query's name, description, visibility, team
// and specification only, never its owner or times; metric samples are
// insert-only. RLS is forced on both.
func TestM10Ops_SavedQueriesAndMetricSamplesGrants(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	updatable := map[string][]string{
		"saved_queries":  {"name", "description", "visibility", "team_id", "spec"},
		"metric_samples": nil,
	}
	deletable := map[string]bool{"saved_queries": true}
	for table, allowed := range updatable {
		rows, err := m.Pgx().Query(ctx, `SELECT column_name FROM information_schema.columns
			WHERE table_schema = 'pc' AND table_name = $1 ORDER BY ordinal_position`, table)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		rows.Close()
		if len(cols) < 5 {
			t.Fatalf("%s has %d columns", table, len(cols))
		}
		for _, c := range cols {
			var got bool
			if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_app', 'pc.' || $1, $2, 'UPDATE')`, table, c).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if want := slices.Contains(allowed, c); got != want {
				t.Errorf("pc_app UPDATE on pc.%s.%s = %v, want %v", table, c, got, want)
			}
		}
		var del, forced bool
		if err := m.Pgx().QueryRow(ctx, `SELECT has_table_privilege('pc_app', 'pc.' || $1, 'DELETE'),
			(SELECT relforcerowsecurity FROM pg_class WHERE oid = ('pc.' || $1)::regclass)`, table).Scan(&del, &forced); err != nil {
			t.Fatal(err)
		}
		if del != deletable[table] || !forced {
			t.Errorf("pc.%s: pc_app DELETE %v, RLS forced %v", table, del, forced)
		}
	}
}

func m10Org(t *testing.T, p *db.Pool) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'm10')", org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return org
}

func m10Exec(p *db.Pool, org ids.OrgID, sql string, args ...any) error {
	return p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func m10Count(t *testing.T, p *db.Pool, org ids.OrgID, sql string) int {
	t.Helper()
	var n int
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestTenancy_saved_queries: another org neither reads nor changes an
// org's saved queries.
func TestTenancy_saved_queries(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := m10Org(t, p), m10Org(t, p)
	owner := "user:" + ids.NewV7().String()
	if err := m10Exec(p, a, `INSERT INTO pc.saved_queries (org_id, id, owner, name, visibility, spec)
		VALUES ($1, $2, $3, 'denials', 'ORG', '{"builtin":{"builtin":"denials"}}')`, a, ids.NewV7(), owner); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, b, "SELECT count(*) FROM pc.saved_queries"); n != 0 {
		t.Fatalf("another org sees %d saved queries", n)
	}
	if err := m10Exec(p, b, "UPDATE pc.saved_queries SET name = 'mine'"); err != nil {
		t.Fatal(err)
	}
	if err := m10Exec(p, b, "DELETE FROM pc.saved_queries"); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, a, "SELECT count(*) FROM pc.saved_queries WHERE name = 'denials'"); n != 1 {
		t.Fatalf("our saved query changed: %d", n)
	}
	if err := m10Exec(p, b, `INSERT INTO pc.saved_queries (org_id, id, owner, name, visibility, spec)
		VALUES ($1, $2, $3, 'x', 'ORG', '{}')`, a, ids.NewV7(), owner); err == nil {
		t.Fatal("inserted into another org")
	}
	// A TEAM query names its team; ORG and PRIVATE ones none.
	if err := m10Exec(p, a, `INSERT INTO pc.saved_queries (org_id, id, owner, name, visibility, spec)
		VALUES ($1, $2, $3, 'team', 'TEAM', '{}')`, a, ids.NewV7(), owner); err == nil {
		t.Fatal("TEAM query without a team")
	}
}

// TestTenancy_metric_samples: another org neither reads an org's samples
// nor writes into it; a sample is a value or an explicit "not collected",
// on an hour boundary, once per metric, dimension and hour.
func TestTenancy_metric_samples(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := m10Org(t, p), m10Org(t, p)
	ins := `INSERT INTO pc.metric_samples (org_id, id, metric, bucket, value, collected) VALUES ($1, $2, 'coverage.enforced', $3, $4, $5)`
	hour := "2026-10-15T10:00:00Z"
	if err := m10Exec(p, a, ins, a, ids.NewV7(), hour, 3.0, true); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, b, "SELECT count(*) FROM pc.metric_samples"); n != 0 {
		t.Fatalf("another org sees %d samples", n)
	}
	if err := m10Exec(p, b, ins, a, ids.NewV7(), "2026-10-15T11:00:00Z", 1.0, true); err == nil {
		t.Fatal("inserted into another org")
	}
	for name, args := range map[string][]any{
		"duplicate hour":            {a, ids.NewV7(), hour, 4.0, true},
		"off the hour":              {a, ids.NewV7(), "2026-10-15T10:30:00Z", 1.0, true},
		"a value not collected":     {a, ids.NewV7(), "2026-10-15T12:00:00Z", 1.0, false},
		"collected without a value": {a, ids.NewV7(), "2026-10-15T13:00:00Z", nil, true},
	} {
		if err := m10Exec(p, a, ins, args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := m10Exec(p, a, ins, a, ids.NewV7(), "2026-10-15T14:00:00Z", nil, false); err != nil {
		t.Errorf("not collected: %v", err)
	}
}
