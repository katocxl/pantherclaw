// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/migrations"
)

// These tests check the schema's second line of defense for retention and
// legal holds (G0 M7 slice B8, migration 00072, HR-198, HR-055): the
// application enforces the same rules first. Names are prefixed m7r so that
// they never collide with other milestones' schema tests in this package.

const (
	m7rPolicy = `INSERT INTO pc.retention_policies (org_id, id, category, revision, days, set_by, effective_from)
		VALUES ($1, $2, $3, $4, $5, $6, now() + $7::interval)`
	m7rHold = `INSERT INTO pc.legal_holds (org_id, id, scope, scope_id, range_start, range_end, reason, created_by)
		VALUES ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz, 'litigation', $7)`
	m7rJWS = "eyJhbGciOiJFZERTQSJ9.e30.sig"
)

// m7rEvidenceTables are the evidence tables pc_app may only insert into and
// read (HR-055): the ledger and its chain, receipts, observations, replay
// inputs, approval notes, tiles, checkpoints, anchor leaves and the
// retention policy revisions.
var m7rEvidenceTables = []string{
	"ledger_entries", "ledger_chain", "decision_receipts", "execution_receipts", "effect_receipts", "observations",
	"evaluation_inputs", "approval_evidence", "ledger_tiles", "checkpoints", "anchor_leaves", "retention_policies",
}

// TestHR055_PcAppCannotUpdateOrDeleteAnyEvidenceTable (M7 part): pc_app
// holds no UPDATE on any column and no DELETE on any evidence table, and
// the statements are refused.
func TestHR055_PcAppCannotUpdateOrDeleteAnyEvidenceTable(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	for _, table := range m7rEvidenceTables {
		var update, del, truncate bool
		d.AdminQueryRow(t, `SELECT has_any_column_privilege('pc_app', $1, 'UPDATE'), has_table_privilege('pc_app', $1, 'DELETE'),
			has_table_privilege('pc_app', $1, 'TRUNCATE')`, []any{"pc." + table}, &update, &del, &truncate)
		if update || del || truncate {
			t.Errorf("pc_app on %s: UPDATE=%v DELETE=%v TRUNCATE=%v, want none (HR-055)", table, update, del, truncate)
		}
		f.want(t, m5Denied, "pc_app deletes from "+table, "DELETE FROM pc."+table)
	}
	f.want(t, m5Denied, "pc_app nulls a ledger body", "UPDATE pc.ledger_entries SET body = NULL")
	f.want(t, m5Denied, "pc_app nulls a receipt", "UPDATE pc.decision_receipts SET receipt_jws = NULL")
	f.want(t, m5Denied, "pc_app nulls observed values", "UPDATE pc.observations SET fields = NULL")
	f.want(t, m5Denied, "pc_app nulls an approval note", "UPDATE pc.approval_evidence SET note = NULL")
	f.want(t, m5Denied, "pc_app rewrites a policy", "UPDATE pc.retention_policies SET days = 3650")
	f.want(t, m5Denied, "pc_app deletes a hold", "DELETE FROM pc.legal_holds")
}

// TestHR198_RetentionRoleHasOnlyItsGrants: pc_retention logs in without
// any privileged attribute, and its privileges are exactly: UPDATE of the
// body columns and their tombstones, DELETE of replay inputs, INSERT of
// its own ledger entries, and SELECT of what it reads to choose items.
func TestHR198_RetentionRoleHasOnlyItsGrants(t *testing.T) {
	d := dbtest.New(t)
	var login, super, bypass, inherit, createRole bool
	d.AdminQueryRow(t, `SELECT rolcanlogin, rolsuper, rolbypassrls, rolinherit, rolcreaterole FROM pg_roles WHERE rolname = 'pc_retention'`,
		nil, &login, &super, &bypass, &inherit, &createRole)
	if !login || super || bypass || inherit || createRole {
		t.Fatalf("pc_retention: login=%v super=%v bypassrls=%v inherit=%v createrole=%v", login, super, bypass, inherit, createRole)
	}
	cols := func(privilege string) []string {
		t.Helper()
		var out []string
		d.AdminQueryRow(t, `SELECT coalesce(array_agg(table_name || '.' || column_name ORDER BY table_name, column_name), '{}')
			FROM information_schema.column_privileges
			WHERE grantee = 'pc_retention' AND table_schema = 'pc' AND privilege_type = $1`, []any{privilege}, &out)
		return out
	}
	updates := []string{
		"approval_evidence.body_removed_at", "approval_evidence.note", "approval_evidence.removed_by_policy",
		"decision_receipts.body_removed_at", "decision_receipts.receipt_jws", "decision_receipts.removed_by_policy",
		"effect_receipts.body_removed_at", "effect_receipts.receipt_jws", "effect_receipts.removed_by_policy",
		"execution_receipts.body_removed_at", "execution_receipts.receipt_jws", "execution_receipts.removed_by_policy",
		"ledger_entries.body", "ledger_entries.body_removed_at", "ledger_entries.removed_by_policy",
		"observations.body_removed_at", "observations.fields", "observations.removed_by_policy",
	}
	if got := cols("UPDATE"); !slices.Equal(got, updates) {
		t.Errorf("pc_retention UPDATE columns = %v, want %v", got, updates)
	}
	inserts := []string{
		"ledger_entries.actor_id", "ledger_entries.actor_type", "ledger_entries.body", "ledger_entries.id",
		"ledger_entries.kind", "ledger_entries.org_id",
	}
	if got := cols("INSERT"); !slices.Equal(got, inserts) {
		t.Errorf("pc_retention INSERT columns = %v, want %v", got, inserts)
	}
	for _, c := range cols("SELECT") {
		if strings.HasSuffix(c, ".reason") || strings.HasSuffix(c, ".release_reason") || strings.HasPrefix(c, "evaluation_inputs.inputs") ||
			strings.HasSuffix(c, ".receipt_jws") || strings.HasSuffix(c, ".note") || strings.HasPrefix(c, "observations.fields") {
			t.Errorf("pc_retention reads %s, which it never needs", c)
		}
	}
	var tables []string
	d.AdminQueryRow(t, `SELECT coalesce(array_agg(table_name || ':' || privilege_type ORDER BY table_name, privilege_type), '{}')
		FROM information_schema.table_privileges WHERE grantee = 'pc_retention' AND table_schema = 'pc'`, nil, &tables)
	if want := []string{"evaluation_inputs:DELETE", "retention_policies:SELECT"}; !slices.Equal(tables, want) {
		t.Errorf("pc_retention table privileges = %v, want %v", tables, want)
	}
}

// TestHR198_RetentionRoleCanOnlyNullBodies: as pc_retention, a body can
// only be removed (nulled, with its tombstone), once; nothing else of an
// evidence row changes, and chain links, checkpoints and ledger rows are
// never deleted.
func TestHR198_RetentionRoleCanOnlyNullBodies(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	r := m5Fixture{p: d.Pool(t, d.Retention), org: f.org}
	entry := f.ledger(t)
	f.mustExec(t, `INSERT INTO pc.ledger_chain (org_id, seq, entry_id, prev_hash, entry_hash) VALUES ($1, 1, $2, $3, $4)`,
		f.org, entry, m6Bytes(32, 0), m6Bytes(32, 1))
	f.mustExec(t, `INSERT INTO pc.decision_receipts (org_id, transaction_id, receipt_jws, ledger_entry_id) VALUES ($1, $2, $3, $4)`,
		f.org, f.txn, m7rJWS, f.ledger(t))
	policy := m5ID()

	r.want(t, m5Check, "a body rewritten", "UPDATE pc.ledger_entries SET body = '\\x7b2261223a317d' WHERE id = $1", entry)
	r.want(t, m5Check, "a tombstone without removing the body",
		"UPDATE pc.ledger_entries SET body_removed_at = now(), removed_by_policy = $2 WHERE id = $1", entry, policy)
	r.want(t, m5Check, "a body removed without its policy",
		"UPDATE pc.ledger_entries SET body = NULL, body_removed_at = now() WHERE id = $1", entry)
	r.want(t, m5Denied, "a kind changed", "UPDATE pc.ledger_entries SET kind = 'receipt.other' WHERE id = $1", entry)
	r.want(t, m5Denied, "an entry's time changed", "UPDATE pc.ledger_entries SET occurred_at = now() WHERE id = $1", entry)
	r.mustExec(t, "UPDATE pc.ledger_entries SET body = NULL, body_removed_at = now(), removed_by_policy = $2 WHERE id = $1", entry, policy)
	r.want(t, m5Check, "a removal again", "UPDATE pc.ledger_entries SET body = NULL, body_removed_at = now(), removed_by_policy = $2 WHERE id = $1",
		entry, m5ID())

	r.want(t, m5Check, "a receipt rewritten", "UPDATE pc.decision_receipts SET receipt_jws = 'eyJ.x.y'")
	r.mustExec(t, "UPDATE pc.decision_receipts SET receipt_jws = NULL, body_removed_at = now(), removed_by_policy = $1", policy)
	r.want(t, m5Check, "a removed receipt rebuilt",
		"UPDATE pc.decision_receipts SET receipt_jws = $1, body_removed_at = NULL, removed_by_policy = NULL", m7rJWS)

	for _, table := range []string{"ledger_entries", "ledger_chain", "decision_receipts", "checkpoints", "ledger_tiles", "anchor_leaves", "observations", "approval_evidence"} {
		r.want(t, m5Denied, "pc_retention deletes from "+table, "DELETE FROM pc."+table)
	}
	r.want(t, m5Denied, "a chain link changed", "UPDATE pc.ledger_chain SET entry_hash = entry_hash")
	r.want(t, m5Denied, "a checkpoint changed", "UPDATE pc.checkpoints SET note = note")
	r.want(t, m5Denied, "a policy recorded by the job", m7rPolicy, f.org, m5ID(), "receipts", 2, 400, nil, "0 seconds")
	r.want(t, m5Denied, "a hold released by the job", "UPDATE pc.legal_holds SET state = 'RELEASED'")
	r.want(t, m5Denied, "a hold's reason read by the job", "SELECT reason FROM pc.legal_holds")
	r.want(t, m5Denied, "replay inputs read by the job", "SELECT inputs FROM pc.evaluation_inputs")
	r.mustExec(t, "DELETE FROM pc.evaluation_inputs WHERE created_at < now()")

	// pc_app still sees the tombstone; a row is never recorded removed.
	f.want(t, m5Check, "an entry inserted removed", `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id,
		body, body_removed_at, removed_by_policy) VALUES ($1, $2, 'receipt.test', 'test', 'test', NULL, now(), $3)`, f.org, m5ID(), policy)
	var removed int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries WHERE body IS NULL AND removed_by_policy = $1`, policy).Scan(&removed)
	}); err != nil || removed != 1 {
		t.Fatalf("removed entries = %d, %v", removed, err)
	}

	// Another org's rows are invisible to the job.
	other := m5Fixture{p: d.Pool(t, d.Retention), org: ids.New[ids.Org]()}
	var n int
	if err := other.p.InTenantTx(context.Background(), other.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_entries").Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("pc_retention sees %d entries of another org (%v)", n, err)
	}
}

// TestHR198_PoliciesAndHoldsInSchema: periods stay within their bounds,
// revisions are consecutive and immutable, a shorter period takes effect
// at least 7 days after it is recorded, and holds have a scope and a
// reason and change only by being released.
func TestHR198_PoliciesAndHoldsInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	f.want(t, m5Check, "payloads kept 31 days", m7rPolicy, f.org, m5ID(), "payloads", 1, 31, nil, "0 seconds")
	f.want(t, m5Check, "receipts kept 29 days", m7rPolicy, f.org, m5ID(), "receipts", 1, 29, nil, "0 seconds")
	f.want(t, m5Check, "approvals kept 364 days", m7rPolicy, f.org, m5ID(), "approvals", 1, 364, nil, "0 seconds")
	f.want(t, m5Check, "security audit kept 3651 days", m7rPolicy, f.org, m5ID(), "security_audit", 1, 3651, nil, "0 seconds")
	f.want(t, m5Check, "an unknown category", m7rPolicy, f.org, m5ID(), "versions", 1, 365, nil, "0 seconds")
	f.want(t, m5Check, "a default that takes effect later", m7rPolicy, f.org, m5ID(), "receipts", 1, 365, nil, "1 day")
	f.want(t, m5Check, "a revision effective before it was recorded", m7rPolicy, f.org, m5ID(), "receipts", 1, 365, f.user, "-1 second")
	f.want(t, m5Check, "a first revision shorter than the default at once", m7rPolicy, f.org, m5ID(), "receipts", 1, 30, f.user, "0 seconds")
	f.mustExec(t, m7rPolicy, f.org, m5ID(), "receipts", 1, 365, nil, "0 seconds")
	f.want(t, m5Check, "a revision skipped", m7rPolicy, f.org, m5ID(), "receipts", 3, 400, f.user, "0 seconds")
	f.want(t, m5Check, "a revision twice", m7rPolicy, f.org, m5ID(), "receipts", 1, 400, f.user, "0 seconds")
	f.want(t, m5Check, "a shortening at once", m7rPolicy, f.org, m5ID(), "receipts", 2, 30, f.user, "0 seconds")
	f.want(t, m5Check, "a shortening after 6 days", m7rPolicy, f.org, m5ID(), "receipts", 2, 30, f.user, "6 days")
	f.mustExec(t, m7rPolicy, f.org, m5ID(), "receipts", 2, 30, f.user, "7 days")
	f.mustExec(t, m7rPolicy, f.org, m5ID(), "receipts", 3, 400, f.user, "0 seconds")
	f.want(t, m5Denied, "a revision changed", "UPDATE pc.retention_policies SET effective_from = now()")

	f.want(t, m5Check, "a transaction hold without its transaction", m7rHold, f.org, m5ID(), "transaction", nil, nil, nil, f.user)
	f.want(t, m5Check, "an org hold naming a transaction", m7rHold, f.org, m5ID(), "org", f.txn, nil, nil, f.user)
	f.want(t, m5Check, "a time range that ends before it starts", m7rHold, f.org, m5ID(), "time_range", nil,
		"2026-10-10T00:00:00Z", "2026-10-09T00:00:00Z", f.user)
	f.want(t, m5Check, "an unknown scope", m7rHold, f.org, m5ID(), "connection", f.txn, nil, nil, f.user)
	hold := m5ID()
	f.mustExec(t, m7rHold, f.org, hold, "transaction", f.txn, nil, nil, f.user)
	f.want(t, m5Check, "released without who and why", "UPDATE pc.legal_holds SET state = 'RELEASED', released_at = now() WHERE id = $1", hold)
	f.want(t, m5Denied, "a hold's scope changed", "UPDATE pc.legal_holds SET scope = 'org' WHERE id = $1", hold)
	f.mustExec(t, `UPDATE pc.legal_holds SET state = 'RELEASED', released_by = $2, released_at = now(), release_reason = 'settled'
		WHERE id = $1`, hold, f.user)
}

// TestHR198_HoldsCoverTheirScope: pc.retention_held, as the job calls it,
// finds an item inside an active org, time range, agent, run or
// transaction hold through the transaction, the run, the agent or the
// approval request it relates to, and never inside a released one.
func TestHR198_HoldsCoverTheirScope(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	r := m5Fixture{p: d.Pool(t, d.Retention), org: f.org}
	request := f.request(t, 1)
	held := func(at string, ref any) bool {
		t.Helper()
		var out bool
		if err := r.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT pc.retention_held($1::timestamptz, $2::uuid)", at, ref).Scan(&out)
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	const at = "2026-10-01T12:00:00Z"
	if held(at, f.txn) || held(at, nil) {
		t.Fatal("held without any hold")
	}
	release := func(id string) {
		f.mustExec(t, `UPDATE pc.legal_holds SET state = 'RELEASED', released_by = $2, released_at = now(),
			release_reason = 'done' WHERE id = $1`, id, f.user)
	}
	for _, c := range []struct {
		scope string
		id    any
	}{{"transaction", f.txn}, {"run", f.run}, {"agent", f.agent}} {
		h := m5ID()
		f.mustExec(t, m7rHold, f.org, h, c.scope, c.id, nil, nil, f.user)
		if !held(at, f.txn) || !held(at, request) {
			t.Errorf("a %s hold does not cover its transaction and approval request", c.scope)
		}
		if !held(at, c.id) {
			t.Errorf("a %s hold does not cover an audit event about it", c.scope)
		}
		if held(at, m5ID()) || held(at, nil) {
			t.Errorf("a %s hold covers what it does not name", c.scope)
		}
		release(h)
		if held(at, f.txn) {
			t.Errorf("a released %s hold still covers", c.scope)
		}
	}
	h := m5ID()
	f.mustExec(t, m7rHold, f.org, h, "time_range", nil, "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", f.user)
	if !held(at, nil) || !held("2026-10-01T00:00:00Z", nil) || held("2026-10-02T00:00:00Z", nil) || held("2026-09-30T23:59:59Z", f.txn) {
		t.Error("a time range hold covers [start, end)")
	}
	release(h)
	f.mustExec(t, m7rHold, f.org, m5ID(), "org", nil, nil, nil, f.user)
	if !held("2020-01-01T00:00:00Z", nil) || !held(at, m5ID()) {
		t.Error("an org hold covers everything")
	}
	// Another org's hold covers nothing here.
	g := newM5Fixture(t, d.AppPool(t))
	g.mustExec(t, m7rHold, g.org, m5ID(), "org", nil, nil, nil, g.user)
	other := m5Fixture{p: r.p, org: g.org}
	var n int
	if err := other.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.legal_holds WHERE org_id = $1", g.org).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("an org sees %d holds of another (%v)", n, err)
	}
}

// TestHR198_ListerFindsOrgsDueForRetention: an active org is due until its
// job ran successfully in the last day.
func TestHR198_ListerFindsOrgsDueForRetention(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := newM5Fixture(t, p)
	due := func() bool {
		t.Helper()
		refs, err := p.CrossOrgList(context.Background(), db.ListerPurpose("retention_due"), 10000)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(refs, func(r db.OrgRef) bool { return r.Org == f.org })
	}
	if !due() {
		t.Fatal("an org never run is not due")
	}
	f.mustExec(t, "INSERT INTO pc.retention_status (org_id, last_attempt_at, last_error) VALUES ($1, now(), 'ROLE_UNAVAILABLE')", f.org)
	if !due() {
		t.Fatal("an org whose run failed is not due")
	}
	f.mustExec(t, "UPDATE pc.retention_status SET last_run_at = now(), last_error = NULL")
	if due() {
		t.Fatal("an org run today is due again")
	}
	f.mustExec(t, "UPDATE pc.retention_status SET last_run_at = now() - interval '25 hours'")
	if !due() {
		t.Fatal("an org last run yesterday is not due")
	}
}

// TestM7Retention_DownMigrationRunsAndUpAgain: 00072's Down section runs
// as pc_migrator and leaves the lister without retention_due, and its Up
// section applies again.
func TestM7Retention_DownMigrationRunsAndUpAgain(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00072_retention.sql")
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
	p := d.AppPool(t)
	if _, err := p.CrossOrgList(ctx, db.ListerPurpose("retention_due"), 10); err == nil {
		t.Error("retention_due survives the Down migration")
	}
	if _, err := p.CrossOrgList(ctx, db.ListerPurpose("budget_settle"), 10); err != nil {
		t.Errorf("the Down migration lost an earlier purpose: %v", err)
	}
	var cols []string
	d.AdminQueryRow(t, `SELECT coalesce(array_agg(column_name::text), '{}') FROM information_schema.columns
		WHERE table_schema = 'pc' AND table_name = 'observations' AND column_name LIKE '%removed%'`, nil, &cols)
	if len(cols) != 0 {
		t.Errorf("observations keep %v after Down", cols)
	}
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	if _, err := p.CrossOrgList(ctx, db.ListerPurpose("retention_due"), 10); err != nil {
		t.Errorf("retention_due after Up again: %v", err)
	}
}
