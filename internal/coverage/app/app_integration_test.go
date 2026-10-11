// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type fixture struct {
	p                                    *db.Pool
	svc                                  *app.Service
	org                                  ids.OrgID
	user, agent, run, gateway, conn, pkg ids.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		p: d.AppPool(t), org: ids.New[ids.Org](), user: ids.NewV7(), agent: ids.NewV7(), run: ids.NewV7(),
		gateway: ids.NewV7(), conn: ids.NewV7(), pkg: ids.NewV7(),
	}
	f.svc = &app.Service{Pool: f.p, Freshness: domain.Freshness{EnforcedTTL: 24 * time.Hour, ReassessInterval: time.Minute}}
	env, version := ids.NewV7(), ids.NewV7()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'cov')", []any{f.org}},
		{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", []any{f.org, f.user}},
		{"INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", []any{f.org, env}},
		{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", []any{f.org, f.agent}},
		{`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source,
			expires_at) VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, []any{f.org, f.run, f.agent, env, f.user}},
		{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", []any{f.org, f.gateway}},
		{`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
			created_by, updated_by) VALUES ($1, $2, 'payments', 'http', $3, 'pc.mock-payments', 'https://api.example.com',
			'pantherclaw_held', 'enforce', 'test', 'test')`, []any{f.org, f.conn, f.gateway}},
		{"INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, 'pc.mock-payments')", []any{f.org, f.pkg}},
		{`INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
			VALUES ($1, $2, $3, '1.0.0', $4, $5, 'ACTIVE')`, []any{f.org, version, f.pkg, digest, mockpayments.Package}},
		{
			`INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, '1.0.0', $4)`,
			[]any{f.org, f.pkg, version, digest},
		},
	} {
		f.exec(t, s.sql, s.args...)
	}
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) closure(probes []domain.ProbeResult, started time.Time) domain.Closure {
	return domain.Closure{
		Agent: f.agent, Connection: f.conn, SandboxSession: ids.NewV7(), SessionStartedAt: started,
		ObservedAt: started, Probes: probes, SigningKeyJKT: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ServerNonce: "nonce-0123456789abcdef", Engine: domain.Engine{Version: "29.0.1", APIVersion: "1.51", Runtime: "runc"},
		ImageDigests: []string{digest}, Gateway: f.gateway,
	}
}

func (f *fixture) record(t *testing.T, c domain.Closure) (ids.UUID, error) {
	t.Helper()
	var id ids.UUID
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = f.svc.RecordClosure(ctx, tx, c)
		return err
	})
	return id, err
}

func probes(failNegative bool) []domain.ProbeResult {
	out := []domain.ProbeResult{
		{Name: "edge_mediated", Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable},
		{Name: "edge_unmapped_refused", Role: domain.RoleNegativeControl, Expect: domain.Blocked, Observed: domain.Blocked},
		{Name: domain.ProbeExternalCanary, Role: domain.RoleCanary, Expect: domain.Blocked, Observed: domain.Blocked},
	}
	if failNegative {
		out[1].Observed = domain.Reachable
	}
	for _, n := range []string{
		domain.ProbeDNSExternal, domain.ProbeDNSDockerResolver, domain.ProbeIPv6, domain.ProbeICMP, domain.ProbeDirectHTTPS,
		domain.ProbeMetadata, domain.ProbeHostGateway, domain.ProbeDockerSocket, domain.ProbeDirectSSH, domain.ProbeSSHPush,
		domain.ProbePATPush,
	} {
		out = append(out, domain.ProbeResult{Name: n, Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Blocked})
	}
	return out
}

// TestIntRecordClosureBindsAndExpires: a passing closure is stored as
// PASSED, bound to the connection's revision, gateway and pinned package
// version, and expires with the freshness contract; readers see what it
// closed.
func TestIntRecordClosureBindsAndExpires(t *testing.T) {
	f := newFixture(t)
	c := f.closure(probes(false), f.dbNow(t))
	id, err := f.record(t, c)
	if err != nil {
		t.Fatal(err)
	}
	var got dbq.PcCoverageClosure
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		got, err = dbq.New(tx).GetCoverageClosure(ctx, f.org, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got.Result != "PASSED" || got.ConnectionRevision != 1 || got.GatewayID != f.gateway ||
		!got.ExpiresAt.Equal(c.ObservedAt.Add(24*time.Hour).Truncate(time.Microsecond)) {
		t.Fatalf("closure %+v", got)
	}
}

// TestHR211_ClosureAfterAChangeIsRefused: a closure whose scope changed
// after its session started is refused; an exclusion is no such change. A
// failed closure is stored and invalidates the scope at once.
func TestHR211_ClosureAfterAChangeIsRefused(t *testing.T) {
	f := newFixture(t)
	started := f.dbNow(t) // after the fixture's package pin
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, 'exclusion', $3)`,
		f.org, ids.NewV7(), f.conn)
	if _, err := f.record(t, f.closure(probes(false), started)); err != nil {
		t.Fatalf("an exclusion made the closure stale: %v", err)
	}
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, 'route_mode', $3)`,
		f.org, ids.NewV7(), f.conn)
	if _, err := f.record(t, f.closure(probes(false), started)); !errors.Is(err, app.ErrClosureStale) {
		t.Fatalf("closure after a route mode change: %v", err)
	}
	failed, err := f.record(t, f.closure(probes(true), f.dbNow(t)))
	if err != nil {
		t.Fatal(err)
	}
	err = f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetCoverageClosure(ctx, f.org, failed)
		if err != nil || row.Result != "FAILED" || row.NegativeControlsPassed {
			t.Fatalf("failed closure %+v (%v)", row, err)
		}
		pending, err := q.PendingCoverageInvalidations(ctx, f.org, 10)
		if err != nil || !slices.ContainsFunc(pending, func(i dbq.PcCoverageInvalidation) bool {
			return i.Kind == "closure_failed" && i.SubjectID != nil && *i.SubjectID == failed
		}) {
			t.Fatalf("no closure_failed invalidation in %v (%v)", pending, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.record(t, f.closure(probes(false), time.Now().Add(time.Hour))); !errors.Is(err, app.ErrClosure) {
		t.Fatalf("a closure observed before its session started: %v", err)
	}
}

// dbNow is the database's clock, which stamps invalidation events.
func (f *fixture) dbNow(t *testing.T) time.Time {
	t.Helper()
	var now time.Time
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now)
	}); err != nil {
		t.Fatal(err)
	}
	return now
}
