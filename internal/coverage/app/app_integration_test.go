// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
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
	version                              ids.UUID
	// session is the sandbox session the closures come from (00090).
	session ids.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		p: d.AppPool(t), org: ids.New[ids.Org](), user: ids.NewV7(), agent: ids.NewV7(), run: ids.NewV7(),
		gateway: ids.NewV7(), conn: ids.NewV7(), pkg: ids.NewV7(), version: ids.NewV7(), session: ids.NewV7(),
	}
	f.svc = &app.Service{Pool: f.p, Freshness: domain.Freshness{EnforcedTTL: 24 * time.Hour, ReassessEvery: time.Minute}}
	env, version, token := ids.NewV7(), f.version, ids.NewV7()
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
		{`INSERT INTO pc.enrollment_tokens (org_id, id, agent_id, environment_id, token_hash, created_by, expires_at)
			VALUES ($1, $2, $3, $4, sha256(convert_to($2::uuid::text, 'UTF8')), 'test', now() + interval '15 minutes')`, []any{f.org, token, f.agent, env}},
		{`INSERT INTO pc.sandbox_sessions (org_id, id, agent_id, launcher, enrollment_token_id, agent_image, edge_image, probe_image,
			config_digest, probe_jkt, probe_public_key, host_jkt, host_public_key, engine_version, api_version, runtime, expires_at)
			VALUES ($1, $2, $3, 'test', $4,
			$5, $5, $5, $5, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', sha256(convert_to($2::uuid::text, 'UTF8')),
			'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', sha256(convert_to($3::uuid::text, 'UTF8')), '29.0.1', '1.51', 'runc',
			now() + interval '1 hour')`, []any{f.org, f.session, f.agent, token, digest}},
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
		Agent: f.agent, Connection: f.conn, SandboxSession: f.session, SessionStartedAt: started,
		ObservedAt: started, Probes: probes, SigningKeyJKT: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ServerNonce:  strings.ReplaceAll(ids.NewV7().String(), "-", ""),
		Engine:       domain.Engine{Version: "29.0.1", APIVersion: "1.51", Runtime: "runc"},
		ImageDigests: []string{digest}, Bound: domain.Bound{ConnectionRevision: 1, Gateway: f.gateway, PackageVersion: f.version},
		ConfigChecks: []domain.ConfigCheck{{ID: domain.CheckNoDockerSocket, OK: true}, {ID: domain.CheckNoHostBind, OK: true}},
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

// probes is a full catalog: each probe blocked in the sandbox with its
// positive twin from the open control network, the named controls and the
// canary. failNegative fails the negative control.
func probes(failNegative bool) []domain.ProbeResult {
	pass := func(name, role, expect string) domain.ProbeResult {
		return domain.ProbeResult{Name: name, Role: role, Expect: expect, Observed: expect}
	}
	out := []domain.ProbeResult{
		pass(domain.ProbeEdgeMediated, domain.RolePositiveControl, domain.Reachable),
		pass(domain.ProbeCanaryControl, domain.RolePositiveControl, domain.Reachable),
		pass(domain.ProbeEdgeUnmappedRefused, domain.RoleNegativeControl, domain.Blocked),
		pass(domain.ProbeExternalCanary, domain.RoleCanary, domain.Blocked),
	}
	if failNegative {
		out[2].Observed = domain.Reachable
	}
	for _, n := range []string{
		domain.ProbeDNSExternal, domain.ProbeDNSDockerResolver, domain.ProbeIPv6, domain.ProbeICMP, domain.ProbeDirectHTTPS,
		domain.ProbeMetadata, domain.ProbeHostGateway, domain.ProbeDirectSSH, domain.ProbeSSHPush, domain.ProbePATPush,
	} {
		out = append(out, pass(n, domain.RoleProbe, domain.Blocked), pass(n, domain.RolePositiveControl, domain.Reachable))
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
// after its session started is refused; an exclusion, a new route or a lapse
// is no such change. A failed closure is stored and invalidates the scope at once.
func TestHR211_ClosureAfterAChangeIsRefused(t *testing.T) {
	f := newFixture(t)
	started := f.dbNow(t) // after the fixture's package pin
	for _, kind := range []string{"exclusion", "route", "evidence_expired"} {
		f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, $3, $4)`,
			f.org, ids.NewV7(), kind, f.conn)
	}
	if _, err := f.record(t, f.closure(probes(false), started)); err != nil {
		t.Fatalf("an exclusion, a route or a lapse made the closure stale: %v", err)
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

// TestHR211_AClosureMustMatchTheBindingsItsSessionOpenedUnder: a closure
// taken against another gateway, connection revision, package version or
// credential than the connection has now is refused.
func TestHR211_AClosureMustMatchTheBindingsItsSessionOpenedUnder(t *testing.T) {
	f := newFixture(t)
	two := int32(2)
	for name, change := range map[string]func(*domain.Bound){
		"another gateway":         func(b *domain.Bound) { b.Gateway = ids.NewV7() },
		"an older revision":       func(b *domain.Bound) { b.ConnectionRevision = 2 },
		"another package version": func(b *domain.Bound) { b.PackageVersion = ids.NewV7() },
		"a credential since gone": func(b *domain.Bound) { b.CredentialVersion = &two },
	} {
		c := f.closure(probes(false), f.dbNow(t))
		change(&c.Bound)
		if _, err := f.record(t, c); !errors.Is(err, app.ErrClosureStale) {
			t.Errorf("%s: %v", name, err)
		}
	}
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
	if got.CredentialVersion != nil || got.PackageVersionID != f.version || !strings.Contains(string(got.ConfigChecks), domain.CheckNoHostBind) {
		t.Fatalf("closure %+v", got)
	}
}

// TestHR215_ASignedResultSetIsRecordedOnce: a replayed server nonce is
// refused, and the sandbox's transaction stays usable.
func TestHR215_ASignedResultSetIsRecordedOnce(t *testing.T) {
	f := newFixture(t)
	c := f.closure(probes(false), f.dbNow(t))
	if _, err := f.record(t, c); err != nil {
		t.Fatal(err)
	}
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := f.svc.RecordClosure(ctx, tx, c); !errors.Is(err, app.ErrClosureReplayed) {
			t.Errorf("a replay: %v", err)
		}
		_, err := dbq.New(tx).GetCoverageClosure(ctx, f.org, ids.NewV7())
		if !db.IsNoRows(err) {
			t.Errorf("the transaction after a replay: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestF443_RoutesSeenInsideTheSandboxAreObserved: a destination the edge
// refused becomes an observed route of the agent and connection, its first
// sighting a route change; seeing it again in the same session changes
// nothing, and only refused destinations and found credentials are taken.
func TestF443_RoutesSeenInsideTheSandboxAreObserved(t *testing.T) {
	f := newFixture(t)
	session := ids.NewV7()
	route := func(kind domain.RouteKind, locator string) (bool, error) {
		var added bool
		err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			added, err = f.svc.RecordRoute(ctx, tx, domain.ObservedRoute{
				Agent: f.agent, Connection: f.conn, SandboxSession: session, Kind: kind, Locator: locator,
			})
			return err
		})
		return added, err
	}
	if added, err := route(domain.KindDirectAPI, "140.82.112.3:443"); err != nil || !added {
		t.Fatalf("a refused destination: %v %v", added, err)
	}
	if added, err := route(domain.KindDirectAPI, "140.82.112.3:443"); err != nil || added {
		t.Fatalf("seen again: %v %v", added, err)
	}
	for _, kind := range []domain.RouteKind{domain.KindHost, domain.KindChannel, "nonsense"} {
		if _, err := route(kind, "x"); !errors.Is(err, app.ErrRoute) {
			t.Errorf("%s: %v", kind, err)
		}
	}
	if _, err := route(domain.KindCredential, strings.Repeat("k", 513)); !errors.Is(err, app.ErrRoute) {
		t.Errorf("a long locator: %v", err)
	}
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		pending, err := q.PendingCoverageInvalidations(ctx, f.org, 10)
		pending = slices.DeleteFunc(pending, func(i dbq.PcCoverageInvalidation) bool { return i.Kind == "package_version" })
		if err != nil || len(pending) != 1 || pending[0].Kind != "route" {
			t.Fatalf("route changes %+v (%v)", pending, err)
		}
		rows, err := q.CoverageRoutesForScope(ctx, dbq.CoverageRoutesForScopeParams{
			OrgID: f.org, ConnectionID: f.conn, AgentID: &f.agent, Operation: "git.push",
		})
		if err != nil || len(rows) != 1 || rows[0].Source != "probe" || rows[0].Observation != "observed" || rows[0].SeenCount != 1 {
			t.Fatalf("routes %+v (%v)", rows, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
