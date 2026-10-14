// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
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

// TestHR227_ClosureEvidenceIsLedgered: recording a closure appends, in the
// same transaction, a sandbox.closure ledger entry that names the closure,
// session, agent and connection, the keys and the signed reports (run, kind,
// digest) and the probe outcomes sorted by name; a failed closure is
// entered too, as FAILED, and a refused one leaves no entry.
func TestHR227_ClosureEvidenceIsLedgered(t *testing.T) {
	f := newFixture(t)
	started := f.dbNow(t)
	run := ids.NewV7()
	sum := sha256.Sum256([]byte("a compact JWS"))
	c := f.closure(probes(false), started)
	c.ProbeKey, c.HostKey = bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	c.Reports = []domain.ClosureReport{{Run: run, Kind: "sandbox", SHA256: sum}}
	id, err := f.record(t, c)
	if err != nil {
		t.Fatal(err)
	}
	entries := f.closureEntries(t)
	if len(entries) != 1 {
		t.Fatalf("%d sandbox.closure entries, want 1", len(entries))
	}
	var got app.ClosureEntry
	if err := json.Unmarshal(entries[0], &got); err != nil {
		t.Fatal(err)
	}
	if got.V != 1 || got.Closure != id.String() || got.Session != f.session.String() || got.Agent != f.agent.String() ||
		!slices.Equal(got.Connections, []string{f.conn.String()}) || got.Result != "PASSED" ||
		got.ProbeKey != base64.RawURLEncoding.EncodeToString(c.ProbeKey) || got.HostKey != base64.RawURLEncoding.EncodeToString(c.HostKey) ||
		!slices.Equal(got.Reports, []app.ClosureEntryReport{{Run: run.String(), Kind: "sandbox", SHA256: hex.EncodeToString(sum[:])}}) ||
		len(got.Probes) != len(c.Probes) || got.RecordedAt == "" {
		t.Fatalf("entry %+v", got)
	}
	if !slices.IsSortedFunc(got.Probes, func(a, b app.ClosureEntryProbe) int { return strings.Compare(a.Name, b.Name) }) {
		t.Errorf("probes are not sorted by name: %v", got.Probes)
	}
	// A failed closure is entered as FAILED.
	if _, err := f.record(t, f.closure(probes(true), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	entries = f.closureEntries(t)
	if len(entries) != 2 {
		t.Fatalf("%d entries after a failed closure, want 2", len(entries))
	}
	var failed app.ClosureEntry
	if err := json.Unmarshal(entries[1], &failed); err != nil || failed.Result != "FAILED" {
		t.Fatalf("failed closure's entry %+v (%v)", failed, err)
	}
	// A refused closure (replayed nonce) leaves no entry.
	c.SessionStartedAt = f.dbNow(t)
	c.ObservedAt = c.SessionStartedAt
	if _, err := f.record(t, c); !errors.Is(err, app.ErrClosureReplayed) {
		t.Fatalf("replay: %v", err)
	}
	if n := len(f.closureEntries(t)); n != 2 {
		t.Fatalf("%d entries after a refused closure, want 2", n)
	}
}

// closureEntries returns the bodies of the org's sandbox.closure entries in
// the order they were written.
func (f *fixture) closureEntries(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, `SELECT body FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'sandbox.closure' ORDER BY id`, f.org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHR227_ABundleOfAClosureCarriesItsEntryAndReports: ExportBundle of a
// closure holds its sandbox.closure entry and the signed reports from
// pc.probe_runs, which verify offline under the keys the entry names; a
// closure of another org is not found, and a caller without evidence.read
// where its agent lives is refused.
func TestHR227_ABundleOfAClosureCarriesItsEntryAndReports(t *testing.T) {
	f := newFixture(t)
	iss := bundletest.NewIssuer(t)
	kit := iss.AppendClosure(bundletest.ClosureOpts{Session: f.session.String(), Agent: f.agent.String()})
	for _, kind := range []string{"sandbox", "control", "canary"} {
		nonce, run := ids.NewV7(), mustUUID(t, kit.Runs[kind])
		sum := sha256.Sum256([]byte(kit.Report(kind)))
		f.exec(t, `INSERT INTO pc.probe_nonces (org_id, id, session_id, kind, nonce_sha256, expires_at)
			VALUES ($1, $2, $3, $4, sha256(convert_to($2::uuid::text, 'UTF8')), now() + interval '10 minutes')`,
			f.org, nonce, f.session, strings.ToUpper(kind))
		f.exec(t, `INSERT INTO pc.probe_runs (org_id, id, session_id, nonce_id, kind, report, report_sha256)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, f.org, run, f.session, nonce, strings.ToUpper(kind), kit.Report(kind), sum[:])
	}
	pub := func(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }
	c := f.closure([]domain.ProbeResult{
		{Name: "ssh_push", Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Blocked},
		{Name: "planted_pat_push", Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Blocked},
		{Name: "gateway_control", Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable},
		{Name: domain.ProbeExternalCanary, Role: domain.RoleCanary, Expect: domain.Blocked, Observed: domain.Blocked},
		{Name: "canary_control", Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable},
	}, f.dbNow(t))
	c.ProbeKey, c.HostKey = pub(kit.ProbeKey), pub(kit.HostKey)
	for _, kind := range []string{"sandbox", "control", "canary"} {
		c.Reports = append(c.Reports, domain.ClosureReport{
			Run: mustUUID(t, kit.Runs[kind]), Kind: kind, SHA256: sha256.Sum256([]byte(kit.Report(kind))),
		})
	}
	id, err := f.record(t, c)
	if err != nil {
		t.Fatal(err)
	}
	// Chaining waits for transactions of the whole cluster below xmin, so under
	// parallel tests it may need another pass.
	for deadline := time.Now().Add(time.Minute); ; {
		if _, err := ledger.ChainAll(context.Background(), f.p, f.org, 100); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_chain WHERE org_id = $1`, f.org).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the closure entry was not chained within a minute")
		}
		time.Sleep(200 * time.Millisecond)
	}
	as := func(org ids.OrgID, role td.RoleName) context.Context {
		return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
			Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		}})
	}
	svc := evapp.New(f.p, "pc.test")
	x, err := svc.ExportBundle(as(f.org, td.RoleAuditor), evapp.Selection{Closures: []ids.UUID{id}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Decode(x.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Entries) != 1 || b.Entries[0].Kind != bundle.ClosureKind || len(b.ProbeReports) != 3 {
		t.Fatalf("bundle holds %d entries and %d probe reports", len(b.Entries), len(b.ProbeReports))
	}
	r := bundle.Verify(b, bundle.Options{Trust: &bundle.Trust{LogOrigin: "pc.test"}})
	var lines []string
	for _, ck := range r.Checks {
		if strings.HasPrefix(ck.Name, "closure.") && ck.Status != bundle.Passed {
			t.Errorf("%s %s is %s: %s", ck.Name, ck.Subject, ck.Status, ck.Detail)
		}
		if ck.Name == "closure.probe" {
			lines = append(lines, ck.Detail)
		}
	}
	if len(lines) != 5 {
		t.Errorf("%d probe lines, want 5", len(lines))
	}
	if _, err := svc.ExportBundle(as(f.org, td.RoleAuditor), evapp.Selection{Closures: []ids.UUID{ids.NewV7()}}, 0); !errors.Is(err, evapp.ErrClosureNotFound) {
		t.Errorf("unknown closure: %v", err)
	}
	if _, err := svc.ExportBundle(as(ids.New[ids.Org](), td.RoleAuditor), evapp.Selection{Closures: []ids.UUID{id}}, 0); !errors.Is(err, evapp.ErrClosureNotFound) {
		t.Errorf("another org's closure: %v", err)
	}
}

func mustUUID(t *testing.T, s string) ids.UUID {
	t.Helper()
	id, err := ids.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestHR227_AFailedLedgerAppendRollsTheClosureBack: the closure row and its
// ledger entry are one transaction. A closure whose entry the ledger refuses
// (more reports than a 64 KiB body holds) is not stored, and nothing is
// ledgered.
func TestHR227_AFailedLedgerAppendRollsTheClosureBack(t *testing.T) {
	f := newFixture(t)
	c := f.closure(probes(false), f.dbNow(t))
	for range 600 {
		c.Reports = append(c.Reports, domain.ClosureReport{Run: ids.NewV7(), Kind: "sandbox"})
	}
	if _, err := f.record(t, c); err == nil {
		t.Fatal("a closure whose ledger entry is refused was recorded")
	}
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.coverage_closures WHERE org_id = $1`, f.org).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(f.closureEntries(t)) != 0 {
		t.Fatalf("%d closure rows and %d entries remain", n, len(f.closureEntries(t)))
	}
}
