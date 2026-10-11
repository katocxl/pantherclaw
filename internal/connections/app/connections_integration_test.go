// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
)

type notes struct {
	mu    sync.Mutex
	types []string
	last  map[string]string
}

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.types, n.last = append(n.types, m.Type), m.Params
	return napp.Enqueued{}, nil
}

func (n *notes) count(typ string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, t := range n.types {
		if t == typ {
			c++
		}
	}
	return c
}

const (
	publicURL  = "https://pc.example.test"
	gatewayURL = "https://gw.example.test:8443"
)

type env struct {
	pool    *db.Pool
	svc     *app.Service
	notes   *notes
	org     ids.OrgID
	gateway ids.UUID
	admin   context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{pool: d.AppPool(t), notes: &notes{}}
	e.svc = app.New(e.pool, e.notes, publicURL, gatewayURL)
	return e.withOrg(t)
}

// withOrg is a new org in the same database, with a gateway and both
// reference packages pinned.
func (e *env) withOrg(t *testing.T) *env {
	t.Helper()
	o := &env{pool: e.pool, svc: e.svc, notes: e.notes, org: ids.New[ids.Org](), gateway: ids.NewV7()}
	o.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'connections')", o.org)
	o.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", o.org, o.gateway)
	o.pin(t, mockpayments.Name, mockpayments.Version, mockpayments.Package)
	o.pin(t, pcshell.Name, pcshell.Version, pcshell.Package)
	o.admin = o.caller(td.KindUser, td.RoleGatewayAdmin)
	return o
}

func (e *env) pin(t *testing.T, name, version string, raw []byte) {
	t.Helper()
	pkg, ver := ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", e.org, pkg, name)
	e.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`, e.org, ver, pkg, version, manifest.FileDigest(raw), raw)
	e.exec(t, "INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, $4, $5)",
		e.org, pkg, ver, version, manifest.FileDigest(raw))
}

func (e *env) caller(kind td.PrincipalKind, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: kind, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) int64(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) epoch(t *testing.T) int64 {
	t.Helper()
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	return e.int64(t, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", e.org)
}

func (e *env) configVersion(t *testing.T, gw ids.UUID) int64 {
	t.Helper()
	return e.int64(t, "SELECT config_version FROM pc.gateways WHERE id = $1", gw)
}

func (e *env) payments(t *testing.T, name string) app.Connection {
	t.Helper()
	c, err := e.svc.Create(e.admin, app.CreateInput{
		Name: name, Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://Payments.Example.TEST/v1/", Gateway: e.gateway,
		AccessMode: app.AccessHeld, CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func is(err, want error) bool { return errors.Is(err, want) }

func denied(err error) bool {
	var pe *pcerr.Error
	return errors.As(err, &pe) && pe.Code() == pcerr.PermissionDenied
}

func modeOf(c app.Connection, route string) string {
	for _, r := range c.Routes {
		if r.Route == route {
			return r.Mode
		}
	}
	return ""
}

// TestHR184_NewConnectionsStartInMonitorMode: a connection takes every
// route its package can serve for its kind, each in monitor mode unless a
// default is given, and normalizes its base URL and credential host.
func TestHR184_NewConnectionsStartInMonitorMode(t *testing.T) {
	e := newEnv(t)
	cv := e.configVersion(t, e.gateway)
	c := e.payments(t, "payments")
	if c.State != app.StateActive || c.Revision != 1 || deref(c.BaseUrl) != "https://payments.example.test/v1" ||
		strings.Join(c.AllowedHosts, ",") != "payments.example.test" || c.DefaultMode != app.ModeMonitor || c.DestinationClass != app.ClassPublic ||
		c.MaxResponseBytes != app.DefaultMaxResponseBytes || c.TimeoutMs != app.DefaultTimeoutMs {
		t.Fatalf("created %+v", c.PcConnection)
	}
	if len(c.Routes) != 2 || modeOf(c, "payments-refund") != app.ModeMonitor || modeOf(c, "payments-refund-get") != app.ModeMonitor {
		t.Fatalf("routes %+v", c.Routes)
	}
	if e.configVersion(t, e.gateway) != cv+1 {
		t.Fatal("the gateway's configuration version did not move")
	}
	if _, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "payments", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://x.test", Gateway: e.gateway, AccessMode: app.AccessNone,
	}); !is(err, app.ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	shell, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "laptop", Kind: app.KindLocal, Package: "pc.shell", Gateway: e.gateway, AccessMode: app.AccessNone, DefaultMode: app.ModeEnforce,
	})
	if err != nil || shell.BaseUrl != nil || len(shell.Routes) != 1 || modeOf(shell, "shell-command") != app.ModeEnforce {
		t.Fatalf("local connection: %+v %v", shell, err)
	}
	for name, in := range map[string]app.CreateInput{
		"unpinned package": {Kind: app.KindHTTP, Package: "pc.nope", BaseURL: "https://x.test", AccessMode: app.AccessNone},
		"no hook routes":   {Kind: app.KindLocal, Package: mockpayments.Name, AccessMode: app.AccessNone},
		"no http dispatch": {Kind: app.KindHTTP, Package: "pc.shell", BaseURL: "https://x.test", AccessMode: app.AccessNone},
		"no mcp dispatch":  {Kind: app.KindMCP, Package: mockpayments.Name, BaseURL: "https://x.test", AccessMode: app.AccessNone},
	} {
		in.Name, in.Gateway = "x", e.gateway
		if _, err := e.svc.Create(e.admin, in); !is(err, app.ErrPackage) && !is(err, app.ErrNoRoutes) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR077_RegistrationRefusesMetadataAndPantherClawItself: a base URL or
// credential host naming a metadata service in any spelling, or
// PantherClaw's own endpoints, is refused; plain http only for a private
// address literal.
func TestHR077_RegistrationRefusesMetadataAndPantherClawItself(t *testing.T) {
	e := newEnv(t)
	create := func(base string, hosts ...string) error {
		_, err := e.svc.Create(e.admin, app.CreateInput{
			Name: "t" + strings.ToLower(ids.NewV7().String()[30:]), Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: base,
			AllowedHosts: hosts, Gateway: e.gateway, AccessMode: app.AccessNone,
		})
		return err
	}
	for _, base := range []string{
		"https://169.254.169.254", "https://2852039166", "https://0xa9fea9fe/latest", "https://0251.0376.0251.0376",
		"https://[::ffff:169.254.169.254]", "https://[fd00:ec2::254]", "https://metadata.google.internal", "https://METADATA.google.internal.",
		"https://100.100.100.200", "http://169.254.169.254",
	} {
		if err := create(base); !is(err, app.ErrBaseURL) && !is(err, app.ErrPlainHTTP) {
			t.Errorf("%s: %v", base, err)
		}
	}
	for _, base := range []string{"https://pc.example.test", "https://PC.example.test:443/api", "https://gw.example.test:8443"} {
		if err := create(base); !is(err, app.ErrOwnHost) {
			t.Errorf("%s: %v", base, err)
		}
	}
	for _, base := range []string{
		"http://payments.example.test", "http://8.8.8.8", "ftp://x.test", "https://user:pw@x.test", "https://x.test/?q=1",
		"https://x.test/#f", "https://x.test/a/../b", "https://x.test:0", "https://x.test:99999", "x.test", "https://x.test/a b",
	} {
		if err := create(base); err == nil {
			t.Errorf("%s: accepted", base)
		}
	}
	for _, base := range []string{"http://10.0.0.5:8080", "http://127.0.0.1:9090", "https://10.0.0.5", "https://payments.example.test:8443/v2"} {
		if err := create(base); err != nil {
			t.Errorf("%s: %v", base, err)
		}
	}
	for _, hosts := range [][]string{{"169.254.169.254"}, {"metadata.goog"}, {"pc.example.test"}, {"gw.example.test:8443"}, {"a.test", "a.test"}, {"bad host"}} {
		if err := create("https://payments.example.test", hosts...); err == nil {
			t.Errorf("allowed hosts %v: accepted", hosts)
		}
	}
	if err := create("https://payments.example.test", "auth.example.test", "payments.example.test:8443", "gw.example.test:9443"); err != nil {
		t.Errorf("valid allowed hosts: %v", err)
	}
}

// TestHR183_WeakeningIsNotifiedAndStrengtheningRaisesTheEpoch: every change
// is audited; weakening ones are notified, strengthening ones raise the
// containment epoch in the same transaction, and every one moves the
// gateway's configuration version.
func TestHR183_WeakeningIsNotifiedAndStrengtheningRaisesTheEpoch(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	epoch, cv := e.epoch(t), e.configVersion(t, e.gateway)

	c, err := e.svc.SetRouteMode(e.admin, c.ID, "payments-refund", app.ModeEnforce)
	if err != nil || modeOf(c, "payments-refund") != app.ModeEnforce || e.epoch(t) != epoch+1 || e.notes.count("security.connection_weakened") != 0 {
		t.Fatalf("to enforce: %v epoch %d", err, e.epoch(t))
	}
	c, err = e.svc.SetRouteMode(e.admin, c.ID, "payments-refund", app.ModeMonitor)
	if err != nil || modeOf(c, "payments-refund") != app.ModeMonitor || e.epoch(t) != epoch+1 || e.notes.count("security.connection_weakened") != 1 {
		t.Fatalf("to monitor: %v epoch %d", err, e.epoch(t))
	}
	if _, err := e.svc.SetRouteMode(e.admin, c.ID, "payments-nope", app.ModeEnforce); !is(err, app.ErrRoute) {
		t.Fatalf("unknown route: %v", err)
	}

	base := "https://payments-2.example.test"
	c2, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, BaseURL: &base})
	if err != nil || deref(c2.BaseUrl) != base || strings.Join(c2.AllowedHosts, ",") != "payments-2.example.test" || c2.Revision != c.Revision+1 {
		t.Fatalf("base URL: %+v %v", c2.PcConnection, err)
	}
	if e.notes.count("security.connection_weakened") != 2 || !strings.Contains(e.notes.last["change"], "base_url") || e.epoch(t) != epoch+1 {
		t.Fatalf("base URL change: %v %v", e.notes.types, e.notes.last)
	}
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, BaseURL: &base}); !is(err, app.ErrStale) {
		t.Fatalf("stale revision: %v", err)
	}
	enforce := app.ModeEnforce
	c3, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c2.Revision, DefaultMode: &enforce})
	if err != nil || c3.DefaultMode != app.ModeEnforce || e.epoch(t) != epoch+2 || e.notes.count("security.connection_weakened") != 2 {
		t.Fatalf("default enforce: %v", err)
	}

	q, err := e.svc.Quarantine(e.admin, c.ID, "suspected compromise <b>")
	if err != nil || q.State != app.StateQuarantined || deref(q.QuarantineReason) != "manual" || e.epoch(t) != epoch+3 ||
		e.notes.count("security.connection_quarantined") != 1 {
		t.Fatalf("quarantine: %+v %v", q.PcConnection, err)
	}
	if _, err := e.svc.Quarantine(e.admin, c.ID, "again"); !is(err, app.ErrState) {
		t.Fatalf("quarantine twice: %v", err)
	}
	if _, err := e.svc.Quarantine(e.admin, c.ID, ""); !is(err, app.ErrReason) {
		t.Fatalf("no reason: %v", err)
	}
	r, err := e.svc.Restore(e.admin, c.ID)
	if err != nil || r.State != app.StateActive || r.QuarantineReason != nil || e.epoch(t) != epoch+3 || e.notes.count("security.connection_weakened") != 3 {
		t.Fatalf("restore: %v", err)
	}
	if err := e.svc.Retire(e.admin, c.ID); err != nil || e.epoch(t) != epoch+4 {
		t.Fatalf("retire: %v", err)
	}
	if _, err := e.svc.Restore(e.admin, c.ID); !is(err, app.ErrState) {
		t.Fatalf("restore a retired connection: %v", err)
	}
	if got := e.configVersion(t, e.gateway); got != cv+7 {
		t.Fatalf("config version moved %d times, want 7", got-cv)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE 'audit.connection.%'"); n != 8 {
		t.Fatalf("%d connection audit entries, want 8 (created and seven changes)", n)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.updated'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'base_url_old' = 'https://payments.example.test/v1'`); n != 1 {
		t.Fatal("the old base URL is not audited")
	}
	again := e.payments(t, "payments")
	if again.ID == c.ID {
		t.Fatal("a retired connection's name is free again")
	}
}

// TestHR183_ConnectionManagementIsForPeople: connection.manage is human
// only, and a reader cannot change anything.
func TestHR183_ConnectionManagementIsForPeople(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	robot := e.caller(td.KindServiceAccount, td.RoleGatewayAdmin)
	dev := e.caller(td.KindUser, td.RoleDeveloper)
	if _, err := e.svc.Quarantine(robot, c.ID, "x"); !denied(err) {
		t.Errorf("service account: %v", err)
	}
	if _, err := e.svc.SetRouteMode(dev, c.ID, "payments-refund", app.ModeMonitor); !denied(err) {
		t.Errorf("developer: %v", err)
	}
	if _, err := e.svc.Get(dev, c.ID); err != nil {
		t.Errorf("developer reads: %v", err)
	}
	if rows, _, err := e.svc.List(dev, 0, "", nil, false); err != nil || len(rows) != 1 {
		t.Errorf("developer lists: %d %v", len(rows), err)
	}
}

// TestT037_ConnectionsOfAnotherOrgAreNotFound: ids from another org are
// NotFound for every use case.
func TestT037_ConnectionsOfAnotherOrgAreNotFound(t *testing.T) {
	e := newEnv(t)
	other := e.withOrg(t)
	theirs := other.payments(t, "payments")
	if _, err := e.svc.Get(e.admin, theirs.ID); !is(err, app.ErrNotFound) {
		t.Errorf("get: %v", err)
	}
	if _, err := e.svc.Quarantine(e.admin, theirs.ID, "x"); !is(err, app.ErrNotFound) {
		t.Errorf("quarantine: %v", err)
	}
	if _, err := e.svc.SetRouteMode(e.admin, theirs.ID, "payments-refund", app.ModeEnforce); !is(err, app.ErrNotFound) {
		t.Errorf("set mode: %v", err)
	}
	if err := e.svc.Retire(e.admin, theirs.ID); !is(err, app.ErrNotFound) {
		t.Errorf("retire: %v", err)
	}
	if _, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "x", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://x.test", Gateway: other.gateway, AccessMode: app.AccessNone,
	}); !is(err, app.ErrGatewayNotFound) {
		t.Errorf("another org's gateway: %v", err)
	}
	if rows, _, err := e.svc.List(e.admin, 0, "", nil, true); err != nil || len(rows) != 0 {
		t.Errorf("list: %d %v", len(rows), err)
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// TestPN003_ConnectionNamesNeverShadowTheGatewaysOwnPaths: a connection's name
// is the first path segment of its routes at the gateway (/{connection}/…),
// so the gateway's own endpoints are not available as names.
func TestPN003_ConnectionNamesNeverShadowTheGatewaysOwnPaths(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"mcp", "hook", "sdk", "healthz", "readyz", "metrics"} {
		if _, err := e.svc.Create(e.admin, app.CreateInput{
			Name: name, Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://payments.example.test", Gateway: e.gateway,
			AccessMode: app.AccessNone,
		}); !is(err, app.ErrNameReserved) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR077_TheOperatorSeedMakesEveryRegistrationCheck: dev seed creates
// connections through Seed, which refuses what Create refuses and records
// the operator as the actor.
func TestHR077_TheOperatorSeedMakesEveryRegistrationCheck(t *testing.T) {
	e := newEnv(t)
	in := app.CreateInput{
		Name: "payments", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "http://169.254.169.254", Gateway: e.gateway,
		AccessMode: app.AccessNone, DefaultMode: app.ModeEnforce,
	}
	if _, err := e.svc.Seed(context.Background(), e.org, "dev-seed", in); !is(err, app.ErrBaseURL) {
		t.Fatalf("metadata address: %v", err)
	}
	in.BaseURL = "http://127.0.0.1:9090"
	c, err := e.svc.Seed(context.Background(), e.org, "dev-seed", in)
	if err != nil || c.CreatedBy != "operator:dev-seed" || modeOf(c, "payments-refund") != app.ModeEnforce {
		t.Fatalf("seed: %+v %v", c, err)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.connection.created' AND actor_type = 'operator' AND actor_id = 'dev-seed'", e.org); n != 1 {
		t.Fatalf("operator audit entries: %d", n)
	}
}

// TestHR078_AGatewaysCircuitReportQuarantinesItsConnection: a report under
// the thresholds or from another gateway changes nothing; one at them
// quarantines the connection at once (epoch +1, audited with the gateway as
// actor, notified), a repeat changes nothing more, and only a person's
// restore lifts it, which closes the circuit.
func TestHR078_AGatewaysCircuitReportQuarantinesItsConnection(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	ctx := context.Background()
	for _, n := range [][2]int32{{4, 4}, {5, 11}, {6, 5}} {
		if _, err := e.svc.OpenCircuit(ctx, e.org, e.gateway, c.ID, n[0], n[1]); !is(err, app.ErrCircuit) {
			t.Errorf("%d of %d: %v", n[0], n[1], err)
		}
	}
	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", e.org, other)
	if _, err := e.svc.OpenCircuit(ctx, e.org, other, c.ID, 5, 5); !is(err, app.ErrNotFound) {
		t.Fatalf("another gateway's report: %v", err)
	}
	epoch := e.epoch(t)
	if q, err := e.svc.OpenCircuit(ctx, e.org, e.gateway, c.ID, 5, 8); err != nil || !q {
		t.Fatalf("report: %v %v", q, err)
	}
	got, err := e.svc.Get(e.admin, c.ID)
	if err != nil || got.State != app.StateQuarantined || deref(got.QuarantineReason) != app.QuarantineCircuitOpen || e.epoch(t) != epoch+1 {
		t.Fatalf("after the report: %s %q epoch %d (was %d) %v", got.State, deref(got.QuarantineReason), e.epoch(t), epoch, err)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.quarantined' AND actor_type = 'gateway'
		AND actor_id = $1`, e.gateway.String()); n != 1 || e.notes.count("security.connection_quarantined") != 1 {
		t.Fatalf("audit entries %d, notifications %d", n, e.notes.count("security.connection_quarantined"))
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.circuit_states WHERE state = 'OPEN' AND unknown_count = 5 AND total_count = 8"); n != 1 {
		t.Fatalf("open circuits %d", n)
	}
	if q, err := e.svc.OpenCircuit(ctx, e.org, e.gateway, c.ID, 7, 9); err != nil || !q || e.epoch(t) != epoch+1 {
		t.Fatalf("a repeat: %v %v epoch %d", q, err, e.epoch(t))
	}
	if _, err := e.svc.Restore(e.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.circuit_states WHERE state = 'CLOSED' AND closed_at IS NOT NULL"); n != 1 {
		t.Fatalf("closed circuits after the restore: %d", n)
	}
}

const upstreamPackage = "acme.mcp-payments"

// upstreamDigest is the reviewed digest of the upstream get_refund tool in
// mcpPayments.
var upstreamDigest = "sha256:" + strings.Repeat("0f", 32)

// mcpPayments is the mock payments package with refunds read from an
// upstream MCP server's get_refund tool.
func mcpPayments(t *testing.T) []byte {
	t.Helper()
	raw := string(mockpayments.Package)
	for _, r := range [][2]string{
		{"name: " + mockpayments.Name + "\n", "name: " + upstreamPackage + "\n"},
		{
			"    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds/{target.id}\n",
			"    dispatch:\n      mcp:\n        tool: get_refund\n        arguments:\n          refund: target.id\n        upstream_digest: " + upstreamDigest + "\n",
		},
	} {
		if strings.Count(raw, r[0]) != 1 {
			t.Fatalf("mock payments package: %q not found once", r[0])
		}
		raw = strings.Replace(raw, r[0], r[1], 1)
	}
	return []byte(raw)
}

// TestHR081_UpstreamDriftQuarantinesThePinnedPackage: a gateway's report
// that an upstream tool changed quarantines the org's pinned version of the
// connection's package, in one transaction with an epoch raise, an audit
// entry with the gateway as actor and a notification; a repeat changes
// nothing more. A report about another gateway's connection, an HTTP
// connection, a tool or digest the package did not review, or a tool that
// did not change is refused, and other packages are untouched.
func TestHR081_UpstreamDriftQuarantinesThePinnedPackage(t *testing.T) {
	e := newEnv(t)
	e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	c, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "upstream", Kind: app.KindMCP, Package: upstreamPackage, BaseURL: "https://mcp.example.test/mcp", Gateway: e.gateway,
		AccessMode: app.AccessNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	payments := e.payments(t, "payments")
	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", e.org, other)
	ctx := context.Background()
	observed := "sha256:" + strings.Repeat("ab", 32)
	for name, tc := range map[string]struct {
		gateway, conn               ids.UUID
		tool, expected, observedNow string
		want                        error
	}{
		"another gateway's connection": {other, c.ID, "get_refund", upstreamDigest, observed, app.ErrNotFound},
		"an http connection":           {e.gateway, payments.ID, "get_refund", upstreamDigest, observed, app.ErrNotFound},
		"an unreviewed tool":           {e.gateway, c.ID, "delete_everything", upstreamDigest, observed, app.ErrDrift},
		"another reviewed digest":      {e.gateway, c.ID, "get_refund", "sha256:" + strings.Repeat("11", 32), observed, app.ErrDrift},
		"no change":                    {e.gateway, c.ID, "get_refund", upstreamDigest, upstreamDigest, app.ErrDrift},
	} {
		if _, err := e.svc.ReportDrift(ctx, e.org, tc.gateway, tc.conn, tc.tool, tc.expected, tc.observedNow); !is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	state := func(pkg string) int64 {
		return e.int64(t, `SELECT count(*) FROM pc.package_versions v JOIN pc.tool_packages p ON p.org_id = v.org_id AND p.id = v.package_id
			WHERE p.name = $1 AND v.state = 'QUARANTINED'`, pkg)
	}
	ledger := func() int64 {
		return e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.package.transitioned' AND actor_type = 'gateway'
			AND actor_id = $1`, e.gateway.String())
	}
	epoch := e.epoch(t)
	if state(upstreamPackage) != 0 || ledger() != 0 {
		t.Fatal("a refused report changed something")
	}
	if q, err := e.svc.ReportDrift(ctx, e.org, e.gateway, c.ID, "get_refund", upstreamDigest, observed); err != nil || !q {
		t.Fatalf("report: %v %v", q, err)
	}
	if state(upstreamPackage) != 1 || e.epoch(t) != epoch+1 || ledger() != 1 || e.notes.count("security.package_quarantined") != 1 ||
		e.notes.last["package"] != upstreamPackage || e.notes.last["reason"] != app.ReasonUpstreamDrift {
		t.Fatalf("after the report: quarantined %d, epoch %d (was %d), audit %d, notes %v", state(upstreamPackage), e.epoch(t), epoch, ledger(), e.notes.last)
	}
	if q, err := e.svc.ReportDrift(ctx, e.org, e.gateway, c.ID, "get_refund", upstreamDigest, ""); err != nil || !q ||
		e.epoch(t) != epoch+1 || ledger() != 1 {
		t.Fatalf("a repeat (tool gone): %v %v, epoch %d, audit %d", q, err, e.epoch(t), ledger())
	}
	if state(mockpayments.Name) != 0 {
		t.Fatal("another package was quarantined")
	}
}
