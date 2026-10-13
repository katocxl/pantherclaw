// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	tdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// caller is a principal of kind holding role over the org, made up for the
// call.
func (e *env) caller(kind td.PrincipalKind, role td.RoleName) context.Context {
	return e.as(ids.NewV7(), kind, role)
}

// brokerKey registers a broker key for gateway.
func (e *env) brokerKey(t *testing.T, gateway ids.UUID) ids.UUID {
	t.Helper()
	cert, key := ids.NewV7(), ids.NewV7()
	serial, pub := make([]byte, 16), make([]byte, 1216) // the size of a sealing public key; never used here
	_, _ = rand.Read(serial)
	_, _ = rand.Read(pub)
	e.exec(t, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, 'ENROLL', now(), now() + interval '24 hours')`, e.org, cert, gateway, serial, strings.Repeat("A", 43))
	e.exec(t, `INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
		VALUES ($1, $2, $3, (SELECT coalesce(max(version), 0) + 1 FROM pc.broker_keys WHERE gateway_id = $3), $4, $5, $6)`,
		e.org, key, gateway, pub, "sha256:"+strings.Repeat("0", 64), cert)
	return key
}

// gitHubConnection is an active pc.github connection served by gateway,
// holding a GitHub App credential sealed to key (kind static when static
// is set).
func (e *env) gitHubConnection(t *testing.T, gateway, key ids.UUID, name string, static bool) ids.UUID {
	t.Helper()
	conn := ids.NewV7()
	e.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, allowed_hosts, default_mode,
		credential_header, credential_scheme, created_by, updated_by) VALUES ($1, $2, $3, 'http', $4, 'pc.github', 'https://api.github.com',
		'pantherclaw_held', ARRAY['api.github.com'], 'enforce', 'Authorization', 'Bearer', 'test', 'test')`, e.org, conn, name, gateway)
	kind := map[bool]string{true: "static", false: "github_app"}[static]
	e.exec(t, `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, scheme, created_by, kind)
		VALUES ($1, $2, $3, 1, $4, $5, ARRAY['api.github.com'], 'Authorization', 'Bearer', 'test', $6)`,
		e.org, ids.NewV7(), conn, key, append([]byte{0x01}, make([]byte, 1200)...), kind) // the shape of a sealed credential; never opened here
	return conn
}

// TestHR209_AnOrgScanRunsAsItsGatewaysLease: a person holding
// github.scan.run in the Team edition starts a scan of a GitHub App
// connection, one at a time; the connection's gateway claims it as an
// org_scan lease and reports its summary, which the run keeps: counts,
// the sources read, and the sources not read with why (never "none
// found"). Anything else in the report is refused; a lease that ends
// unreported fails the run; a service account or the Community edition
// starts nothing.
func TestHR209_AnOrgScanRunsAsItsGatewaysLease(t *testing.T) {
	e := newEnv(t)
	gateway := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", e.org, gateway)
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	key := e.brokerKey(t, gateway)
	conn := e.gitHubConnection(t, gateway, key, "github", false)
	static := e.gitHubConnection(t, gateway, key, "github-pat", true)
	admin := e.caller(td.KindUser, td.RoleSecurityAdmin)
	team := &app.Scans{Pool: e.pool, Ents: edition(billing.Team)}

	for name, c := range map[string]struct {
		scans *app.Scans
		ctx   context.Context
		conn  ids.UUID
		want  error
	}{
		"the Community edition":           {&app.Scans{Pool: e.pool, Ents: edition(billing.Community)}, admin, conn, app.ErrEdition},
		"a service account with the role": {team, e.caller(td.KindServiceAccount, td.RoleOrgAdmin), conn, app.ErrHumanOnly},
		"a static credential":             {team, admin, static, app.ErrNotGitHubApp},
		"no such connection":              {team, admin, ids.NewV7(), app.ErrNotGitHubApp},
		"an Auditor":                      {team, e.caller(td.KindUser, td.RoleAuditor), conn, nil},
	} {
		if _, err := c.scans.Start(c.ctx, c.conn); err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	scan, err := team.Start(admin, conn)
	if err != nil || scan.State != "PENDING" || scan.ConnectionID != conn {
		t.Fatalf("start %+v %v", scan, err)
	}
	if _, err := team.Start(admin, conn); !errors.Is(err, app.ErrScanRunning) {
		t.Fatalf("a second scan while one runs: %v", err)
	}

	store := &pgtransactions.Store{Pool: e.pool}
	leases, err := store.Claim(context.Background(), e.org, gateway, 4, 30*time.Second)
	if err != nil || len(leases) != 1 || leases[0].Purpose != tdomain.PurposeOrgScan || leases[0].Connection != conn ||
		!strings.Contains(string(leases[0].Request), scan.ID.String()) {
		t.Fatalf("leases %+v %v", leases, err)
	}
	if got, _ := team.Get(admin, scan.ID); got.State != "RUNNING" {
		t.Fatalf("leased: %s", got.State)
	}
	report := func(fields map[string]string) error {
		_, err := store.Report(context.Background(), e.org, gateway, tapp.Report{
			Task: leases[0].Task, Secret: leases[0].Secret, HTTPStatus: 200, Found: true, Complete: true, Fields: fields,
		}, nil)
		return err
	}
	for name, fields := range map[string]map[string]string{
		"a field that is no summary":   {"/secrets/production": "x"},
		"a source outside the catalog": {"/scanned/secrets": "true"},
		"read and not read":            {"/scanned/workflows": "true", "/not_scanned/workflows": "time limit"},
		"an unknown reason":            {"/not_scanned/everything_else": "x"},
	} {
		if err := report(fields); !errors.Is(err, tapp.ErrUndeclared) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := report(map[string]string{
		"/counts/repositories": "3", "/counts/workflows": "2", "/scanned/repositories": "true", "/scanned/workflows": "true",
		"/not_scanned/org_installations": "the App lacks organization_administration:read",
	}); err != nil {
		t.Fatal(err)
	}
	done, err := team.Get(admin, scan.ID)
	if err != nil || done.State != "DONE" || done.FinishedAt == nil || !maps.Equal(done.Counts, map[string]int64{"repositories": 3, "workflows": 2}) ||
		!slices.Equal(done.Scanned, []string{"repositories", "workflows"}) || done.NotScanned["org_installations"] == "" ||
		done.NotScanned["mcp_configs"] != "not reported" || done.NotScanned["rulesets"] != "not reported" {
		t.Fatalf("done %+v %v", done, err)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind IN ('audit.github.scan_started', 'audit.github.scan_finished')`); n != 2 {
		t.Fatalf("%d audited scan events", n)
	}

	// The next scan's lease ends without a report: the run failed.
	again, err := team.Start(admin, conn)
	if err != nil {
		t.Fatal(err)
	}
	e.exec(t, "UPDATE pc.verifications SET state = 'EXPIRED', finished_at = now() WHERE org_id = $1 AND purpose = 'org_scan' AND state = 'PENDING'", e.org)
	if got, _ := team.Get(admin, again.ID); got.State != "FAILED" {
		t.Fatalf("an expired lease: %s", got.State)
	}
}

// TestHR209_OnlyTheLeaseHoldingGatewaySubmitsFindingsAndTheyGrantNothing:
// a gateway submits an organization scan's findings only while it holds
// that scan's org_scan lease, and only GitHub kinds; they become
// DISCOVERED agents tagged with the scan, are listed with the scan, are
// counted when seen again, and grant nothing. A local scan submits no
// GitHub kind.
func TestHR209_OnlyTheLeaseHoldingGatewaySubmitsFindingsAndTheyGrantNothing(t *testing.T) {
	e := newEnv(t)
	gateway, other := ids.NewV7(), ids.NewV7()
	for name, g := range map[string]ids.UUID{"edge": gateway, "other": other} {
		e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, $3, 'test')", e.org, g, name)
	}
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	conn := e.gitHubConnection(t, gateway, e.brokerKey(t, gateway), "github", false)
	admin := e.caller(td.KindUser, td.RoleSecurityAdmin)
	scans := &app.Scans{Pool: e.pool, Ents: edition(billing.Team)}
	scan, err := scans.Start(admin, conn)
	if err != nil {
		t.Fatal(err)
	}
	inv := aapp.NewInventory(e.pool, edition(billing.Team))
	key := func(b byte) [32]byte { return [32]byte{b} }
	findings := []aapp.ScanFinding{
		{Kind: "github_workflow", Key: key(1), Attributes: map[string]string{"repository": "acme/payments", "path": ".github/workflows/deploy.yml", "environments": "production"}},
		{Kind: "github_mcp_config", Key: key(2), Attributes: map[string]string{"repository": "acme/payments", "name": "github", "command": "npx"}},
	}
	if _, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, nil, findings); !errors.Is(err, aapp.ErrNoScanLease) {
		t.Fatalf("before the lease: %v", err)
	}
	store := &pgtransactions.Store{Pool: e.pool}
	leases, err := store.Claim(context.Background(), e.org, gateway, 4, 30*time.Second)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases %+v %v", leases, err)
	}
	lease := leases[0].Secret
	if _, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, []byte("not the lease"), findings); !errors.Is(err, aapp.ErrNoScanLease) {
		t.Fatalf("the gateway without the lease's secret: %v", err)
	}
	if _, err := inv.SubmitGitHubScan(context.Background(), e.org, other, scan.ID, lease, findings); !errors.Is(err, aapp.ErrNoScanLease) {
		t.Fatalf("another gateway: %v", err)
	}
	local := []aapp.ScanFinding{{Kind: "mcp_server", Key: key(3), Attributes: map[string]string{"name": "x"}}}
	if _, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, lease, local); !errors.Is(err, aapp.ErrScanKind) {
		t.Fatalf("a local kind from a gateway: %v", err)
	}
	r, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, lease, findings)
	if err != nil || r.Created != 2 {
		t.Fatalf("submit %+v %v", r, err)
	}
	if r, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, lease, findings[:1]); err != nil || r.Counted != 1 || r.Created != 0 {
		t.Fatalf("seen again %+v %v", r, err)
	}
	listed, _, err := scans.Findings(admin, scan.ID, 0, "")
	if err != nil || len(listed) != 2 || listed[0].Attributes["kind"] != "github_workflow" || listed[0].Attributes["scan_run"] != "" ||
		listed[1].Attributes["command"] != "npx" || listed[0].SeenCount != 2 {
		t.Fatalf("findings %+v %v", listed, err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1 AND state = 'DISCOVERED'", e.org); n != 2 {
		t.Fatalf("%d discovered agents", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.grants WHERE org_id = $1", e.org); n != 0 {
		t.Fatalf("findings granted something: %d grants", n)
	}
	// After the report, the lease is gone: nothing more is accepted.
	if _, err := store.Report(context.Background(), e.org, gateway, tapp.Report{
		Task: leases[0].Task, Secret: leases[0].Secret, HTTPStatus: 200, Found: true, Complete: true, Fields: map[string]string{"/counts/workflows": "1"},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, lease, findings); !errors.Is(err, aapp.ErrNoScanLease) {
		t.Fatalf("after the report: %v", err)
	}
	// A person's local scan submits no GitHub kind.
	person := e.caller(td.KindUser, td.RoleOrgAdmin)
	if _, err := inv.SubmitScan(person, "laptop", findings); !errors.Is(err, aapp.ErrScanKind) {
		t.Fatalf("a GitHub kind from a local scan: %v", err)
	}
}

// TestHR209_APersonsScanNeverTouchesTheGatewaysFindings: a person's local
// scan and the gateway's org scan keep their findings apart, even under
// the same key: a person cannot pre-seed or overwrite a gateway finding,
// nor fill its room, since each source has its own cap.
func TestHR209_APersonsScanNeverTouchesTheGatewaysFindings(t *testing.T) {
	e := newEnv(t)
	gateway := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", e.org, gateway)
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	conn := e.gitHubConnection(t, gateway, e.brokerKey(t, gateway), "github", false)
	admin := e.caller(td.KindUser, td.RoleSecurityAdmin)
	scans := &app.Scans{Pool: e.pool, Ents: edition(billing.Team)}
	scan, err := scans.Start(admin, conn)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := (&pgtransactions.Store{Pool: e.pool}).Claim(context.Background(), e.org, gateway, 4, 30*time.Second)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases %+v %v", leases, err)
	}
	lease := leases[0].Secret
	inv := aapp.NewInventory(e.pool, edition(billing.Team))
	person := e.caller(td.KindUser, td.RoleAgentOwner)
	seeded := [32]byte{7}
	pre := []aapp.ScanFinding{{Kind: "mcp_server", Key: seeded, Attributes: map[string]string{"name": "decoy"}}}
	if r, err := inv.SubmitScan(person, "laptop", pre); err != nil || r.Created != 1 {
		t.Fatalf("a person's finding: %+v %v", r, err)
	}
	workflow := []aapp.ScanFinding{{Kind: "github_workflow", Key: seeded, Attributes: map[string]string{"repository": "acme/payments", "path": ".github/workflows/deploy.yml"}}}
	if r, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, lease, workflow); err != nil || r.Created != 1 || r.Counted != 0 {
		t.Fatalf("the gateway's finding under a key a person submitted first: %+v %v", r, err)
	}
	if r, err := inv.SubmitScan(person, "laptop", pre); err != nil || r.Counted != 1 {
		t.Fatalf("the person's finding again: %+v %v", r, err)
	}
	listed, _, err := scans.Findings(admin, scan.ID, 0, "")
	if err != nil || len(listed) != 1 || listed[0].Attributes["kind"] != "github_workflow" || listed[0].SeenCount != 1 {
		t.Fatalf("the gateway's finding after the person's resubmission: %+v %v", listed, err)
	}
	// A person's scan filling its cap leaves the org scan's room.
	e.exec(t, `WITH a AS (INSERT INTO pc.agents (org_id, id, name, state, created_by)
		SELECT $1, gen_random_uuid(), 'd' || g, 'DISCOVERED', 'test' FROM generate_series(1, $2::int) g RETURNING id)
		INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key)
		SELECT $1, gen_random_uuid(), id, 'scan', sha256(id::text::bytea) FROM a`, e.org, aapp.MaxOpenScanDiscoveries)
	more := []aapp.ScanFinding{{Kind: "github_workflow", Key: [32]byte{8}, Attributes: map[string]string{"repository": "acme/payments", "path": ".github/workflows/release.yml"}}}
	if r, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, lease, more); err != nil || r.Created != 1 || r.Dropped != 0 {
		t.Fatalf("an org scan finding with the people's room full: %+v %v", r, err)
	}
}

// TestHR209_AnOrgScanHasThreeLeasesAtMost: a scan whose leases keep ending
// unreported is not leased again and again, each time spending the
// installation's API quota: its third unreported lease fails it.
func TestHR209_AnOrgScanHasThreeLeasesAtMost(t *testing.T) {
	e := newEnv(t)
	gateway := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", e.org, gateway)
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	conn := e.gitHubConnection(t, gateway, e.brokerKey(t, gateway), "github", false)
	admin := e.caller(td.KindUser, td.RoleSecurityAdmin)
	team := &app.Scans{Pool: e.pool, Ents: edition(billing.Team)}
	scan, err := team.Start(admin, conn)
	if err != nil {
		t.Fatal(err)
	}
	store := &pgtransactions.Store{Pool: e.pool}
	for attempt := 1; attempt <= 3; attempt++ {
		leases, err := store.Claim(context.Background(), e.org, gateway, 4, 30*time.Second)
		if err != nil || len(leases) != 1 {
			t.Fatalf("lease %d: %+v %v", attempt, leases, err)
		}
		e.exec(t, "UPDATE pc.verifications SET leased_at = now() - interval '20 seconds', lease_expires_at = now() - interval '1 second' WHERE org_id = $1 AND purpose = 'org_scan' AND state = 'LEASED'", e.org)
		if _, err := store.Expire(context.Background(), e.org, nil); err != nil {
			t.Fatal(err)
		}
		e.exec(t, "UPDATE pc.verifications SET next_at = now() WHERE org_id = $1 AND purpose = 'org_scan' AND state = 'PENDING'", e.org)
	}
	if leases, err := store.Claim(context.Background(), e.org, gateway, 4, 30*time.Second); err != nil || len(leases) != 0 {
		t.Fatalf("a fourth lease: %+v %v", leases, err)
	}
	if got, err := team.Get(admin, scan.ID); err != nil || got.State != "FAILED" {
		t.Fatalf("after three unreported leases: %+v %v", got, err)
	}
}

// TestHR209_ADismissedFindingReopensWhenItsRouteMayDoMore: a finding
// dismissed for what its route could do is only counted while that stays
// the same; once the scan sees it differently (it may now write, deploy
// or read a new secret), it reopens for a new DISCOVERED agent, audited,
// so people and coverage see the route again.
func TestHR209_ADismissedFindingReopensWhenItsRouteMayDoMore(t *testing.T) {
	e := newEnv(t)
	gateway := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", e.org, gateway)
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	conn := e.gitHubConnection(t, gateway, e.brokerKey(t, gateway), "github", false)
	scans := &app.Scans{Pool: e.pool, Ents: edition(billing.Team)}
	scan, err := scans.Start(e.caller(td.KindUser, td.RoleSecurityAdmin), conn)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := (&pgtransactions.Store{Pool: e.pool}).Claim(context.Background(), e.org, gateway, 4, 30*time.Second)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases %+v %v", leases, err)
	}
	inv := aapp.NewInventory(e.pool, edition(billing.Team))
	submit := func(attrs map[string]string) aapp.ScanResult {
		t.Helper()
		r, err := inv.SubmitGitHubScan(context.Background(), e.org, gateway, scan.ID, leases[0].Secret,
			[]aapp.ScanFinding{{Kind: "github_workflow", Key: [32]byte{9}, Attributes: attrs}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	readOnly := map[string]string{"repo": "acme/payments", "path": ".github/workflows/claude.yml", "agent_actions": "anthropics/claude-code-action",
		"permissions": "contents:read", "writes": "false", "deploys": "false"}
	if r := submit(readOnly); r.Created != 1 {
		t.Fatalf("first %+v", r)
	}
	e.exec(t, "UPDATE pc.discoveries SET state = 'DISMISSED' WHERE org_id = $1 AND source = 'github_scan'", e.org)
	if r := submit(readOnly); r.Counted != 1 || r.Reopened != 0 {
		t.Fatalf("the same route again %+v", r)
	}
	writes := maps.Clone(readOnly)
	writes["permissions"], writes["writes"], writes["deploys"], writes["environments"] = "contents:write", "true", "true", "production"
	if r := submit(writes); r.Created != 1 || r.Reopened != 1 {
		t.Fatalf("a route that may now write and deploy %+v", r)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND source = 'github_scan' AND state = 'OPEN' AND observed->>'writes' = 'true'", e.org); n != 1 {
		t.Fatalf("%d reopened findings", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1 AND state = 'DISCOVERED'", e.org); n != 2 {
		t.Fatalf("%d discovered agents, want the first and the reopened one's", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agents.discovery_reopened'", e.org); n != 1 {
		t.Fatalf("%d reopen events", n)
	}
}
