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
	if err := report(map[string]string{"/secrets/production": "x"}); !errors.Is(err, tapp.ErrUndeclared) {
		t.Fatalf("a field that is no summary: %v", err)
	}
	if err := report(map[string]string{
		"/counts/repositories": "3", "/counts/workflows": "2", "/scanned/repositories": "true", "/scanned/workflows": "true",
		"/not_scanned/org_installations": "the App lacks organization_administration:read",
	}); err != nil {
		t.Fatal(err)
	}
	done, err := team.Get(admin, scan.ID)
	if err != nil || done.State != "DONE" || done.FinishedAt == nil || !maps.Equal(done.Counts, map[string]int64{"repositories": 3, "workflows": 2}) ||
		!slices.Equal(done.Scanned, []string{"repositories", "workflows"}) || done.NotScanned["org_installations"] == "" {
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
