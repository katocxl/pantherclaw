// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/app"
	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// TestHR204_AGitHubAppCredentialKeepsItsKind: the kind is stored, listed
// and sent to the gateway; a GitHub App credential needs Authorization:
// Bearer, and an unknown kind is refused. Without a kind a credential is
// static, as every credential before M8.
func TestHR204_AGitHubAppCredentialKeepsItsKind(t *testing.T) {
	e := newEnv(t)
	_, in := e.seal(t, "sk_live_static")
	m, err := e.svc.PutCredential(e.sealer, in)
	if err != nil || m.Kind != domain.KindStatic {
		t.Fatalf("static: %+v %v", m, err)
	}
	_, in = e.seal(t, `{"v":1}`)
	in.Kind = "oauth"
	if _, err := e.svc.PutCredential(e.sealer, in); !is(err, app.ErrKind) {
		t.Fatalf("an unknown kind: %v", err)
	}
	in.Kind, in.GitHub = domain.KindGitHubApp, &domain.Installation{AppClientID: "Iv23liApp", ID: 7, Account: "acme"}
	m, err = e.svc.PutCredential(e.sealer, in)
	if err != nil || m.Kind != domain.KindGitHubApp {
		t.Fatalf("github_app: %+v %v", m, err)
	}
	listed, err := e.svc.ListCredentials(e.sealer, e.conn.ID)
	if err != nil || len(listed) != 2 || listed[0].Kind != domain.KindGitHubApp || listed[1].Kind != domain.KindStatic {
		t.Fatalf("listed %+v %v", listed, err)
	}
	var kind string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT kind FROM pc.credentials WHERE state = 'ACTIVE' AND connection_id = $1", e.conn.ID).Scan(&kind)
	}); err != nil || kind != domain.KindGitHubApp {
		t.Fatalf("stored kind %q %v", kind, err)
	}
	// The table refuses a GitHub App credential placed any other way.
	err = e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.credentials SET state = 'SUPERSEDED', superseded_at = now() WHERE connection_id = $1", e.conn.ID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, scheme, created_by, kind)
			SELECT org_id, gen_random_uuid(), connection_id, 9, broker_key_id, sealed, allowed_hosts, 'X-Api-Key', NULL, 'test', 'github_app'
			FROM pc.credentials WHERE connection_id = $1 AND version = 1`, e.conn.ID)
		return err
	})
	if err == nil {
		t.Fatal("a GitHub App credential without Authorization: Bearer was stored")
	}
}

// TestHR203_AGitHubAppCredentialRecordsItsInstallation: storing a GitHub
// App credential records the installation it was sealed for as the
// connection's (connection_github), audited and shown on the connection; a
// GitHub App credential without its installation, or a static one with
// one, is refused. Sealing for another installation forgets what was read
// from the old one.
func TestHR203_AGitHubAppCredentialRecordsItsInstallation(t *testing.T) {
	e := newEnv(t)
	gh := &domain.Installation{AppClientID: "Iv23liApp", ID: 7, Account: "acme"}
	for name, c := range map[string]struct {
		kind string
		gh   *domain.Installation
	}{
		"a GitHub App without its installation": {kind: domain.KindGitHubApp},
		"a static credential with one":          {kind: domain.KindStatic, gh: gh},
		"an uppercase account":                  {kind: domain.KindGitHubApp, gh: &domain.Installation{AppClientID: "Iv23liApp", ID: 7, Account: "Acme"}},
		"no installation id":                    {kind: domain.KindGitHubApp, gh: &domain.Installation{AppClientID: "Iv23liApp", Account: "acme"}},
	} {
		_, in := e.seal(t, `{"v":1}`)
		in.Kind, in.GitHub = c.kind, c.gh
		if _, err := e.svc.PutCredential(e.sealer, in); !is(err, app.ErrInstallation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, in := e.seal(t, `{"v":1}`)
	in.Kind, in.GitHub = domain.KindGitHubApp, gh
	if _, err := e.svc.PutCredential(e.sealer, in); err != nil {
		t.Fatal(err)
	}
	conn, err := e.conns.Get(e.sealer, e.conn.ID)
	if err != nil || conn.GitHub == nil || conn.GitHub.AppClientID != "Iv23liApp" || conn.GitHub.InstallationID != 7 || conn.GitHub.AccountLogin != "acme" {
		t.Fatalf("the connection's installation: %+v %v", conn.GitHub, err)
	}
	var audited int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.sealed_stored'
			AND convert_from(body, 'UTF8')::jsonb->'details'->>'github_installation' = '7'`).Scan(&audited)
	}); err != nil || audited != 1 {
		t.Fatalf("%d audited installations: %v", audited, err)
	}
	// What was read from installation 7 is kept for a new seal of it, and
	// forgotten for installation 8.
	e.exec(t, `UPDATE pc.connection_github SET repository_selection = 'all', read_at = now(), permissions = '{"contents":"write"}' WHERE org_id = $1`, e.org)
	_, in = e.seal(t, `{"v":1}`)
	in.Kind, in.GitHub = domain.KindGitHubApp, gh
	if _, err := e.svc.PutCredential(e.sealer, in); err != nil {
		t.Fatal(err)
	}
	if conn, _ = e.conns.Get(e.sealer, e.conn.ID); conn.GitHub.RepositorySelection == nil || conn.GitHub.ReadAt == nil {
		t.Fatalf("the same installation forgot what was read: %+v", conn.GitHub)
	}
	_, in = e.seal(t, `{"v":1}`)
	in.Kind, in.GitHub = domain.KindGitHubApp, &domain.Installation{AppClientID: "Iv23liApp", ID: 8, Account: "acme"}
	if _, err := e.svc.PutCredential(e.sealer, in); err != nil {
		t.Fatal(err)
	}
	if conn, _ = e.conns.Get(e.sealer, e.conn.ID); conn.GitHub.InstallationID != 8 || conn.GitHub.RepositorySelection != nil || conn.GitHub.ReadAt != nil ||
		string(conn.GitHub.Permissions) != "{}" {
		t.Fatalf("another installation kept what was read from the old one: %+v", conn.GitHub)
	}
}
