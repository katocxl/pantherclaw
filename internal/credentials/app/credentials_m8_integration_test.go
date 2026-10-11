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
	in.Kind = domain.KindGitHubApp
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
