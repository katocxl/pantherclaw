// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check migration 00223 (G0 M18 D155). Names carry m18idps so
// that they never collide with other milestones' schema tests here.

const m18idpsInsert = `INSERT INTO pc.org_identity_providers (org_id, id, name, issuer, client_id, client_secret, created_by, updated_by)
	VALUES ($1, $2, $3, $4, 'client', $5, $6, $6)`

// TestTenancy_org_identity_providers: an org's providers and its "own
// providers only" setting are invisible to and unchangeable by another
// org; the issuer of a provider that has been ACTIVE can't change, even
// after it is disabled (T-207); only https issuers are stored; the audit
// reader can't read the sealed secret (HR-482).
//
// Covers: PN-012.7
func TestTenancy_org_identity_providers(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	prov := m5ID()
	a.mustExec(t, m18idpsInsert, a.org, prov, "acme", "https://idp.example.com", m5Secret(1), a.user)
	a.want(t, m5Check, "an http issuer", m18idpsInsert, a.org, m5ID(), "plain", "http://idp.example.com", m5Secret(1), a.user)
	a.want(t, "23505", "a second provider of the same name", m18idpsInsert, a.org, m5ID(), "acme", "https://x.example.com", m5Secret(1), a.user)
	a.want(t, m5Check, "ACTIVE without activated_at", "UPDATE pc.org_identity_providers SET state = 'ACTIVE' WHERE id = $1", prov)

	// While PENDING the issuer may change; once ACTIVE it is fixed.
	a.mustExec(t, "UPDATE pc.org_identity_providers SET issuer = 'https://idp2.example.com' WHERE id = $1", prov)
	a.mustExec(t, "UPDATE pc.org_identity_providers SET state = 'ACTIVE', activated_at = now() WHERE id = $1", prov)
	a.want(t, m5Check, "the issuer of an active provider changes",
		"UPDATE pc.org_identity_providers SET issuer = 'https://evil.example.com' WHERE id = $1", prov)
	a.mustExec(t, "UPDATE pc.org_identity_providers SET state = 'DISABLED', disabled_by = $2, disabled_at = now() WHERE id = $1", prov, a.user)
	a.want(t, m5Check, "the issuer of a disabled provider changes",
		"UPDATE pc.org_identity_providers SET issuer = 'https://evil.example.com' WHERE id = $1", prov)
	a.want(t, m5Check, "activated_at is reset",
		"UPDATE pc.org_identity_providers SET activated_at = NULL, state = 'PENDING', disabled_by = NULL, disabled_at = NULL WHERE id = $1", prov)
	a.want(t, m5Denied, "a provider is deleted", "DELETE FROM pc.org_identity_providers WHERE id = $1", prov)
	a.want(t, m5Denied, "the creator is rewritten", "UPDATE pc.org_identity_providers SET created_by = $2 WHERE id = $1", prov, a.user)
	a.mustExec(t, "INSERT INTO pc.org_identity_provider_settings (org_id, own_providers_only, updated_by) VALUES ($1, true, $2)", a.org, a.user)

	// Another org sees and changes nothing, and can't write into ours.
	for _, sql := range []string{"SELECT count(*) FROM pc.org_identity_providers", "SELECT count(*) FROM pc.org_identity_provider_settings"} {
		if n := m10Count(t, p, b.org, sql); n != 0 {
			t.Fatalf("another org: %s = %d", sql, n)
		}
	}
	b.mustExec(t, "UPDATE pc.org_identity_providers SET client_id = 'x'")
	b.mustExec(t, "UPDATE pc.org_identity_provider_settings SET own_providers_only = false")
	b.want(t, m5Denied, "a provider in another org", m18idpsInsert, a.org, m5ID(), "other", "https://idp.example.com", m5Secret(1), b.user)
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.org_identity_providers WHERE client_id = 'client'"); n != 1 {
		t.Fatalf("another org changed our provider: %d", n)
	}
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.org_identity_provider_settings WHERE own_providers_only"); n != 1 {
		t.Fatalf("another org changed our setting: %d", n)
	}

	// HR-482: the audit reader can't read the sealed secret.
	var granted bool
	d.AdminQueryRow(t, "SELECT has_column_privilege('pc_audit_ro', 'pc.org_identity_providers', 'client_secret', 'SELECT')", nil, &granted)
	if granted {
		t.Fatal("pc_audit_ro may read client_secret")
	}
}
