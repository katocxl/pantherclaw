// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check migrations 00292 and 00293 (G0 M26 D405, D406). Names
// carry m26prov so that they never collide with other schema tests here.

const (
	m26provGroup = `INSERT INTO pc.groups (org_id, id, issuer, display_name) VALUES ($1, $2, 'https://idp.example.com', $3)`
	m26provMap   = `INSERT INTO pc.group_role_mappings (org_id, id, group_id, role, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`
	m26provToken = `INSERT INTO pc.scim_tokens (org_id, id, name, issuer, subject_attribute, secret_hash, hint, created_by, expires_at)
		VALUES ($1, $2, $3, 'https://idp.example.com', 'userName', $4, 'hint', 'test', now() + interval '1 day')`
	m26provSAML = `INSERT INTO pc.saml_connections (org_id, id, name, idp_entity_id, sso_url, certificates, created_by)
		VALUES ($1, $2, $3, $4, $5, ARRAY['AAAA'], 'test')`
)

// TestHR630_NoAdminRoleCanBeMappedInTheSchema: the tables themselves refuse
// an admin role in a mapping and in a binding a mapping made (R-08), whatever
// the code above them does.
//
// Covers: F920
func TestHR630_NoAdminRoleCanBeMappedInTheSchema(t *testing.T) {
	d := dbtest.New(t)
	a := newM5Fixture(t, d.AppPool(t))
	group := m5ID()
	a.mustExec(t, m26provGroup, a.org, group, "engineers")
	a.mustExec(t, m26provMap, a.org, m5ID(), group, "viewer")
	for _, role := range []string{"org_admin", "security_admin", "scope_admin"} {
		a.want(t, m5Check, "a mapping to "+role, m26provMap, a.org, m5ID(), group, role)
		a.want(t, m5Check, "a provisioned binding of "+role,
			`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, provisioned)
			 VALUES ($1, $2, $3, $4, 'ORG', 'test', true)`, a.org, m5ID(), role, a.user)
	}
	a.mustExec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, provisioned)
		VALUES ($1, $2, 'viewer', $3, 'ORG', 'test', true)`, a.org, m5ID(), a.user)
	a.mustExec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')`, a.org, m5ID(), a.user)
	a.want(t, m5Denied, "a binding's provenance is rewritten", "UPDATE pc.role_bindings SET provisioned = false WHERE user_id = $1", a.user)

	// Deleting a group takes its members and mappings with it.
	a.mustExec(t, "INSERT INTO pc.group_members (org_id, group_id, user_id) VALUES ($1, $2, $3)", a.org, group, a.user)
	a.mustExec(t, "DELETE FROM pc.groups WHERE id = $1", group)
	for _, sql := range []string{"SELECT count(*) FROM pc.group_members", "SELECT count(*) FROM pc.group_role_mappings"} {
		if n := m10Count(t, d.AppPool(t), a.org, sql); n != 0 {
			t.Fatalf("after the group went: %s = %d", sql, n)
		}
	}
}

// TestTenancy_provisioning: another org sees and changes nothing of ours; a
// token keeps only its hash, which the audit reader can't read.
//
// Covers: F918, F919
func TestTenancy_provisioning(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	group := m5ID()
	a.mustExec(t, m26provGroup, a.org, group, "engineers")
	a.want(t, "23505", "a second group of the same name", m26provGroup, a.org, m5ID(), "engineers")
	a.mustExec(t, "INSERT INTO pc.group_members (org_id, group_id, user_id) VALUES ($1, $2, $3)", a.org, group, a.user)
	a.mustExec(t, m26provMap, a.org, m5ID(), group, "viewer")
	a.mustExec(t, m26provToken, a.org, m5ID(), "okta", m5Secret(1))
	a.want(t, m5Check, "a short hash", m26provToken, a.org, m5ID(), "short", []byte("x"))
	a.mustExec(t, "INSERT INTO pc.scim_users (org_id, user_id, external_id) VALUES ($1, $2, 'ext')", a.org, a.user)

	a.want(t, m5Denied, "a token's hash is rewritten", "UPDATE pc.scim_tokens SET secret_hash = $1", m5Secret(2))
	a.want(t, m5Denied, "a token's issuer moves", "UPDATE pc.scim_tokens SET issuer = 'https://other.example.com'")
	a.want(t, m5Denied, "a token is deleted", "DELETE FROM pc.scim_tokens")
	a.want(t, m5Denied, "a group's issuer moves", "UPDATE pc.groups SET issuer = 'https://other.example.com'")

	for _, table := range []string{"groups", "group_members", "group_role_mappings", "scim_tokens", "scim_users"} {
		sql := "SELECT count(*) FROM pc." + table
		if n := m10Count(t, p, b.org, sql); n != 0 {
			t.Fatalf("another org: %s = %d", sql, n)
		}
		if n := m10Count(t, p, a.org, sql); n != 1 {
			t.Fatalf("our org: %s = %d", sql, n)
		}
	}
	b.want(t, m5Check, "a group in another org (org write guard)", m26provGroup, a.org, m5ID(), "other")

	var granted bool
	d.AdminQueryRow(t, "SELECT has_column_privilege('pc_audit_ro', 'pc.scim_tokens', 'secret_hash', 'SELECT')", nil, &granted)
	if granted {
		t.Fatal("the audit reader can read a token's hash")
	}
}

// TestHR633_SAMLConnectionSchema: the entity id never changes, the issuer
// can't equal an OpenID issuer, and sign-in goes only over https.
//
// Covers: F921
func TestHR633_SAMLConnectionSchema(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	conn := m5ID()
	a.mustExec(t, m26provSAML, a.org, conn, "okta", "https://idp.example.com", "https://idp.example.com/sso")
	a.want(t, m5Check, "an http sign-in URL", m26provSAML, a.org, m5ID(), "plain", "urn:x", "http://idp.example.com/sso")
	a.want(t, "23505", "the same entity id twice", m26provSAML, a.org, m5ID(), "again", "https://idp.example.com", "https://idp.example.com/sso")
	a.want(t, m5Check, "ACTIVE without activated_at", "UPDATE pc.saml_connections SET state = 'ACTIVE' WHERE id = $1", conn)
	a.want(t, m5Check, "DISABLED without disabled_at", "UPDATE pc.saml_connections SET state = 'DISABLED' WHERE id = $1", conn)
	a.want(t, m5Denied, "the entity id moves", "UPDATE pc.saml_connections SET idp_entity_id = 'https://evil.example.com' WHERE id = $1", conn)
	a.want(t, m5Denied, "a connection is deleted", "DELETE FROM pc.saml_connections WHERE id = $1", conn)
	a.mustExec(t, "UPDATE pc.saml_connections SET state = 'ACTIVE', activated_at = now() WHERE id = $1", conn)

	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.saml_connections WHERE issuer = 'saml:https://idp.example.com'"); n != 1 {
		t.Fatalf("issuer not prefixed: %d", n)
	}
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.saml_connections"); n != 0 {
		t.Fatalf("another org sees %d connections", n)
	}
}
