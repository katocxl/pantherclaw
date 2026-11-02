// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"fmt"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check migrations 00290 and 00291 (G0 M26 D400-D402, D408).
// Names carry m26ida so that they never collide with other schema tests.

const (
	m26idaIssuer = `INSERT INTO pc.org_assertion_issuers (org_id, id, name, issuer, audience, algorithms, created_by, updated_by)
	VALUES ($1, $2, $3, $4, 'https://pc.example.com/orgs/x', ARRAY['RS256'], $5, $5)`
	m26idaClient = `INSERT INTO pc.org_assertion_clients (org_id, id, issuer_id, client_id, agent_id, created_by)
	VALUES ($1, $2, $3, $4, $5, $6)`
	m26idaAgent    = "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, $3, 'DISCOVERED', 'system')"
	m26idaInstance = `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
	VALUES ($1, $2, $3, $4, '{}', 'PENDING_ADMISSION', 'mcp_client')`
	m26idaMcpClient = `INSERT INTO pc.mcp_clients (org_id, id, client_url, agent_id, instance_id, created_by)
	VALUES ($1, $2, $3, $4, $5, $6)`
)

func m26idaJKT(n int) string { return fmt.Sprintf("%043d", n) }

// TestTenancy_org_assertion_issuers: an org's issuers and bindings are
// invisible to and unchangeable by another org; an issuer that has been
// ACTIVE is fixed; a client id is one agent; rows are never deleted.
//
// Covers: F911
func TestTenancy_org_assertion_issuers(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	iss, agent, agent2 := m5ID(), m5ID(), m5ID()
	a.mustExec(t, m26idaIssuer, a.org, iss, "okta", "https://acme.okta.com", a.user)
	a.mustExec(t, m26idaAgent, a.org, agent, "a1")
	a.mustExec(t, m26idaAgent, a.org, agent2, "a2")
	bind := m5ID()
	a.mustExec(t, m26idaClient, a.org, bind, iss, "client-1", agent, a.user)

	a.want(t, m5Check, "an http issuer", m26idaIssuer, a.org, m5ID(), "plain", "http://acme.okta.com", a.user)
	a.want(t, m5Unique, "the same issuer twice", m26idaIssuer, a.org, m5ID(), "other", "https://acme.okta.com", a.user)
	a.want(t, m5Unique, "one client id, two agents", m26idaClient, a.org, m5ID(), iss, "client-1", agent2, a.user)
	a.want(t, m5Check, "an algorithm outside the list",
		"UPDATE pc.org_assertion_issuers SET algorithms = ARRAY['HS256'] WHERE id = $1", iss)
	a.want(t, m5Check, "ACTIVE without activated_at", "UPDATE pc.org_assertion_issuers SET state = 'ACTIVE' WHERE id = $1", iss)

	// While PENDING the issuer may change; once ACTIVE it is fixed.
	a.mustExec(t, "UPDATE pc.org_assertion_issuers SET issuer = 'https://acme2.okta.com' WHERE id = $1", iss)
	a.mustExec(t, "UPDATE pc.org_assertion_issuers SET state = 'ACTIVE', activated_at = now() WHERE id = $1", iss)
	for _, col := range []string{"issuer = 'https://evil.example.com'", "audience = 'https://evil.example.com'", "tenant = 'evil'"} {
		a.want(t, m5Check, "an active issuer changes: "+col, "UPDATE pc.org_assertion_issuers SET "+col+" WHERE id = $1", iss)
	}
	a.mustExec(t, "UPDATE pc.org_assertion_issuers SET state = 'DISABLED', disabled_by = $2, disabled_at = now() WHERE id = $1", iss, a.user)
	a.want(t, m5Check, "a disabled issuer changes", "UPDATE pc.org_assertion_issuers SET issuer = 'https://evil.example.com' WHERE id = $1", iss)
	a.want(t, m5Denied, "an issuer is deleted", "DELETE FROM pc.org_assertion_issuers WHERE id = $1", iss)
	a.want(t, m5Denied, "a binding is deleted", "DELETE FROM pc.org_assertion_clients WHERE id = $1", bind)
	a.want(t, m5Denied, "a binding is re-pointed", "UPDATE pc.org_assertion_clients SET agent_id = $2 WHERE id = $1", bind, agent2)

	for _, sql := range []string{"SELECT count(*) FROM pc.org_assertion_issuers", "SELECT count(*) FROM pc.org_assertion_clients"} {
		if n := m10Count(t, p, b.org, sql); n != 0 {
			t.Fatalf("another org: %s = %d", sql, n)
		}
	}
	b.want(t, m5Check, "an issuer in another org (org write guard)", m26idaIssuer, a.org, m5ID(), "other", "https://x.okta.com", b.user)
}

// TestTenancy_mcp_clients: the MCP tables are invisible to another org, the
// opt-in needs a gateway URL, a client URL is one agent, and the audit reader
// never sees a code or token hash.
//
// Covers: F913
func TestTenancy_mcp_clients(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	agent, agent2, inst, inst2, client := m5ID(), m5ID(), m5ID(), m5ID(), m5ID()
	a.mustExec(t, m26idaAgent, a.org, agent, "a1")
	a.mustExec(t, m26idaAgent, a.org, agent2, "a2")
	a.mustExec(t, m26idaInstance, a.org, inst, agent, m26idaJKT(1))
	a.mustExec(t, m26idaInstance, a.org, inst2, agent2, m26idaJKT(2))
	const url = "https://client.example.com/oauth/client.json"
	a.mustExec(t, m26idaMcpClient, a.org, client, url, agent, inst, a.user)

	a.want(t, m5Unique, "one client URL, two agents", m26idaMcpClient, a.org, m5ID(), url, agent2, inst2, a.user)
	a.want(t, m5Unique, "two clients, one instance", m26idaMcpClient, a.org, m5ID(), url+"2", agent, inst, a.user)
	a.want(t, m5Check, "a client URL without a path", m26idaMcpClient, a.org, m5ID(), "https://client.example.com", agent2, inst2, a.user)
	a.want(t, m5Check, "on without a gateway URL",
		"INSERT INTO pc.org_mcp_access (org_id, enabled, updated_by) VALUES ($1, true, $2)", a.org, a.user)
	a.want(t, m5Check, "an attested client instance",
		"UPDATE pc.agent_instances SET att_level = 2, attested_until = now(), issuer_revision_id = NULL WHERE id = $1", inst)
	a.mustExec(t, "INSERT INTO pc.org_mcp_access (org_id, enabled, gateway_url, updated_by) VALUES ($1, true, 'https://gw.example.com', $2)", a.org, a.user)

	a.want(t, m5Check, "a code living past a minute", `INSERT INTO pc.mcp_authorization_codes
		(org_id, code_hash, client_id, user_id, redirect_uri, code_challenge, resource, expires_at)
		VALUES ($1, $2, $3, $4, 'http://127.0.0.1/cb', repeat('a', 43), 'https://gw.example.com/mcp-oauth/x', now() + interval '2 minutes')`,
		a.org, m5Secret(9), client, a.user)

	for _, sql := range []string{
		"SELECT count(*) FROM pc.org_mcp_access", "SELECT count(*) FROM pc.mcp_clients",
		"SELECT count(*) FROM pc.mcp_authorization_codes", "SELECT count(*) FROM pc.mcp_refresh_tokens",
	} {
		if n := m10Count(t, p, b.org, sql); n != 0 {
			t.Fatalf("another org: %s = %d", sql, n)
		}
	}
	b.want(t, m5Check, "a client in another org (org write guard)", m26idaMcpClient, a.org, m5ID(), url+"3", agent, inst, b.user)

	var code, token bool
	d.AdminQueryRow(t, `SELECT has_column_privilege('pc_audit_ro', 'pc.mcp_authorization_codes', 'code_hash', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.mcp_refresh_tokens', 'token_hash', 'SELECT')`, nil, &code, &token)
	if code || token {
		t.Fatalf("pc_audit_ro may read hashes: code=%v token=%v", code, token)
	}
}

// TestHR620_RootRunLauncherInstanceOnlyForIDJAG: a root run has a launcher
// instance only with source id_jag, which must also name the subject and the
// user (D408).
//
// Covers: F910
func TestHR620_RootRunLauncherInstanceOnlyForIDJAG(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	inst := newID()
	f.mustExec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, f.org, inst, f.agent, testJKT)
	const insert = `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_instance_id, launcher_user_id,
		principal_user_id, principal_source, subject_issuer, subject_subject, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now() + interval '8 hours')`
	none := (*string)(nil)
	iss, sub := "https://acme.okta.com", "00u1"
	f.mustExec(t, insert, f.org, newID(), f.agent, f.env, inst, none, f.owner, "id_jag", iss, sub)
	f.wantState(t, checkViolation, "a launcher source with a launcher instance", insert,
		f.org, newID(), f.agent, f.env, inst, f.owner, f.owner, "launcher", none, none)
	f.wantState(t, checkViolation, "a subject token source with a launcher instance", insert,
		f.org, newID(), f.agent, f.env, inst, none, f.owner, "subject_token", iss, sub)
	f.wantState(t, checkViolation, "id_jag without a launcher instance", insert,
		f.org, newID(), f.agent, f.env, none, f.owner, f.owner, "id_jag", iss, sub)
	f.wantState(t, checkViolation, "id_jag without its subject", insert,
		f.org, newID(), f.agent, f.env, inst, none, f.owner, "id_jag", none, none)
}
