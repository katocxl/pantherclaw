// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for M8 track G
// (migration 00081): GitHub facts, identities and the organisation scan.
// The application enforces the same rules first. Names are prefixed m8g so
// that they never collide with other milestones' schema tests here.

const (
	m8gProvider = `INSERT INTO pc.fact_providers (org_id, id, name, service_account_id, gateway_id, connection_id, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, 'test')`
	m8gIdentity = `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by, verified_at)
		VALUES ($1, $2, $3, $4, $5, 'test', now())`
)

// TestHR160_GatewayProvidersAndObjectFacts: a provider has exactly one
// source, one active gateway provider per connection, and an object fact
// may be larger than a scalar one.
func TestHR160_GatewayProvidersAndObjectFacts(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	f.want(t, m5Check, "no source", m8gProvider, f.org, m5ID(), "none", nil, nil, nil)
	f.want(t, m5Check, "a gateway without its connection", m8gProvider, f.org, m5ID(), "half", nil, f.gateway, nil)
	f.mustExec(t, m8gProvider, f.org, m5ID(), "github", nil, f.gateway, f.connection)
	f.want(t, m5Unique, "a second active provider for the connection", m8gProvider, f.org, m5ID(), "github2", nil, f.gateway, f.connection)
	f.mustExec(t, `INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s)
		SELECT org_id, id, 'github.pull.head', 'object', 'github.pull_request', 30 FROM pc.fact_providers WHERE name = 'github'`)
	f.mustExec(t, `INSERT INTO pc.facts (org_id, id, name, subject_type, subject_id, provider_id, value, observed_at)
		SELECT org_id, gen_random_uuid(), 'github.pull.head', 'github.pull_request', 'acme/payments#7', id, convert_to(repeat('x', 8000), 'UTF8'), now()
		FROM pc.fact_providers WHERE name = 'github'`)
}

// TestHR207_GitHubIdentitiesAreOnePerGitHubUser: a GitHub user id links to
// one person of the org, and only a person of the org.
func TestHR207_GitHubIdentitiesAreOnePerGitHubUser(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	f.mustExec(t, m8gIdentity, f.org, m5ID(), f.user, "alice", 101)
	f.want(t, m5Unique, "one GitHub user linked twice", m8gIdentity, f.org, m5ID(), f.user, "alice2", 101)
	f.want(t, m5Check, "a login GitHub would not issue", m8gIdentity, f.org, m5ID(), f.user, "-bad-", 102)
	f.want(t, m7pForeignKey, "someone who is no person of the org", m8gIdentity, f.org, m5ID(), m5ID(), "bob", 103)
}

// TestHR207_LinksAreProvedAndARequestKeepsItsLinkedPeople (P2f, migration
// 00083): a link records when the person proved it by signing in to GitHub,
// and one nobody proved is refused; the people linked when a request was
// created are kept for that request only, and never changed or removed.
func TestHR207_LinksAreProvedAndARequestKeepsItsLinkedPeople(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	f.want(t, m5Check, "a link nobody proved", `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by)
		VALUES ($1, $2, $3, 'alice', 101, 'test')`, f.org, m5ID(), f.user)
	const kept = `INSERT INTO pc.approval_request_linked_people (org_id, request_id, fact, user_id) VALUES ($1, $2, 'github.pull.people', $3)`
	f.want(t, m7pForeignKey, "people of a request that does not exist", kept, f.org, m5ID(), f.user)
	f.want(t, m5Denied, "UPDATE approval_request_linked_people", "UPDATE pc.approval_request_linked_people SET fact = fact")
	f.want(t, m5Denied, "DELETE approval_request_linked_people", "DELETE FROM pc.approval_request_linked_people")
}

// TestHR209_ScanRunsAndOrgScanLeases: a scan run finishes with a time, a
// discovery may come from the GitHub scan, and an org scan lease has no
// transaction.
func TestHR209_ScanRunsAndOrgScanLeases(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	run := m5ID()
	f.mustExec(t, `INSERT INTO pc.github_scan_runs (org_id, id, connection_id, started_by) VALUES ($1, $2, $3, 'test')`, f.org, run, f.connection)
	f.want(t, m5Check, "done without a finish time", `UPDATE pc.github_scan_runs SET state = 'DONE' WHERE id = $1`, run)
	f.mustExec(t, `UPDATE pc.github_scan_runs SET state = 'DONE', finished_at = now() WHERE id = $1`, run)
	f.want(t, m5Denied, "DELETE github_scan_runs", "DELETE FROM pc.github_scan_runs")
	f.mustExec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key) VALUES ($1, $2, $3, 'github_scan', $4)`, f.org, m5ID(), f.agent, m5Secret(9))
	f.mustExec(t, m7Verification, f.org, m5ID(), "org_scan", nil, f.connection, nil, nil)
	f.want(t, m5Check, "an org scan with a transaction", m7Verification, f.org, m5ID(), "org_scan", f.txn, f.connection, nil, nil)
}

// TestHR203_ConnectionGitHubIsOnePerConnection: a connection records one
// GitHub installation, whose account is a lowercase GitHub login, and what
// was last read from it comes with the time it was read.
func TestHR203_ConnectionGitHubIsOnePerConnection(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	const ins = `INSERT INTO pc.connection_github (org_id, connection_id, app_client_id, installation_id, account_login, repository_selection, read_at, updated_by)
		VALUES ($1, $2, 'Iv23liApp', 7, $3, $4, $5, 'test')`
	f.want(t, m5Check, "an account GitHub would not issue", ins, f.org, f.connection, "Acme", nil, nil)
	f.want(t, m5Check, "a repository selection without its time", ins, f.org, f.connection, "acme", "all", nil)
	f.mustExec(t, ins, f.org, f.connection, "acme", nil, nil)
	f.want(t, m5Unique, "a second installation for the connection", ins, f.org, f.connection, "acme", nil, nil)
	f.want(t, m5Denied, "DELETE connection_github", "DELETE FROM pc.connection_github")
}
