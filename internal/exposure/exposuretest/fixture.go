// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package exposuretest builds an org for breach-radius and posture
// integration tests: two agents, a payments connection on the mock
// payments package with a static credential, grants, dispatches and
// coverage snapshots.
package exposuretest

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// Digest is a placeholder package digest.
const Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Org is a test org.
type Org struct {
	D    *dbtest.DB
	P    *db.Pool
	Org  ids.OrgID
	User ids.UUID
	Env  ids.UUID
	// Agent and Other are two agents; Run is Agent's run.
	Agent, Other, Run ids.UUID
	Gateway, Conn     ids.UUID
	Pkg, Version      ids.UUID
}

// New builds the org in a fresh database.
func New(t *testing.T) *Org {
	t.Helper()
	d := dbtest.New(t)
	return NewIn(t, d, d.AppPool(t))
}

// NewIn builds another org in an existing database.
func NewIn(t *testing.T, d *dbtest.DB, p *db.Pool) *Org {
	t.Helper()
	o := &Org{
		D: d, P: p, Org: ids.New[ids.Org](), User: ids.NewV7(), Env: ids.NewV7(), Agent: ids.NewV7(), Other: ids.NewV7(),
		Run: ids.NewV7(), Gateway: ids.NewV7(), Conn: ids.NewV7(), Pkg: ids.NewV7(), Version: ids.NewV7(),
	}
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'exposure')", []any{o.Org}},
		{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", []any{o.Org, o.User}},
		{"INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", []any{o.Org, o.Env}},
		{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", []any{o.Org, o.Agent}},
		{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'other', 'DISCOVERED', 'test')", []any{o.Org, o.Other}},
		{`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source,
			expires_at) VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, []any{o.Org, o.Run, o.Agent, o.Env, o.User}},
		{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", []any{o.Org, o.Gateway}},
		{`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
			destination_class, created_by, updated_by) VALUES ($1, $2, 'payments', 'http', $3, 'pc.mock-payments',
			'https://api.example.com', 'pantherclaw_held', 'enforce', 'internal', 'test', 'test')`, []any{o.Org, o.Conn, o.Gateway}},
		{"INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, 'pc.mock-payments')", []any{o.Org, o.Pkg}},
		{`INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
			VALUES ($1, $2, $3, '1.0.0', $4, $5, 'ACTIVE')`, []any{o.Org, o.Version, o.Pkg, Digest, mockpayments.Package}},
		{
			`INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, '1.0.0', $4)`,
			[]any{o.Org, o.Pkg, o.Version, Digest},
		},
	} {
		o.Exec(t, s.sql, s.args...)
	}
	return o
}

// Exec runs one statement in the org's tenant transaction.
func (o *Org) Exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// Tx runs fn in the org's tenant transaction.
func (o *Org) Tx(t *testing.T, fn func(ctx context.Context, tx db.TenantTx) error) {
	t.Helper()
	if err := o.P.InTenantTx(context.Background(), o.Org, fn); err != nil {
		t.Fatal(err)
	}
}

// Grant issues agent a root grant over ops (none: every operation) for a
// day, with delegation depth depth, created age ago (a Postgres interval).
func (o *Org) Grant(t *testing.T, agent ids.UUID, depth int, age string, ops ...string) ids.UUID {
	t.Helper()
	grant := ids.NewV7()
	if age == "" {
		age = "0 seconds"
	}
	o.Exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision,
		grantor_kind, grantor_id, basis, created_at) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test', now() - $6::interval)`,
		o.Org, grant, agent, o.User, o.Env, age)
	bounds := `{}`
	if len(ops) > 0 {
		bounds = `{"operations":["` + strings.Join(ops, `","`) + `"]}`
	}
	o.Exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements,
		limits, delegation_depth, max_children, min_attestation, widens, created_by) VALUES ($1, $2, $3, 1, now() - interval '1 hour',
		now() + interval '1 day', $4, '\x7b7d', '\x7b7d', $5, 0, 0, false, 'test')`,
		o.Org, ids.NewV7(), grant, []byte(bounds), depth)
	o.Exec(t, `INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)`, o.Org, grant)
	return grant
}

// Revoke revokes a grant.
func (o *Org) Revoke(t *testing.T, grant ids.UUID) {
	t.Helper()
	o.Exec(t, `UPDATE pc.grants SET state = 'REVOKED', revoked_at = now(), revoke_reason = 'test' WHERE id = $1`, grant)
}

// Credential seals a placeholder static credential on the connection,
// created age ago.
func (o *Org) Credential(t *testing.T, age string) {
	t.Helper()
	broker, cert := ids.NewV7(), ids.NewV7()
	o.Exec(t, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, 'ENROLL', now(), now() + interval '24 hours')`, o.Org, cert, o.Gateway, cert[:16],
		bytes.Repeat([]byte("A"), 43))
	o.Exec(t, `INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
		VALUES ($1, $2, $3, 1, $4, 'sha256:' || encode(sha256($4), 'hex'), $5)`, o.Org, broker, o.Gateway,
		bytes.Repeat([]byte{7}, 1216), cert)
	o.Exec(t, `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header,
		created_by, created_at) VALUES ($1, $2, $3, 1, $4, $5, '{api.example.com}', 'Authorization', 'test', now() - $6::interval)`,
		o.Org, ids.NewV7(), o.Conn, broker, bytes.Repeat([]byte{1}, 1200), age)
}

// Dispatch records a dispatched transaction of op by the run.
func (o *Org) Dispatch(t *testing.T, op string) ids.UUID {
	t.Helper()
	txn, permit := ids.NewV7(), ids.NewV7()
	o.Exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http', 'enforce')`,
		o.Org, txn, o.Run, ids.NewV7(), make([]byte, 32), op, o.Conn)
	o.Exec(t, `INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, state, expires_at, dispatching_at, finished_at)
		VALUES ($1, $2, $3, 'gw', 1, 'DISPATCHED', now() + interval '5 seconds', now(), now())`, o.Org, permit, txn)
	o.Exec(t, `INSERT INTO pc.execution_attempts (org_id, id, permit_id, transaction_id, outcome, target_status, target_ref)
		VALUES ($1, $2, $3, $4, 'accepted', 200, 're_1')`, o.Org, ids.NewV7(), permit, txn)
	return txn
}

// Claim places agent in a new team (with an environment of its own) owned
// by the org's user, and returns the team: a caller bound at that team
// sees the agent, and nothing at org scope.
func (o *Org) Claim(t *testing.T, agent ids.UUID) ids.UUID {
	t.Helper()
	team, env := ids.NewV7(), ids.NewV7()
	slug := "t" + strings.ReplaceAll(team.String(), "-", "")[:12]
	o.Exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, $3, 'Team')", o.Org, team, slug)
	o.Exec(t, `INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, $4, 'Env', 'DEVELOPMENT')`,
		o.Org, env, team, slug)
	o.D.AdminExec(t, `UPDATE pc.agents SET state = 'CLAIMED', claimed_at = now(), team_id = $2, environment_id = $3,
		owner_user_id = $4, execution_context = 'ci' WHERE id = $1`, agent, team, env, o.User)
	return team
}
