// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type m34Unlimited struct{}

func (m34Unlimited) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition, e.Limits.MaxAgents = billing.Business, billing.Unlimited
	return e, nil
}

// m34InstancePrincipal reads grants as the store does but names an instance
// as their principal, which the schema never allows: the store returning
// what it must not.
type m34InstancePrincipal struct{ s *grantspg.Store }

func (g m34InstancePrincipal) GrantInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id gdomain.GrantID) (gdomain.Grant, bool, error) {
	gr, found, err := g.s.GrantInTx(ctx, tx, org, id)
	gr.Principal = gdomain.Principal{Kind: gdomain.PrincipalInstance, ID: ids.NewV7()}
	return gr, found, err
}

type m34World struct {
	pool                    *db.Pool
	org                     ids.OrgID
	team, env, owner, agent ids.UUID
	grant                   ids.UUID
}

func newM34World(t *testing.T) *m34World {
	t.Helper()
	w := &m34World{pool: dbtest.New(t).AppPool(t), org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(), owner: ids.NewV7()}
	w.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", w.org, w.team)
	w.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')",
		w.org, w.env, w.team)
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.owner)
	owner := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.owner},
		Bindings: []td.Binding{{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeTeam, ID: w.team}}},
	}, Credential: tenancy.CredAccessToken})
	a, err := aapp.NewInventory(w.pool, m34Unlimited{}).Create(owner, adomain.Details{
		Name: "orders-gw", TeamID: w.team, EnvironmentID: w.env, OwnerUserID: w.owner, Context: adomain.ContextService,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.agent = a.ID
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return aapp.MarkVerified(ctx, dbq.New(tx), w.org, a.ID, adomain.System)
	}); err != nil {
		t.Fatal(err)
	}
	w.grant = ids.NewV7()
	w.exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth,
		current_revision, grantor_kind, grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`,
		w.org, w.grant, w.agent, w.owner, w.env)
	w.exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements, limits,
		delegation_depth, max_children, min_attestation, widens, created_by)
		VALUES ($1, $2, $3, 1, now() - interval '1 hour', now() + interval '2 hours',
		convert_to('{"operations":["payments.refund.create"]}', 'UTF8'), convert_to('[]', 'UTF8'), convert_to('{}', 'UTF8'),
		0, 0, 0, false, 'test')`, w.org, ids.NewV7(), w.grant)
	w.exec(t, "INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)", w.org, w.grant)
	return w
}

func (w *m34World) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (w *m34World) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// issuer inserts an issuer revision of kind for the world's agent in state,
// with the world's grant as its run grant when withGrant.
func (w *m34World) issuer(t *testing.T, kind, state string, withGrant bool) ids.UUID {
	t.Helper()
	rev := ids.NewV7()
	var g *ids.UUID
	if withGrant {
		g = &w.grant
	}
	activated := "now()"
	if state == "PROPOSED" {
		activated = "NULL"
	}
	by := "'test'"
	if state == "PROPOSED" {
		by = "NULL"
	}
	w.exec(t, `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience, algorithms,
		binding, state, proposed_by, activated_by, activated_at, run_grant_id) VALUES ($1, $2, $3, 1, $4, $5, 'https://issuer.test', $6,
		'{RS256}', '{"x":{}}', $7, 'test', `+by+`, `+activated+`, $8)`,
		w.org, rev, ids.NewV7(), w.agent, kind, "pantherclaw:"+w.org.String(), state, g)
	return rev
}

// instance inserts an admitted instance of the world's agent enrolled
// through rev at level, attested until now + until.
func (w *m34World) instance(t *testing.T, rev ids.UUID, level int, until string) pap.Instance {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := ids.NewV7()
	w.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via, issuer_revision_id,
		binding, att_level, attested_until, expires_at)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'attestation', $5, '{}', $6, now() + $7::interval, now() + interval '1 day')`,
		w.org, id, w.agent, base64.RawURLEncoding.EncodeToString(b), rev, level, until)
	return pap.Instance{Org: w.org, Agent: w.agent, Instance: id}
}

func (w *m34World) runtime(grants runsapp.Grants) *runtimeRuns {
	return &runtimeRuns{pool: w.pool, runs: runsapp.New(w.pool).WithGrants(grants), clk: clock.System{}}
}

func m34WantCode(t *testing.T, what string, err error, code pcerr.Code, reason string) {
	t.Helper()
	if pcerr.CodeOf(err) != code || pcerr.ReasonOf(err) != reason {
		t.Errorf("%s: err = %v, want %s %s", what, err, code, reason)
	}
}

// TestHR761_ARuntimeRunStartsOnlyForACloudAttestedInstanceWithARunGrant:
// StartRuntimeRun starts a run, launched by the instance under its issuer
// entry's run grant and audited runtime.run_started, for an admitted L2
// instance enrolled by aws_iam, gcp_workload, azure_mi or entra_agent_id
// attestation. Another attestation kind, an L1 or expired attestation, an
// entry no longer active, another agent's instance, an entry without a run
// grant, a run grant whose principal is no user or service account, and a
// name outside D992's set are refused, and none writes a run (G0 M34 D992).
//
// Covers: F1042, HR-761, T-345
func TestHR761_ARuntimeRunStartsOnlyForACloudAttestedInstanceWithARunGrant(t *testing.T) {
	w := newM34World(t)
	store := &grantspg.Store{Pool: w.pool}
	s := w.runtime(store)
	ctx := context.Background()
	runs := func() int { return w.count(t, "SELECT count(*)::int FROM pc.runs WHERE org_id = $1", w.org) }

	for i, kind := range []string{"aws_iam", "gcp_workload", "azure_mi", "entra_agent_id"} {
		rev := w.issuer(t, kind, "ACTIVE", true)
		in := w.instance(t, rev, 2, "1 hour")
		name := "agentcore:orders-interceptor:2026/11/05/--LATEST-abc" + kind
		run, err := s.start(ctx, in, name)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if n := w.count(t, `SELECT count(*)::int FROM pc.runs WHERE org_id = $1 AND id = $2 AND principal_source = 'trusted_issuer'
			AND launcher_instance_id = $3 AND launcher_issuer_id = $4 AND principal_user_id = $5 AND task_ref = $6`,
			w.org, run.ID, in.Instance, rev, w.owner, name); n != 1 {
			t.Errorf("%s: the run is not the instance's under the run grant", kind)
		}
		if n := w.count(t, `SELECT count(*)::int FROM pc.ledger_entries WHERE kind = 'audit.runtime.run_started'
			AND convert_from(body, 'UTF8') LIKE '%' || $1 || '%'`, run.ID.String()); n != 1 {
			t.Errorf("%s: %d runtime.run_started entries", kind, n)
		}
		if n := runs(); n != i+1 {
			t.Fatalf("%d runs after %s", n, kind)
		}
	}
	started := runs()

	good := w.instance(t, w.issuer(t, "aws_iam", "ACTIVE", true), 2, "1 hour")
	for what, in := range map[string]pap.Instance{
		"a github_actions instance":  w.instance(t, w.issuer(t, "github_actions", "ACTIVE", true), 2, "1 hour"),
		"a kubernetes instance":      w.instance(t, w.issuer(t, "kubernetes", "ACTIVE", true), 2, "1 hour"),
		"an L1 instance":             w.instance(t, w.issuer(t, "aws_iam", "ACTIVE", true), 1, "1 hour"),
		"an expired attestation":     w.instance(t, w.issuer(t, "aws_iam", "ACTIVE", true), 2, "-1 minute"),
		"a disabled entry":           w.instance(t, w.issuer(t, "aws_iam", "DISABLED", true), 2, "1 hour"),
		"another agent's credential": {Org: w.org, Agent: ids.NewV7(), Instance: good.Instance},
		"an instance of no row":      {Org: w.org, Agent: w.agent, Instance: ids.NewV7()},
	} {
		_, err := s.start(ctx, in, "agentcore:f:s")
		m34WantCode(t, what, err, pcerr.PermissionDenied, "RUNTIME_NOT_CLOUD_INSTANCE")
	}
	_, err := s.start(ctx, w.instance(t, w.issuer(t, "aws_iam", "ACTIVE", false), 2, "1 hour"), "agentcore:f:s")
	m34WantCode(t, "an entry without a run grant", err, pcerr.FailedPrecondition, "RUNTIME_NO_RUN_GRANT")
	_, err = w.runtime(m34InstancePrincipal{store}).start(ctx, good, "agentcore:f:s")
	m34WantCode(t, "an instance principal", err, pcerr.FailedPrecondition, "RUNTIME_RUN_GRANT_PRINCIPAL")
	for _, name := range []string{"", strings.Repeat("a", 201), "agentcore:f:2026/11/05/[$LATEST]abc", "a b", "a\nb", "ä"} {
		_, err := s.start(ctx, good, name)
		m34WantCode(t, "name "+name, err, pcerr.InvalidArgument, "RUNTIME_RUN_NAME")
	}
	if _, err := s.start(ctx, good, strings.Repeat("a", 200)); err != nil {
		t.Errorf("a 200-character name: %v", err)
	}
	if n := runs(); n != started+1 {
		t.Errorf("%d runs after the refusals, want %d", n, started+1)
	}
}
