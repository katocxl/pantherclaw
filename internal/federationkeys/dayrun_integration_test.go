// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package federationkeys

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func execOrg(t *testing.T, p *db.Pool, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// TestHR775_AReplacedGrantGetsItsOwnDayRun: the peer's run is keyed by the
// grant, so a grant replaced during the UTC day is used at once (D1024e).
func TestHR775_AReplacedGrantGetsItsOwnDayRun(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	org := ids.New[ids.Org]()
	user, team, env := ids.NewV7(), ids.NewV7(), ids.NewV7()
	agent, inst := ids.NewV7(), ids.NewV7()
	trust, peer := ids.NewV7(), ids.NewV7()
	grantA, grantB := ids.NewV7(), ids.NewV7()
	execOrg(t, p, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertContainment(ctx, org)
	}); err != nil {
		t.Fatal(err)
	}
	execOrg(t, p, org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'pay', 'Pay')", org, team)
	execOrg(t, p, org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')", org, env, team)
	execOrg(t, p, org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", org, user)
	execOrg(t, p, org, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, 'peer-bot', $3, $4, $5, 'service', 'VERIFIED', 'test', now())`, org, agent, team, env, user)
	execOrg(t, p, org, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'federation')`, org, inst, agent, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	execOrg(t, p, org, `INSERT INTO pc.federation_trusts (org_id, id, peer_org_id, peer_name, peer_doc_url, peer_server_url,
		pinned_jwks, pinned_keys_digest, peer_document, peer_doc_expires_at, safety_code, created_by)
		VALUES ($1, $2, $3, 'Peer', 'https://peer.example/federation.json', 'https://peer.example',
		'{}', $4, '\x7b7d', now() + interval '1 day', 'AAAA BBBB CCCC DDDD EEEE', 'test')`,
		org, trust, peer, make([]byte, 32))
	for _, g := range []ids.UUID{grantA, grantB} {
		execOrg(t, p, org, `INSERT INTO pc.grants (org_id, id, agent_id, instance_id, principal_user_id, environment_id,
			depth, current_revision, grantor_kind, grantor_id, basis)
			VALUES ($1, $2, $3, $4, $5, $6, 0, 1, 'user', $5, 'grant.issue')`, org, g, agent, inst, user, env)
	}
	fa := dbq.GetFederationAgentRow{AgentID: agent, InstanceID: inst, EnvironmentID: &env, PeerAgent: "pc:org/" + peer.String() + "/agent/bot"}
	tr := dbq.PcFederationTrust{ID: trust, PeerOrgID: peer, PeerName: "Peer"}
	now := time.Now().UTC()
	var first, second, again ids.UUID
	err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		first, err = dayRun(ctx, q, org, tr, fa, grantA, now)
		if err != nil {
			return err
		}
		again, err = dayRun(ctx, q, org, tr, fa, grantA, now)
		if err != nil {
			return err
		}
		second, err = dayRun(ctx, q, org, tr, fa, grantB, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if first != again || first == second || first.IsZero() {
		t.Fatalf("runs %s then %s for the new grant", first, second)
	}
	_ = pgtype.Date{}
}
