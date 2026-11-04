// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// devOwnerIssuer is the issuer of the seeded owner; no provider signs for
// it, so nobody can sign in as that user.
const devOwnerIssuer = "https://dev-seed.pantherclaw.invalid"

// devWorkload is what seedWorkload created.
type devWorkload struct {
	Agent, Instance, Env, Owner ids.UUID
}

// seedWorkload adds a PAP/1 workload to a seeded org, in tx: a team, an
// environment, an owner, a CI agent and an admitted instance of a new key
// (enrolled with a consumed enrollment token, as an owner would). Its run
// is started by seedRun once its grant exists. It returns the key file to
// write (without the run). DEVELOPMENT ONLY.
func seedWorkload(ctx context.Context, tx db.TenantTx, org ids.OrgID, server string) (devWorkload, workloadclient.KeyFile, error) {
	var w devWorkload
	kf, key, err := workloadclient.NewKeyFile()
	if err != nil {
		return w, kf, err
	}
	team, env, owner := ids.NewV7(), ids.NewV7(), ids.NewV7()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'dev', 'Development')", []any{org, team}},
		{
			"INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Development', 'DEVELOPMENT')",
			[]any{org, env, team},
		},
		{
			"INSERT INTO pc.users (org_id, id, issuer, subject, display_name) VALUES ($1, $2, $3, 'dev-owner', 'Dev owner')",
			[]any{org, owner, devOwnerIssuer},
		},
	} {
		if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
			return w, kf, fmt.Errorf("dev seed: workload: %w", err)
		}
	}
	q := dbq.New(tx)
	ci := string(adomain.ContextCI)
	a, err := q.InsertAgent(ctx, dbq.InsertAgentParams{
		OrgID: org, ID: ids.NewV7(), Name: "dev-refunder", Purpose: "development refunds", TeamID: &team, EnvironmentID: &env,
		OwnerUserID: &owner, ExecutionContext: &ci, CreatedBy: "dev-seed",
	})
	if err != nil {
		return w, kf, fmt.Errorf("dev seed: agent: %w", err)
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return w, kf, err
	}
	hash := sha256.Sum256(secret[:])
	if _, err := q.InsertEnrollmentToken(ctx, dbq.InsertEnrollmentTokenParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, EnvironmentID: env, TokenHash: hash[:], CreatedBy: "dev-seed", TtlMinutes: 15,
	}); err != nil {
		return w, kf, err
	}
	et, err := q.ConsumeEnrollmentToken(ctx, org, hash[:])
	if err != nil {
		return w, kf, err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return w, kf, err
	}
	in, err := q.InsertInstance(ctx, dbq.InsertInstanceParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, Jkt: jws.Thumbprint(pub), PublicJwk: jwk,
		EnrolledVia: "enrollment_token", EnrollmentTokenID: &et.ID,
	})
	if err != nil {
		return w, kf, err
	}
	by := "dev-seed"
	if _, err := q.AdmitInstance(ctx, &by, org, in.ID); err != nil {
		return w, kf, err
	}
	if err := agents.MarkVerified(ctx, q, org, a.ID, adomain.System); err != nil {
		return w, kf, err
	}
	w = devWorkload{Agent: a.ID, Instance: in.ID, Env: env, Owner: owner}
	kf.Identifier = pap.Instance{Org: org, Agent: a.ID, Instance: in.ID}.String()
	kf.Server = server
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: auditkind.DevWorkloadSeeded, Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "instance", ID: in.ID.String()},
		Details: map[string]string{"agent_id": a.ID.String()},
	})
	return w, kf, err
}

// seedRun starts the workload's run, bound to its instance and to grant,
// for as long as the grant lasts. DEVELOPMENT ONLY.
func seedRun(ctx context.Context, pool *db.Pool, org ids.OrgID, w devWorkload, grant ids.UUID, until time.Time) (ids.UUID, error) {
	var run ids.UUID
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		chain, err := json.Marshal([]map[string]string{{"kind": "user", "id": w.Owner.String()}})
		if err != nil {
			return err
		}
		r, err := dbq.New(tx).InsertRun(ctx, dbq.InsertRunParams{
			OrgID: org, ID: ids.NewV7(), AgentID: w.Agent, InstanceID: &w.Instance, EnvironmentID: w.Env, LauncherUserID: &w.Owner,
			PrincipalUserID: &w.Owner, PrincipalSource: "launcher", ActorChain: chain, GrantID: &grant, TaskRef: "dev seed",
			TtlMinutes: 24 * 60, NotAfter: &until,
		})
		if err != nil {
			return err
		}
		run = r.ID
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.RunStarted, Actor: devSeedActor, Outcome: audit.Success, Object: &audit.Object{Type: "run", ID: r.ID.String()},
			Details: map[string]string{"agent_id": w.Agent.String(), "grant_id": grant.String()},
		})
		return err
	})
	return run, err
}
