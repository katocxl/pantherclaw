// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"io"
	"strings"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
	pca2a "github.com/katocxl/pantherclaw/packages/pc-a2a"
)

// The development peer agent connection (G0 M14 D33): the seeded workload
// asks the peer agent "dev-peer" at /a2a/peer through the gateway; the
// peer's runs for those messages are delegated from the workload's grant,
// within the peer scope below: refunds, every other bound inherited from
// the workload's grant (its refund maximum carries over, D33).
const (
	devA2AConnectionName = "peer"
	devPeerScope         = `{"operations":["payments.refund.create","payments.refund.get"]}`
)

// devA2AOperations are the pc.a2a operations the seeded grant allows.
var devA2AOperations = []string{"a2a.message.send", "a2a.task.read", "a2a.task.cancel"}

func devA2APackage() devPackage { return devPackage{pca2a.Name, pca2a.Version, pca2a.Package} }

// seedA2A seeds the peer agent "dev-peer" (an admitted instance whose key
// file goes to peerOut; its runs come from the requests it is sent) and
// the simulated a2a connection "peer" to the simulator at simURL, its card
// pinned and activated by the operator. DEVELOPMENT ONLY: a person confirms
// a pin on the confirm page with a security key (D85, D92).
func seedA2A(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, w devWorkload, simURL, peerOut string,
	stdout io.Writer,
) error {
	simURL = strings.TrimRight(simURL, "/")
	var peer devWorkload
	var kf workloadclient.KeyFile
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		peer, kf, err = seedPeerAgent(ctx, tx, org, w, cfg.Auth.PublicURL)
		return err
	})
	if err != nil {
		return err
	}
	if err := workloadclient.WriteKeyFile(peerOut, kf, false); err != nil {
		return err
	}
	kinds := &ports.KindConfigs{}
	kinds.Register(capp.KindA2A, &a2astore.Adapter{Pinner: a2astore.NewPinner()})
	agent := peer.Agent
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).WithKindConfigs(kinds).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devA2AConnectionName, Kind: capp.KindA2A, Package: pca2a.Name, Gateway: gateway, Simulated: true,
		DestinationClass: capp.ClassInternal, AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		A2A: &capp.A2AConfig{
			CardURL: simURL + wire.CardPath, Interface: capp.A2AInterface{Protocol: wire.BindingJSONRPC, URL: simURL + a2asim.JSONRPCPath},
			Skills: []string{"refunds", "echo"}, PeerAgent: &agent, PeerScope: &capp.A2APeerScope{Bounds: []byte(devPeerScope)},
		},
	})
	if err != nil {
		return fmt.Errorf("dev: a2a connection: %w", err)
	}
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		p, err := a2astore.Get(ctx, q, org, c.ID, a2astore.StateProposed)
		if err != nil {
			return err
		}
		if _, err := a2astore.ActivateAsOperator(ctx, q, org, c.ID, p.ID, "dev-seed"); err != nil {
			return err
		}
		if _, err := q.BumpGatewayConfig(ctx, org, gateway); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "connection.a2a_pin_confirmed", Actor: devSeedActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "connection", ID: c.ID.String()}, Details: map[string]string{"pin_id": p.ID.String(), "card_digest": p.Digest()},
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("dev: a2a pin: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "seeded a2a connection %s (%s) to the peer agent %s at %s; agents call the gateway at /a2a/%s; "+
		"peer key file %s\n", c.ID, c.Name, peer.Agent, simURL, c.Name, peerOut)
	return nil
}

// seedPeerAgent adds the agent "dev-peer" with an admitted instance of a
// new key to the seeded workload's team and environment, in tx.
func seedPeerAgent(ctx context.Context, tx db.TenantTx, org ids.OrgID, w devWorkload, server string) (devWorkload, workloadclient.KeyFile, error) {
	kf, key, err := workloadclient.NewKeyFile()
	if err != nil {
		return devWorkload{}, kf, err
	}
	q := dbq.New(tx)
	var team ids.UUID
	if err := tx.QueryRow(ctx, "SELECT team_id FROM pc.environments WHERE org_id = $1 AND id = $2", org, w.Env).Scan(&team); err != nil {
		return devWorkload{}, kf, err
	}
	ci := string(adomain.ContextCI)
	a, err := q.InsertAgent(ctx, dbq.InsertAgentParams{
		OrgID: org, ID: ids.NewV7(), Name: "dev-peer", Purpose: "development peer agent", TeamID: &team, EnvironmentID: &w.Env,
		OwnerUserID: &w.Owner, ExecutionContext: &ci, CreatedBy: "dev-seed",
	})
	if err != nil {
		return devWorkload{}, kf, fmt.Errorf("dev seed: peer agent: %w", err)
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return devWorkload{}, kf, err
	}
	hash := sha256.Sum256(secret[:])
	if _, err := q.InsertEnrollmentToken(ctx, dbq.InsertEnrollmentTokenParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, EnvironmentID: w.Env, TokenHash: hash[:], CreatedBy: "dev-seed", TtlMinutes: 15,
	}); err != nil {
		return devWorkload{}, kf, err
	}
	et, err := q.ConsumeEnrollmentToken(ctx, org, hash[:])
	if err != nil {
		return devWorkload{}, kf, err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return devWorkload{}, kf, err
	}
	in, err := q.InsertInstance(ctx, dbq.InsertInstanceParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, Jkt: jws.Thumbprint(pub), PublicJwk: jwk,
		EnrolledVia: "enrollment_token", EnrollmentTokenID: &et.ID,
	})
	if err != nil {
		return devWorkload{}, kf, err
	}
	by := "dev-seed"
	if _, err := q.AdmitInstance(ctx, &by, org, in.ID); err != nil {
		return devWorkload{}, kf, err
	}
	if err := agents.MarkVerified(ctx, q, org, a.ID, adomain.System); err != nil {
		return devWorkload{}, kf, err
	}
	kf.Identifier = pap.Instance{Org: org, Agent: a.ID, Instance: in.ID}.String()
	kf.Server = server
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "dev.workload_seeded", Actor: devSeedActor, Outcome: audit.Success,
		Object: &audit.Object{Type: "instance", ID: in.ID.String()}, Details: map[string]string{"agent_id": a.ID.String(), "role": "a2a peer"},
	})
	return devWorkload{Agent: a.ID, Instance: in.ID, Env: w.Env, Owner: w.Owner}, kf, err
}
