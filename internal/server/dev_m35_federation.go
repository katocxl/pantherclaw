// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// devFederation is the dev seed's second org (G0 M35 D1046): a peer org on
// the same dev server, with its own gateway, so the two can federate. The
// seed makes no trust, key or listing itself: the two orgs' admins run the
// federation protocol over HTTPS with their security keys, as on any
// deployment (D1021: no shortcut between orgs on one deployment).
// DEVELOPMENT ONLY.
type devFederation struct {
	peerName, peerGatewayOut *string
}

// devFederationFlags declares the dev seed's --federation-peer-name and
// --federation-peer-gateway-out.
func devFederationFlags(fs *flag.FlagSet) devFederation {
	return devFederation{
		peerName: fs.String("federation-peer-name", "", "with --federation-peer-gateway-out: the peer org's name (default: --org-name and \"-peer\")"),
		peerGatewayOut: fs.String("federation-peer-gateway-out", "", "with --gateway-out: also seed a second org on this dev server with its own gateway, "+
			"write that gateway's enrollment file here (0600, never overwritten), and print the steps to federate the two orgs (G0 M35)"),
	}
}

// any reports whether the peer org was asked for.
func (f devFederation) any() bool { return *f.peerGatewayOut != "" }

// seed creates the peer org and its gateway, and prints the federation
// steps for both orgs.
func (f devFederation) seed(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, orgName string, stdout io.Writer) error {
	name := *f.peerName
	if name == "" {
		name = orgName + "-peer"
	}
	peer := ids.New[ids.Org]()
	err := pool.InTenantTx(ctx, peer, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", peer, name); err != nil {
			return fmt.Errorf("dev seed: peer org: %w", err)
		}
		if err := dbq.New(tx).InsertContainment(ctx, peer); err != nil {
			return fmt.Errorf("dev seed: peer containment: %w", err)
		}
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: auditkind.DevOrgSeeded, Actor: devSeedActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: peer.String()},
		})
		return err
	})
	if err != nil {
		return err
	}
	gw, err := seedGateway(ctx, cfg, pool, peer, "dev-gateway", *f.peerGatewayOut)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded peer org %s (%q) with gateway %s; its enrollment file is %s\n", peer, name, gw, *f.peerGatewayOut)
	_, _ = io.WriteString(stdout, federationSteps(strings.TrimSuffix(cfg.Auth.PublicURL, "/"), org, peer))
	return nil
}

// federationSteps says how the two seeded orgs federate (G0 M35 D1020..D1024).
func federationSteps(publicURL string, a, b ids.OrgID) string {
	return fmt.Sprintf(`to federate org A %[2]s and org B %[3]s (Enterprise edition):
  1. make an admin in each: pantherclaw-server org admin-invite --org %[2]s (and --org %[3]s); each signs in with
     pclaw login --invitation <token> and adds a security key at %[1]s/account
  2. each admin names its own gateway's public https URL: pclaw federation endpoint https://GATEWAY
  3. as A: pclaw federation trust propose %[1]s/.well-known/pantherclaw/orgs/%[3]s/federation.json
     as B: pclaw federation trust propose %[1]s/.well-known/pantherclaw/orgs/%[2]s/federation.json
     both compare the safety code (pclaw federation trust show TRUST_ID) out of band, then each runs
     pclaw federation trust confirm TRUST_ID with its security key; the trust is ACTIVE once both confirmed
  4. as B: pclaw federation listing create NAME --agent AGENT_ID --connection A2A_CONNECTION_ID --skill SKILL
     as B: pclaw federation grant issue TRUST_ID --peer-agent pc:org/%[2]s/agent/AGENT_ID --listing NAME
           --op federation.message.receive --expires-at 720h
  5. as A: pclaw federation peers TRUST_ID lists B's verified agents; an a2a connection whose federation peer
     names the trust and the listing sends to it; pclaw federation receipts shows the receipts both sides keep
the server and both gateways must be reachable over https (D1021), for example behind a loopback TLS proxy
`, publicURL, a, b)
}
