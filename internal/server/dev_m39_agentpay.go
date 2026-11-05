// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"flag"
	"fmt"
	"io"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	apsim "github.com/katocxl/pantherclaw/internal/sim/agentpay"
	pcagentpay "github.com/katocxl/pantherclaw/packages/pc-agentpay"
)

// devAgentPay is the dev seed's M39 agent payments target (G0 M39 D1124):
// with --agentpay-url it seeds pc.agentpay and the connection "agentpay" to
// the simulated merchant, held by the gateway, with no credential (the
// simulator's merchant takes none). The trust anchors the mandates need are
// the simulator's static development JWKS, as sandbox anchors activated
// with a security key. DEVELOPMENT ONLY; everything is SIMULATED.
type devAgentPay struct {
	url *string
}

// devAgentPayFlags declares the dev seed's --agentpay-url.
func devAgentPayFlags(fs *flag.FlagSet) devAgentPay {
	return devAgentPay{
		url: fs.String("agentpay-url", "", "with --gateway-out: also seed pc.agentpay and the connection \"agentpay\" to this simulated AP2 "+
			"merchant (pantherclaw-sim agentpay: https://127.0.0.1:9118), sandbox only"),
	}
}

// any reports whether the target was named.
func (a devAgentPay) any() bool { return *a.url != "" }

// packages are its packages.
func (a devAgentPay) packages() []devPackage {
	if !a.any() {
		return nil
	}
	return []devPackage{{pcagentpay.Name, pcagentpay.Version, pcagentpay.Package}}
}

// seed creates the connection and says how to add the sandbox anchors.
func (a devAgentPay) seed(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, stdout io.Writer) error {
	u := *a.url
	if u == "" {
		return nil
	}
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: "agentpay", Kind: capp.KindHTTP, Package: pcagentpay.Name, BaseURL: u, Gateway: gateway,
		DestinationClass: devClass(u), AccessMode: capp.AccessNone, DefaultMode: "enforce",
	})
	if err != nil {
		return fmt.Errorf("dev: agentpay connection: %w", err)
	}
	// The merchant audience the simulated mandates' KB-JWTs name (D1124c).
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).SetConnectionMerchantAudience(ctx, dbq.SetConnectionMerchantAudienceParams{
			OrgID: org, ConnectionID: c.ID, MerchantAudience: apsim.Merchant, UpdatedBy: "operator:dev-seed",
		})
	}); err != nil {
		return fmt.Errorf("dev: agentpay audience: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "seeded agentpay connection %s (%s) to %s (SIMULATED, sandbox only) with merchant audience %s; "+
		"set dev.agentpay_sim_roots in the server configuration and agentpay_sim_roots in the gateway's to trust the simulator's "+
		"development certificate; add the sandbox trust anchors MANDATE_ISSUER with the JWKS at %s/cp/.well-known/jwks.json and "+
		"MERCHANT %s with the JWKS at %s/merchant/.well-known/jwks.json, and activate each with a security key; ask the simulator "+
		"for mandates with aud %s; every payment then holds for a person unless an ACTIVE merchant cap allows it\n",
		c.ID, c.Name, u, apsim.Merchant, u, apsim.Merchant, u, apsim.Merchant)
	return nil
}
