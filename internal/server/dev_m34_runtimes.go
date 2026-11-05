// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	vsim "github.com/katocxl/pantherclaw/internal/sim/vertexagent"
	pcvertexagentengine "github.com/katocxl/pantherclaw/packages/pc-vertex-agent-engine"
)

// devRuntimes is the dev seed's M34 cloud agent runtime targets (G0 M34
// D998): each URL, when set, seeds its package and a connection held by the
// gateway, through which agents deploy and discovery scans. DEVELOPMENT
// ONLY. pc.aws-agentcore and pc.azure-foundry are seeded here once their
// packages land (D993a).
type devRuntimes struct {
	vertex *string
}

// devRuntimesFlags declares the dev seed's --vertex-agent-engine-url.
func devRuntimesFlags(fs *flag.FlagSet) devRuntimes {
	return devRuntimes{
		vertex: fs.String("vertex-agent-engine-url", "", "with --gateway-out: also seed pc.vertex-agent-engine and the connection \"vertex-agent-engine\" "+
			"to this Vertex AI base (pantherclaw-sim vertex-agent-engine: http://127.0.0.1:9114), its access token minted per dispatch "+
			"from a google_service_account credential"),
	}
}

// any reports whether any target was named.
func (r devRuntimes) any() bool { return *r.vertex != "" }

// packages are the packages of the named targets.
func (r devRuntimes) packages() []devPackage {
	var pkgs []devPackage
	if *r.vertex != "" {
		pkgs = append(pkgs, devPackage{pcvertexagentengine.Name, pcvertexagentengine.Version, pcvertexagentengine.Package})
	}
	return pkgs
}

// seed creates the named targets' connections and says how to seal each
// credential and scan it daily.
func (r devRuntimes) seed(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, stdout io.Writer) error {
	if *r.vertex == "" {
		return nil
	}
	c, err := seedSaaSAgentConnection(ctx, cfg, pool, org, gateway, "vertex-agent-engine", pcvertexagentengine.Name, *r.vertex, "Bearer")
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded vertex-agent-engine connection %s (%s) to %s; seal a service account key file whose token_uri is %s/token with "+
		"pclaw seal --connection %s --google-service-account FILE --scope https://www.googleapis.com/auth/cloud-platform; "+
		"then pclaw discover scan --source vertex_agent_engine --connection %s --tenant %s/%s scans it now and daily\n",
		c.ID, c.Name, *r.vertex, *r.vertex, c.ID, c.ID, vsim.Project, vsim.Location)
	return nil
}
