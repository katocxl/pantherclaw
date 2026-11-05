// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	awssim "github.com/katocxl/pantherclaw/internal/sim/aws"
	azuresim "github.com/katocxl/pantherclaw/internal/sim/azure"
	vsim "github.com/katocxl/pantherclaw/internal/sim/vertexagent"
	pcawsagentcore "github.com/katocxl/pantherclaw/packages/pc-aws-agentcore"
	pcawsssm "github.com/katocxl/pantherclaw/packages/pc-aws-ssm"
	pcazurecompute "github.com/katocxl/pantherclaw/packages/pc-azure-compute"
	pcazurefoundry "github.com/katocxl/pantherclaw/packages/pc-azure-foundry"
	pcvertexagentengine "github.com/katocxl/pantherclaw/packages/pc-vertex-agent-engine"
)

// devRuntimes is the dev seed's M34 cloud agent runtime and cloud admin
// targets (G0 M34 D998): each URL, when set, seeds its packages and
// connections held by the gateway, through which agents deploy or run
// commands and discovery scans. DEVELOPMENT ONLY.
type devRuntimes struct {
	agentcore, vertex, azure, ssm *string
}

// devRuntimesFlags declares the dev seed's --agentcore-url,
// --vertex-agent-engine-url, --azure-url and --aws-ssm-url.
func devRuntimesFlags(fs *flag.FlagSet) devRuntimes {
	return devRuntimes{
		agentcore: fs.String("agentcore-url", "", "with --gateway-out: also seed pc.aws-agentcore and the connection \"aws-agentcore\" to this AgentCore "+
			"control plane (pantherclaw-sim agentcore: http://127.0.0.1:9113, which also serves its account's STS), signed with an aws_sigv4 session"),
		vertex: fs.String("vertex-agent-engine-url", "", "with --gateway-out: also seed pc.vertex-agent-engine and the connection \"vertex-agent-engine\" "+
			"to this Vertex AI base (pantherclaw-sim vertex-agent-engine: http://127.0.0.1:9114), its access token minted per dispatch "+
			"from a google_service_account credential"),
		azure: fs.String("azure-url", "", "with --gateway-out: also seed pc.azure-foundry and pc.azure-compute and the connections \"azure-foundry\" "+
			"(its project endpoint) and \"azure-compute\" to this Azure base (pantherclaw-sim azure: http://127.0.0.1:9115), each token minted per "+
			"dispatch from an oauth_client credential"),
		ssm: fs.String("aws-ssm-url", "", "with --gateway-out: also seed pc.aws-ssm and the connection \"aws-ssm\" to this SSM endpoint "+
			"(pantherclaw-sim aws: http://127.0.0.1:9099), signed with an aws_sigv4 session"),
	}
}

// any reports whether any target was named.
func (r devRuntimes) any() bool {
	return *r.agentcore != "" || *r.vertex != "" || *r.azure != "" || *r.ssm != ""
}

// packages are the packages of the named targets.
func (r devRuntimes) packages() []devPackage {
	var pkgs []devPackage
	if *r.agentcore != "" {
		pkgs = append(pkgs, devPackage{pcawsagentcore.Name, pcawsagentcore.Version, pcawsagentcore.Package})
	}
	if *r.vertex != "" {
		pkgs = append(pkgs, devPackage{pcvertexagentengine.Name, pcvertexagentengine.Version, pcvertexagentengine.Package})
	}
	if *r.azure != "" {
		pkgs = append(pkgs, devPackage{pcazurefoundry.Name, pcazurefoundry.Version, pcazurefoundry.Package},
			devPackage{pcazurecompute.Name, pcazurecompute.Version, pcazurecompute.Package})
	}
	if *r.ssm != "" {
		pkgs = append(pkgs, devPackage{pcawsssm.Name, pcawsssm.Version, pcawsssm.Package})
	}
	return pkgs
}

// seed creates the named targets' connections and says how to seal each
// credential and, for a runtime, scan it daily.
func (r devRuntimes) seed(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, stdout io.Writer) error {
	awsSeal := "seal the account's base key with pclaw seal --connection %s --from-file SECRET --aws-access-key-id " + awssim.BaseKeyID +
		" --aws-role-arn " + awssim.RoleARN + " --aws-sts-url %s --aws-sts-region " + awssim.Region + " --aws-region " + awssim.Region +
		" --aws-service %s"
	if u := *r.agentcore; u != "" {
		c, err := seedSaaSAgentConnection(ctx, cfg, pool, org, gateway, "aws-agentcore", pcawsagentcore.Name, u, creddomain.AWSSigV4Scheme)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "seeded aws-agentcore connection %s (%s) to %s; "+awsSeal+"; then pclaw discover scan --source aws_agentcore "+
			"--connection %s --tenant %s scans it now and daily\n", c.ID, c.Name, u, c.ID, u, "bedrock-agentcore", c.ID, awssim.Account)
	}
	if u := *r.vertex; u != "" {
		c, err := seedSaaSAgentConnection(ctx, cfg, pool, org, gateway, "vertex-agent-engine", pcvertexagentengine.Name, u, "Bearer")
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "seeded vertex-agent-engine connection %s (%s) to %s; seal a service account key file whose token_uri is %s/token "+
			"with pclaw seal --connection %s --google-service-account FILE --scope https://www.googleapis.com/auth/cloud-platform; "+
			"then pclaw discover scan --source vertex_agent_engine --connection %s --tenant %s/%s scans it now and daily\n",
			c.ID, c.Name, u, u, c.ID, c.ID, vsim.Project, vsim.Location)
	}
	if u := strings.TrimSuffix(*r.azure, "/"); u != "" {
		project := u + "/api/projects/" + azuresim.Project
		f, err := seedSaaSAgentConnection(ctx, cfg, pool, org, gateway, "azure-foundry", pcazurefoundry.Name, project, "Bearer")
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "seeded azure-foundry connection %s (%s) to %s; seal the app's client secret with pclaw seal --connection %s "+
			"--from-file SECRET --oauth-token-url %s/%s/oauth2/v2.0/token --oauth-client-id ID --oauth-scope %s; then pclaw discover scan "+
			"--source azure_foundry --connection %s --tenant %s scans it now and daily\n",
			f.ID, f.Name, project, f.ID, u, azuresim.TenantID, azuresim.FoundryScope, f.ID, azuresim.Project)
		c, err := seedSaaSAgentConnection(ctx, cfg, pool, org, gateway, "azure-compute", pcazurecompute.Name, u, "Bearer")
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "seeded azure-compute connection %s (%s) to %s, its VM %s; seal the app's client secret with pclaw seal "+
			"--connection %s --from-file SECRET --oauth-token-url %s/%s/oauth2/v2.0/token --oauth-client-id ID --oauth-scope %s\n",
			c.ID, c.Name, u, azuresim.VMID, c.ID, u, azuresim.TenantID, azuresim.ARMScope)
	}
	if u := *r.ssm; u != "" {
		c, err := seedSaaSAgentConnection(ctx, cfg, pool, org, gateway, "aws-ssm", pcawsssm.Name, u, creddomain.AWSSigV4Scheme)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "seeded aws-ssm connection %s (%s) to %s, its instance %s; "+awsSeal+"\n",
			c.ID, c.Name, u, awssim.Instance, c.ID, u, "ssm")
	}
	return nil
}
