// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"io"
	"strings"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmodel"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcanthropic "github.com/katocxl/pantherclaw/packages/pc-anthropic"
	pcbedrock "github.com/katocxl/pantherclaw/packages/pc-bedrock"
	pcopenai "github.com/katocxl/pantherclaw/packages/pc-openai"
	pcvertex "github.com/katocxl/pantherclaw/packages/pc-vertex"
)

// The development model connections (G0 M29 D811, D826; G0 M31 D962a): the
// packages against pantherclaw-sim model, whose key is devSimModelKey. The
// sandbox edge maps the providers' API hosts to them.
const (
	devSimModelURL = "http://127.0.0.1:9103/v1"
	devSimModelKey = "sim-model-key"
)

// devModelConnections are the seeded model connections: name, package, the
// host agents use, the path on the simulator (empty: the --model-url as
// given; otherwise this path on its host), and how to seal the credential.
var devModelConnections = []struct{ name, pkg, agentHost, path, seal string }{
	{"anthropic", pcanthropic.Name, "api.anthropic.com", "", "the simulator's key (" + devSimModelKey + ") with pclaw seal --connection %s --from-file KEYFILE"},
	{"openai", pcopenai.Name, "api.openai.com", "", "the simulator's key (" + devSimModelKey + ") with pclaw seal --connection %s --from-file KEYFILE"},
	{
		"vertex", pcvertex.Name, "us-east5-aiplatform.googleapis.com", "/vertex/models",
		"a service account key file whose token_uri is the simulator's /vertex/token with pclaw seal --connection %s --google-service-account KEY.json",
	},
	{
		"bedrock", pcbedrock.Name, "bedrock-runtime.us-east-1.amazonaws.com", "/bedrock",
		"a base key with pclaw seal --connection %s --from-file SECRET --aws-access-key-id ID --aws-role-arn ARN --aws-sts-url URL " +
			"--aws-sts-region R --aws-region R --aws-service bedrock (its STS host on the connection's allowed hosts)",
	},
}

func devModelPackages() []devPackage {
	return []devPackage{
		{pcanthropic.Name, pcanthropic.Version, pcanthropic.Package},
		{pcopenai.Name, pcopenai.Version, pcopenai.Package},
		{pcvertex.Name, pcvertex.Version, pcvertex.Package},
		{pcbedrock.Name, pcbedrock.Version, pcbedrock.Package},
	}
}

// seedModelConnections seeds the simulated model connections "anthropic",
// "openai", "vertex" and "bedrock" to the fake model at simURL (default
// devSimModelURL; vertex and bedrock at /vertex/models and /bedrock on its
// host), held by the gateway, in enforce mode. Nothing is sealed: a person
// seals each credential with pclaw seal. DEVELOPMENT ONLY.
func seedModelConnections(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, simURL string, stdout io.Writer) error {
	if simURL == "" {
		simURL = devSimModelURL
	}
	simURL = strings.TrimRight(simURL, "/")
	kinds := &ports.KindConfigs{}
	kinds.Register(capp.KindModel, pgmodel.Store{})
	svc := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).WithKindConfigs(kinds)
	for _, m := range devModelConnections {
		base := simURL
		if m.path != "" {
			base = devModelRoot(simURL) + m.path
		}
		c, err := svc.Seed(ctx, org, "dev-seed", capp.CreateInput{
			Name: m.name, Kind: capp.KindModel, Package: m.pkg, BaseURL: base, Gateway: gateway, Simulated: true,
			DestinationClass: capp.ClassInternal, AccessMode: capp.AccessHeld, DefaultMode: "enforce",
			AgentHosts: []string{m.agentHost}, Model: &capp.ModelConfig{},
		})
		if err != nil {
			return fmt.Errorf("dev: model connection %s: %w", m.name, err)
		}
		_, _ = fmt.Fprintf(stdout, "seeded model connection %s (%s, %s) to %s; agents call the gateway at /%s%s; seal "+m.seal+"\n",
			c.ID, c.Name, m.pkg, base, c.Name, devModelPath(base), c.ID)
	}
	return nil
}

// devModelRoot is the base URL's scheme and host.
func devModelRoot(base string) string {
	return strings.TrimSuffix(base, devModelPath(base))
}

// devModelPath is the base URL's path, which agents' requests start with.
func devModelPath(base string) string {
	rest := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[i:]
	}
	return ""
}
