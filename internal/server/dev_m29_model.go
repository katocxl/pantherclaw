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
	pcopenai "github.com/katocxl/pantherclaw/packages/pc-openai"
)

// The development model connections (G0 M29 D811, D826): both packages
// against pantherclaw-sim model, whose key is devSimModelKey. The sandbox
// edge maps the providers' API hosts to them.
const (
	devSimModelURL = "http://127.0.0.1:9103/v1"
	devSimModelKey = "sim-model-key"
)

// devModelConnections are the seeded model connections: name, package, the
// host agents use.
var devModelConnections = []struct{ name, pkg, agentHost string }{
	{"anthropic", pcanthropic.Name, "api.anthropic.com"},
	{"openai", pcopenai.Name, "api.openai.com"},
}

func devModelPackages() []devPackage {
	return []devPackage{
		{pcanthropic.Name, pcanthropic.Version, pcanthropic.Package},
		{pcopenai.Name, pcopenai.Version, pcopenai.Package},
	}
}

// seedModelConnections seeds the simulated model connections "anthropic"
// and "openai" to the fake model at simURL (default devSimModelURL), held by
// the gateway, in enforce mode. Nothing is sealed: a person seals the
// simulator's key with pclaw seal. DEVELOPMENT ONLY.
func seedModelConnections(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, simURL string, stdout io.Writer) error {
	if simURL == "" {
		simURL = devSimModelURL
	}
	simURL = strings.TrimRight(simURL, "/")
	kinds := &ports.KindConfigs{}
	kinds.Register(capp.KindModel, pgmodel.Store{})
	svc := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).WithKindConfigs(kinds)
	for _, m := range devModelConnections {
		c, err := svc.Seed(ctx, org, "dev-seed", capp.CreateInput{
			Name: m.name, Kind: capp.KindModel, Package: m.pkg, BaseURL: simURL, Gateway: gateway, Simulated: true,
			DestinationClass: capp.ClassInternal, AccessMode: capp.AccessHeld, DefaultMode: "enforce",
			AgentHosts: []string{m.agentHost}, Model: &capp.ModelConfig{},
		})
		if err != nil {
			return fmt.Errorf("dev: model connection %s: %w", m.name, err)
		}
		_, _ = fmt.Fprintf(stdout, "seeded model connection %s (%s, %s) to %s; agents call the gateway at /%s%s; seal the simulator's key "+
			"(%s) with pclaw seal --connection %s --from-file KEYFILE\n", c.ID, c.Name, m.pkg, simURL, c.Name, devModelPath(simURL),
			devSimModelKey, c.ID)
	}
	return nil
}

// devModelPath is the base URL's path, which agents' requests start with.
func devModelPath(base string) string {
	rest := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[i:]
	}
	return ""
}
