// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"flag"
	"fmt"
	"io"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/connections/sfmanifest"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclinear "github.com/katocxl/pantherclaw/packages/pc-linear"
	pcnotion "github.com/katocxl/pantherclaw/packages/pc-notion"
	pcsalesforce "github.com/katocxl/pantherclaw/packages/pc-salesforce"
	pcsnowflake "github.com/katocxl/pantherclaw/packages/pc-snowflake"
)

// devSaaS is the dev seed's M31 software-as-a-service targets (G0 M31 D960):
// each URL, when set, seeds its package and an agent-side connection held by
// the gateway. DEVELOPMENT ONLY.
type devSaaS struct {
	salesforce, notion, linear, snowflake *string
}

// devSaaSFlags declares the dev seed's --salesforce-url, --notion-url,
// --linear-url and --snowflake-url.
func devSaaSFlags(fs *flag.FlagSet) devSaaS {
	return devSaaS{
		salesforce: fs.String("salesforce-url", "", "with --gateway-out: also seed pc.salesforce and the connection \"salesforce\" to this Salesforce org "+
			"(pantherclaw-sim salesforce: http://127.0.0.1:9106), its access token minted per dispatch from an oauth_client credential"),
		notion: fs.String("notion-url", "", "with --gateway-out: also seed pc.notion and the connection \"notion\" to this Notion API "+
			"(pantherclaw-sim notion: http://127.0.0.1:9107)"),
		linear: fs.String("linear-url", "", "with --gateway-out: also seed pc.linear and the connection \"linear\" to this Linear API "+
			"(pantherclaw-sim linear: http://127.0.0.1:9108)"),
		snowflake: fs.String("snowflake-url", "", "with --gateway-out: also seed pc.snowflake and the simulated snowflake connection \""+
			devSnowflakeConnectionName+"\" to this Snowflake SQL API (pantherclaw-sim snowflake: http://127.0.0.1:9109) over the D19 fixture manifest"),
	}
}

// any reports whether any target was named.
func (s devSaaS) any() bool {
	return *s.salesforce != "" || *s.notion != "" || *s.linear != "" || *s.snowflake != ""
}

// packages are the packages of the named targets.
func (s devSaaS) packages() []devPackage {
	var pkgs []devPackage
	if *s.salesforce != "" {
		pkgs = append(pkgs, devPackage{pcsalesforce.Name, pcsalesforce.Version, pcsalesforce.Package})
	}
	if *s.notion != "" {
		pkgs = append(pkgs, devPackage{pcnotion.Name, pcnotion.Version, pcnotion.Package})
	}
	if *s.linear != "" {
		pkgs = append(pkgs, devPackage{pclinear.Name, pclinear.Version, pclinear.Package})
	}
	if *s.snowflake != "" {
		pkgs = append(pkgs, devPackage{pcsnowflake.Name, pcsnowflake.Version, pcsnowflake.Package})
	}
	return pkgs
}

// seed creates the named targets' connections and says how to seal each
// credential.
func (s devSaaS) seed(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, stdout io.Writer) error {
	for _, t := range []struct {
		url, name, pkg, scheme, seal string
	}{
		{
			*s.salesforce, "salesforce", pcsalesforce.Name, "Bearer",
			"seal the connected app's client with pclaw seal --connection %s --from-file SECRET --oauth-client-id ID " +
				"--oauth-token-url %s/services/oauth2/token --oauth-scope api",
		},
		{*s.notion, "notion", pcnotion.Name, "Bearer", "seal an internal integration token with pclaw seal --connection %s --from-file TOKEN"},
		{*s.linear, "linear", pclinear.Name, "", "seal a personal API key with pclaw seal --connection %s --from-file KEY"},
	} {
		if t.url == "" {
			continue
		}
		c, err := seedSaaSAgentConnection(ctx, cfg, pool, org, gateway, t.name, t.pkg, t.url, t.scheme)
		if err != nil {
			return err
		}
		seal := fmt.Sprintf(t.seal, c.ID)
		if t.name == "salesforce" {
			seal = fmt.Sprintf(t.seal, c.ID, t.url)
		}
		_, _ = fmt.Fprintf(stdout, "seeded %s connection %s (%s) to %s; %s\n", t.name, c.ID, c.Name, t.url, seal)
	}
	if *s.snowflake != "" {
		return seedSnowflakeConnection(ctx, cfg, pool, org, gateway, *s.snowflake, stdout)
	}
	return nil
}

// The development snowflake connection (G0 M31 D962a): pc.snowflake against
// pantherclaw-sim snowflake, over the D19 fixture manifest.
const (
	devSnowflakeConnectionName = "snowflake"
	devSnowflakeAccount        = "devorg-devaccount"
)

// seedSnowflakeConnection creates the simulated snowflake connection
// "snowflake" to the simulator at targetURL, in enforce mode,
// pantherclaw_held, its manifest proposed for a person to confirm. Nothing
// is sealed: a person seals a key pair with pclaw seal. DEVELOPMENT ONLY.
func seedSnowflakeConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string, stdout io.Writer) error {
	kinds := &ports.KindConfigs{}
	kinds.Register(capp.KindSnowflake, sfmanifest.Store{})
	sc := capp.SnowflakeConfig{Account: devSnowflakeAccount, Warehouse: "dev_wh", Database: "dev", Schema: "shop", Tables: devPostgresTables()}
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).WithKindConfigs(kinds).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devSnowflakeConnectionName, Kind: capp.KindSnowflake, Package: pcsnowflake.Name, BaseURL: targetURL, Gateway: gateway,
		Simulated: true, DestinationClass: devClass(targetURL), AccessMode: capp.AccessHeld, DefaultMode: "enforce", Snowflake: &sc,
	})
	if err != nil {
		return fmt.Errorf("dev: snowflake connection: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "seeded snowflake connection %s (%s) to %s, account %s; confirm its manifest with your security key at "+
		"%s/connections/%s/postgres/confirm, then seal a key pair with pclaw seal --connection %s --snowflake-account %s --snowflake-user USER "+
		"--from-file KEY.p8; agents call the gateway at /mcp/%s\n",
		c.ID, c.Name, targetURL, devSnowflakeAccount, cfg.Auth.PublicURL, c.ID, c.ID, devSnowflakeAccount, c.Name)
	return nil
}

// seedSaaSAgentConnection creates a development connection through which
// agents work with one M31 package: targetURL is the service's API base
// (its pantherclaw-sim simulator), its host the only one the credential is
// bound to, and the credential is held by the gateway (a person seals it
// with pclaw seal) and placed in Authorization with scheme (empty for a
// Linear key, which is the whole header). DEVELOPMENT ONLY.
func seedSaaSAgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, name, pkg, targetURL, scheme string) (capp.Connection, error) {
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: name, Kind: capp.KindHTTP, Package: pkg, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: devClass(targetURL), AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		CredentialHeader: "Authorization", CredentialScheme: scheme,
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: %s connection: %w", name, err)
	}
	return c, nil
}
