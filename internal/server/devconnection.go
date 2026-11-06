// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"slices"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
)

// devConnectionName is the development connection's name: agents call the
// gateway at /payments/… (G0 M6, PN-003.5).
const devConnectionName = "payments"

// devAccessModes are the access modes a development connection takes
// (--access-mode). A pantherclaw_held connection places its credential as
// "Authorization: Bearer …"; nothing is sealed until a person seals one
// (pclaw seal) after the gateway registered its broker key.
var devAccessModes = []string{capp.AccessNone, capp.AccessHeld, capp.AccessTargetEnforced}

// seedConnection creates a development connection to the reference
// payments package's target, as the operator but through every check the
// connection use cases make (HR-077). Its routes take mode, enforce unless
// asked otherwise, so the refund scenarios decide for real; a connection a
// person creates starts in monitor mode (PN-013). The destination class is
// internal for a private or loopback address. access is one of
// devAccessModes. DEVELOPMENT ONLY.
func seedConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, name, targetURL, mode, access string,
) (capp.Connection, error) {
	class := capp.ClassPublic
	if u, err := url.Parse(targetURL); err == nil {
		if a, isIP := httpx.HostAddr(u.Hostname()); isIP && (a.IsPrivate() || a.IsLoopback()) {
			class = capp.ClassInternal
		}
	}
	in := capp.CreateInput{
		Name: name, Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: class, AccessMode: access, DefaultMode: mode,
	}
	if access == capp.AccessHeld {
		in.CredentialHeader, in.CredentialScheme = "Authorization", "Bearer"
	}
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", in)
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: connection: %w", err)
	}
	return c, nil
}

// The development hook connection (G0 M6 design decision 16): the Claude
// Code hook asks the gateway at /hook/shell.
const (
	devShellConnectionName = "shell"
	shellOperation         = "shell.command.run"
)

// seedShellConnection creates the kind-local connection serving pc.shell,
// in enforce mode, as the operator but through every connection check.
// DEVELOPMENT ONLY.
func seedShellConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID) (capp.Connection, error) {
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devShellConnectionName, Kind: capp.KindLocal, Package: pcshell.Name, Gateway: gateway,
		DestinationClass: capp.ClassInternal, AccessMode: capp.AccessNone, DefaultMode: "enforce",
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: shell connection: %w", err)
	}
	return c, nil
}

// The development browser and computer-use hook connections (G0 M33): the
// native host asks the gateway at /hook/browser, the SDK computer-use
// wrappers at /hook/computer.
const (
	devBrowserConnectionName  = "browser"
	devComputerConnectionName = "computer"
)

// seedHookConnection creates a kind-local connection serving pkg, in
// enforce mode, as the operator but through every connection check.
// DEVELOPMENT ONLY.
func seedHookConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, name, pkg string) (capp.Connection, error) {
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: name, Kind: capp.KindLocal, Package: pkg, Gateway: gateway,
		DestinationClass: capp.ClassInternal, AccessMode: capp.AccessNone, DefaultMode: "enforce",
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: %s connection: %w", name, err)
	}
	return c, nil
}

// gatewayByName finds an active gateway of org by name.
func gatewayByName(ctx context.Context, pool *db.Pool, org ids.OrgID, name string) (ids.UUID, error) {
	var out ids.UUID
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var after ids.UUID
		for {
			gs, err := q.ListGateways(ctx, dbq.ListGatewaysParams{OrgID: org, AfterID: after, MaxRows: 100})
			if err != nil {
				return err
			}
			if i := slices.IndexFunc(gs, func(g dbq.PcGateway) bool { return g.Name == name }); i >= 0 {
				out = gs[i].ID
				return nil
			}
			if len(gs) < 100 {
				return fmt.Errorf("dev: org %s has no active gateway named %q", org, name)
			}
			after = gs[len(gs)-1].ID
		}
	})
	return out, err
}

// accessUsage describes --access-mode.
const accessUsage = "the connection's access mode: none, pantherclaw_held (the gateway places a sealed credential as " +
	"\"Authorization: Bearer\"; seal it with pclaw seal once the gateway registered its broker key) or " +
	"target_enforced (the target checks PantherClaw action tokens)"

// cmdDevConnection implements `dev connection --org ID --target-url URL
// [--gateway NAME] [--name NAME] [--mode enforce|monitor] [--access-mode MODE]`.
func cmdDevConnection(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	fs := flag.NewFlagSet("dev connection", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	orgFlag := fs.String("org", "", "the org")
	target := fs.String("target-url", "", "base URL of the payments API (pantherclaw-sim payments)")
	gwName := fs.String("gateway", "dev-gateway", "name of the gateway that serves the connection")
	name := fs.String("name", devConnectionName, "connection name (the first path segment at the gateway)")
	mode := fs.String("mode", capp.ModeEnforce, "route mode: enforce or monitor")
	access := fs.String("access-mode", capp.AccessNone, accessUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	org, err := ids.Parse[ids.Org](*orgFlag)
	if err != nil || *target == "" || fs.NArg() != 0 || !slices.Contains(devAccessModes, *access) {
		fs.Usage()
		return errUsage
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "dev connection")
	if err != nil {
		return err
	}
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, 2)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, appCfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	gw, err := gatewayByName(ctx, pool, org, *gwName)
	if err != nil {
		return err
	}
	c, err := seedConnection(ctx, cfg, pool, org, gw, *name, *target, *mode, *access)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded connection %s (%s, access %s) to %s through gateway %s; agents call the gateway at /%s/v1/refunds\n",
		c.ID, c.Name, *access, *target, *gwName, c.Name)
	return nil
}

// errTargetNeedsGateway: a development connection needs the gateway that
// serves it.
var errTargetNeedsGateway = errors.New("dev seed: --target-url and --shell need --gateway-out (the connection's gateway)")

// errAccessMode: --access-mode names a mode of the --target-url connection.
var errAccessMode = errors.New("dev seed: --access-mode is none, pantherclaw_held or target_enforced, and needs --target-url")
