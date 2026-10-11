// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
)

// devSeedActor records `dev seed` in the audit log.
var devSeedActor = evdomain.Actor{Type: "operator", ID: "dev-seed"}

// cmdDev implements `dev seed`: a demo org with its containment row and the
// reference payments package imported and active, and optionally an
// enrollment file for a development gateway (it then authenticates with a
// certificate from the internal CA, like any gateway) and a ready-to-use
// workload: an admitted instance, a fact provider for refundable charges, a
// grant and a run bound to both. `dev gateway` writes an enrollment file for
// an existing org. DEVELOPMENT ONLY.
func cmdDev(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) > 0 && args[0] == "gateway" {
		return cmdDevGateway(ctx, args[1:], stdout, stderr, env)
	}
	if len(args) > 0 && args[0] == "connection" {
		return cmdDevConnection(ctx, args[1:], stdout, stderr, env)
	}
	if len(args) == 0 || args[0] != "seed" {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	fs := flag.NewFlagSet("dev seed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	name := fs.String("org-name", "dev-org", "name of the new org")
	limit := fs.String("budget-limit", "1000.00", "the seeded grant's task budget, in the grant currency")
	maxCount := fs.Int("max-count", 0, "optional limit on the number of refunds the seeded grant allows (0 = none)")
	gatewayOut := fs.String("gateway-out", "", "also seed a gateway; write its enrollment file here (0600, never overwritten)")
	targetURL := fs.String("target-url", "", "with --gateway-out: also seed the connection \"payments\" to this payments API, in enforce mode")
	access := fs.String("access-mode", "", "with --target-url: "+accessUsage+" (default none)")
	shell := fs.Bool("shell", false, "with --gateway-out: also seed the pc.shell package and the hook connection \"shell\" (Claude Code), in enforce mode; "+
		"with --workload-out the grant also allows shell commands")
	workloadOut := fs.String("workload-out", "", "also seed an admitted PAP/1 workload with a grant and a run; write its key file here (0600, never overwritten)")
	factsOut := fs.String("facts-key-out", "", "with --workload-out: write the API key of the development fact provider here (0600, never overwritten)")
	holdOver := fs.String("hold-over", "50.00", "publish a policy holding refunds over this amount (grant currency) for an approver; empty for none")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *maxCount < 0 || (*factsOut != "" && *workloadOut == "") {
		fs.Usage()
		return errUsage
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "dev seed")
	if err != nil {
		return err
	}
	lim, err := money.ParseMoney(*limit, cfg.Authority.GrantCurrency)
	if err != nil || lim.Amount.Sign() <= 0 {
		return fmt.Errorf("dev seed: --budget-limit must be a positive %s amount", cfg.Authority.GrantCurrency)
	}
	maxPer, err := money.ParseMoney(cfg.Authority.GrantMaxPerAction, cfg.Authority.GrantCurrency)
	if err != nil {
		return fmt.Errorf("dev seed: authority.grant_max_per_action: %w", err)
	}
	var hold *money.Money
	if *holdOver != "" {
		h, err := money.ParseMoney(*holdOver, cfg.Authority.GrantCurrency)
		if err != nil || h.Amount.Sign() <= 0 {
			return fmt.Errorf("dev seed: --hold-over must be a positive %s amount", cfg.Authority.GrantCurrency)
		}
		hold = &h
	}
	for _, out := range []string{*workloadOut, *factsOut, *gatewayOut} {
		if out == "" {
			continue
		}
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("dev seed: %s already exists", out)
		}
	}
	if (*targetURL != "" || *shell) && *gatewayOut == "" {
		return errTargetNeedsGateway
	}
	if *access == "" {
		*access = capp.AccessNone
	} else if *targetURL == "" || !slices.Contains(devAccessModes, *access) {
		return errAccessMode
	}
	if *gatewayOut != "" && cfg.GatewayAPI.Addr == "" {
		return errors.New("dev seed: --gateway-out needs gateway_api in the server config (gateways reach the Authority only over mTLS)")
	}
	signer, err := devPackageSigner(cfg, stdout)
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

	org := ids.New[ids.Org]()
	var w devWorkload
	var kf workloadclient.KeyFile
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", org, *name); err != nil {
			return fmt.Errorf("dev seed: org: %w", err)
		}
		if err := dbq.New(tx).InsertContainment(ctx, org); err != nil {
			return fmt.Errorf("dev seed: containment: %w", err)
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "dev.org_seeded", Actor: devSeedActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: org.String()},
		}); err != nil {
			return err
		}
		if *workloadOut != "" {
			w, kf, err = seedWorkload(ctx, tx, org, cfg.Auth.PublicURL)
		}
		return err
	})
	if err != nil {
		return err
	}
	pkgs := []devPackage{{mockpayments.Name, mockpayments.Version, mockpayments.Package}}
	if *shell {
		pkgs = append(pkgs, devPackage{pcshell.Name, pcshell.Version, pcshell.Package})
	}
	if err := seedPackages(ctx, pool, org, signer, pkgs...); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded org %s (%q) with package %s@%s active\n", org, *name, mockpayments.Name, mockpayments.Version)
	if hold != nil {
		if _, err := seedHoldPolicy(ctx, pool, org, *hold); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "published policy dev-holds: refunds over %s wait for an approver (%s)\n%s", hold, devHoldReason,
			approverSteps(cfg.Auth.PublicURL, org))
	}
	if *gatewayOut != "" {
		gw, err := seedGateway(ctx, cfg, pool, org, "dev-gateway", *gatewayOut)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "seeded gateway %s; within 15 minutes, start it with: pantherclaw-gateway serve --enroll-file %s\n",
			gw, *gatewayOut)
		if err := seedApproverKeys(ctx, cfg, pool, org, *gatewayOut, stdout); err != nil {
			return err
		}
		if *targetURL != "" {
			c, err := seedConnection(ctx, cfg, pool, org, gw, devConnectionName, *targetURL, "enforce", *access)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded connection %s (%s, access %s) to %s; agents call the gateway at /%s/v1/refunds\n",
				c.ID, c.Name, *access, *targetURL, c.Name)
		}
		if *shell {
			c, err := seedShellConnection(ctx, cfg, pool, org, gw)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded package %s@%s and connection %s (%s); the Claude Code hook asks the gateway at /hook/%s\n",
				pcshell.Name, pcshell.Version, c.ID, c.Name, c.Name)
		}
	}
	if *workloadOut == "" {
		return nil
	}
	key, err := seedFacts(ctx, pool, org, credential.Env(cfg.Auth.APIKeyEnv))
	if err != nil {
		return err
	}
	g, err := seedGrant(ctx, pool, org, w, devGrantTerms{MaxPerAction: maxPer, Limit: lim, MaxCount: *maxCount, Shell: *shell})
	if err != nil {
		return err
	}
	run, err := seedRun(ctx, pool, org, w, g.ID.UUID(), g.ExpiresAt)
	if err != nil {
		return err
	}
	kf.RunID = run.String()
	if err := workloadclient.WriteKeyFile(*workloadOut, kf, false); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded workload %s with grant %s (refunds up to %s, task budget %s) and run %s; key file %s\n",
		kf.Identifier, g.ID, maxPer, lim, kf.RunID, *workloadOut)
	if *factsOut != "" {
		if err := writeSecretFile(*factsOut, key.Reveal()); err != nil {
			return fmt.Errorf("dev seed: facts key file: %w", err)
		}
		_, _ = fmt.Fprintf(stdout, "refunds need a fresh %s fact about the charge: report it with the API key in %s\n", devFact, *factsOut)
	} else {
		_, _ = fmt.Fprintf(stdout, "refunds need a fresh %s fact about the charge; seed again with --facts-key-out to report it\n", devFact)
	}
	return nil
}
