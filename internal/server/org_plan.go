// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"time"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/billing/licence"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// cmdOrgPlan implements `org plan grant` and `org plan revoke` (G0 UI D12,
// D34; HR-358): complimentary plans, only from the operator command line
// with database access, never through the API or a browser. They work in
// every billing mode and deployment, at most a year, with a reason, and are
// recorded in the org's evidence ledger.
func cmdOrgPlan(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) == 0 || (args[0] != "grant" && args[0] != "revoke") {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	sub := args[0]
	fs := flag.NewFlagSet("org plan "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	orgFlag := fs.String("org", "", "organization id")
	plan := fs.String("plan", "", "plan id (grant)")
	edition := fs.String("edition", "", "edition: team, business or enterprise (grant; default: the plan id when it names one)")
	until := fs.String("until", "", "end of the comp plan, RFC 3339, at most a year away (grant)")
	reason := fs.String("reason", "", "why (recorded and shown)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *orgFlag == "" || *reason == "" || (sub == "grant" && (*plan == "" || *until == "")) {
		fs.Usage()
		return errUsage
	}
	org, err := ids.Parse[ids.Org](*orgFlag)
	if err != nil {
		return fmt.Errorf("org plan: --org: %w", err)
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "org plan "+sub)
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
	roots, err := licence.EmbeddedRoots()
	if err != nil {
		return err
	}
	bill := billing.New(pool, roots, clock.System{}, newLogger(cfg, stderr))
	svc, err := entitlements.New(pool, entitlements.LicenceFunc(bill.Licence), cfg.billingMode(), clock.System{}, newLogger(cfg, stderr))
	if err != nil {
		return err
	}
	operator := operatorName()
	if sub == "revoke" {
		if err := svc.RevokeComp(ctx, org, *reason, operator); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "ended the complimentary plan of %s\n", org)
		return nil
	}
	end, err := time.Parse(time.RFC3339, *until)
	if err != nil {
		return fmt.Errorf("org plan grant: --until: %w", err)
	}
	if err := svc.GrantComp(ctx, org, entitlements.CompGrant{
		PlanID: *plan, Edition: *edition, Until: end, Reason: *reason, Operator: operator,
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "granted %s a complimentary %s plan until %s\n", org, *plan, end.UTC().Format(time.RFC3339))
	return nil
}

// operatorName names who ran an operator command, for the ledger.
func operatorName() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	host, _ := os.Hostname()
	if host != "" {
		name += "@" + host
	}
	if len(name) > 190 {
		name = name[:190]
	}
	return "cli:" + name
}
