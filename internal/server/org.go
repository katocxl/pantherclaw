// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/katocxl/pantherclaw/internal/billing"
	billingdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/billing/licence"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// cmdOrg implements the operator commands `org create` and
// `org admin-invite`. They need database access and print the bootstrap
// admin token once (BUILD_GUIDE §8 M2); it is never retrievable again.
func cmdOrg(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) > 0 && args[0] == "plan" {
		return cmdOrgPlan(ctx, args[1:], stdout, stderr, env)
	}
	if len(args) == 0 || (args[0] != "create" && args[0] != "admin-invite") {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	sub := args[0]
	fs := flag.NewFlagSet("org "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	name := fs.String("name", "", "organization name (org create)")
	orgFlag := fs.String("org", "", "organization id (org admin-invite)")
	email := fs.String("admin-email", "", "only this email may use the token (optional)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (sub == "create" && *name == "") || (sub == "admin-invite" && *orgFlag == "") {
		fs.Usage()
		return errUsage
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "org "+sub)
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
	var ents tapp.Entitlements = billing.New(pool, roots, clock.System{}, newLogger(cfg, stderr))
	if cfg.billingMode() != entitlements.ModeLicence {
		// Hosted: plans are per org (G0 UI D9), so the licence's org limit
		// does not apply.
		ents = hostedOrgLimit{ents}
	}
	b := tapp.NewBootstrap(pool, ents)

	var org ids.OrgID
	var tok string
	if sub == "create" {
		o, t, err := b.CreateOrg(ctx, *name, *email)
		if err != nil {
			return err
		}
		org, tok = o, t.Reveal()
		_, _ = fmt.Fprintf(stdout, "created organization %s (%q)\n", org, *name)
	} else {
		if org, err = ids.Parse[ids.Org](*orgFlag); err != nil {
			return err
		}
		t, err := b.AdminInvitation(ctx, org, *email)
		if err != nil {
			return err
		}
		tok = t.Reveal()
		_, _ = fmt.Fprintf(stdout, "issued a new bootstrap admin token for %s; earlier unused ones are revoked\n", org)
	}
	_, _ = fmt.Fprintf(stdout, "\nbootstrap admin token (shown only now; single use; valid 24 hours):\n  %s\n", tok)
	_, _ = fmt.Fprintf(stdout, "\nthe first administrator signs in with:\n  pclaw login --server %s --org %s --invitation %s\n",
		cfg.Auth.PublicURL, org, tok)
	return nil
}

// hostedOrgLimit lifts the licence's org limit for hosted servers.
type hostedOrgLimit struct{ tapp.Entitlements }

// Current implements tapp.Entitlements.
func (h hostedOrgLimit) Current(ctx context.Context) (billingdomain.Entitlements, error) {
	e, err := h.Entitlements.Current(ctx)
	e.Limits.MaxOrgs = billingdomain.Unlimited
	return e, err
}
