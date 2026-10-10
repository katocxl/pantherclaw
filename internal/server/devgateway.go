// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// gatewayEnrollFile is what a development gateway enrolls from
// (pantherclaw-gateway serve --enroll-file).
type gatewayEnrollFile struct {
	APIURL   string `json:"api_url"`
	Token    string `json:"token"`
	CASHA256 string `json:"ca_sha256"`
}

// seedGateway creates a gateway record in org and writes an enrollment
// file for it: the public API URL, a single-use pcg_ token (15 minutes) and
// the CA pin. DEVELOPMENT ONLY: production gateways get their token from a
// person holding Gateway Admin (`pclaw gateway enroll-token`).
func seedGateway(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, name, out string) (ids.UUID, error) {
	if cfg.GatewayAPI.Addr == "" {
		return ids.UUID{}, errors.New("dev: configure gateway_api (addr, hostnames, url) first: gateways reach the Authority only over mTLS")
	}
	if _, err := os.Stat(out); err == nil {
		return ids.UUID{}, fmt.Errorf("dev: %s already exists", out)
	}
	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		return ids.UUID{}, err
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, reg); err != nil {
		return ids.UUID{}, err
	}
	authority, err := ca.New(reg)
	if err != nil {
		return ids.UUID{}, err
	}
	tok, err := credential.New(credential.GatewayEnrollmentToken, "", org)
	if err != nil {
		return ids.UUID{}, err
	}
	var gw ids.UUID
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.InsertGateway(ctx, dbq.InsertGatewayParams{OrgID: org, ID: ids.NewV7(), Name: name, CreatedBy: "operator:dev-seed"})
		if db.IsUniqueViolation(err) {
			return fmt.Errorf("dev: an active gateway named %q exists", name)
		} else if err != nil {
			return err
		}
		if _, err := q.InsertGatewayEnrollmentToken(ctx, dbq.InsertGatewayEnrollmentTokenParams{
			OrgID: org, ID: ids.NewV7(), GatewayID: g.ID, TokenHash: tok.Hash(), CreatedBy: "operator:dev-seed",
			TtlMinutes: int32(gwapp.EnrollmentTTL.Minutes()),
		}); err != nil {
			return err
		}
		gw = g.ID
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "dev.gateway_seeded", Actor: devSeedActor, Outcome: audit.Success, Object: &audit.Object{Type: "gateway", ID: g.ID.String()},
		})
		return err
	})
	if err != nil {
		return ids.UUID{}, err
	}
	b, err := json.Marshal(gatewayEnrollFile{APIURL: cfg.Auth.PublicURL, Token: tok.Reveal(), CASHA256: ca.Fingerprint(authority.Certificate())})
	if err != nil {
		return ids.UUID{}, err
	}
	if err := writeSecretFile(out, string(b)); err != nil {
		return ids.UUID{}, fmt.Errorf("dev: gateway enrollment file: %w", err)
	}
	return gw, nil
}

// cmdDevGateway implements `dev gateway --org ID --out FILE [--name NAME]`.
func cmdDevGateway(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	fs := flag.NewFlagSet("dev gateway", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	orgFlag := fs.String("org", "", "the org the gateway serves")
	name := fs.String("name", "dev-gateway", "gateway name")
	out := fs.String("out", "", "write the enrollment file here (0600, never overwritten)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	org, err := ids.Parse[ids.Org](*orgFlag)
	if err != nil || *out == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "dev gateway")
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
	gw, err := seedGateway(ctx, cfg, pool, org, *name, *out)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded gateway %s in org %s; enroll it within 15 minutes with: pantherclaw-gateway serve --enroll-file %s\n", gw, org, *out)
	return seedApproverKeys(ctx, cfg, pool, org, *out, stdout)
}
