// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// rotateCAActor is recorded on the key changes.
var rotateCAActor = evdomain.Actor{Type: "operator", ID: "keys-rotate-gateway-ca"}

// cmdRotateGatewayCA implements `keys rotate-gateway-ca --confirm [--config
// FILE]` (founder decision 2026-10-10): the internal gateway CA gets a new
// key and every earlier one is revoked in the same transaction, with no
// overlap, since a key may be replaced because it is compromised. Every
// gateway pinned the old CA, so each must enroll again with a new token and
// the new pin, and every server instance must restart to load the key.
// Without --confirm nothing changes.
func cmdRotateGatewayCA(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	fs := flag.NewFlagSet("keys rotate-gateway-ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	confirm := fs.Bool("confirm", false, "replace the CA: every gateway stops until it enrolls again with the new pin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	if !*confirm {
		return errors.New("keys rotate-gateway-ca: every gateway stops until it enrolls again with the new CA pin; run again with --confirm")
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "keys rotate-gateway-ca")
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
	kp, err := newKeyProvider(cfg)
	if err != nil {
		return err
	}
	old := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, old); err != nil {
		return err
	}
	before, err := ca.New(old)
	if err != nil {
		return err
	}
	kid, revoked, err := keystore.ReplaceSigningKey(ctx, pool, kp, keys.PurposeGatewayCA, rotateCAActor)
	if err != nil {
		return fmt.Errorf("keys rotate-gateway-ca: %w", err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, reg); err != nil {
		return err
	}
	after, err := ca.New(reg)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "replaced the gateway CA: new key %s, pin %s (was %s); revoked %d earlier key(s)\n",
		kid, ca.Fingerprint(after.Certificate()), ca.Fingerprint(before.Certificate()), len(revoked))
	_, _ = fmt.Fprintln(stdout, "next: restart every server instance; then, for each gateway, a gateway admin issues a new enrollment token "+
		"(pclaw gateway enroll-token, which shows the new pin) and the operator enrolls again (docs/runbooks/key-rotation.md section 6)")
	return nil
}
