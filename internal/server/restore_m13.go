// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/restore"
)

func newRestoreRegistry(ctx context.Context, cfg *Config, pool *db.Pool) (*restore.Registry, error) {
	kp, err := newKeyProvider(cfg)
	if err != nil {
		return nil, err
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	applyFIPSMode(ctx, cfg, log)
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, reg, cfg.evidenceKeyPurposes()...); err != nil {
		return nil, err
	}
	data, err := newDataRequests(cfg, pool, reg, nil, log)
	if err != nil {
		return nil, err
	}
	newAccountDeletion(accounts.NewStore(pool), data)
	r := restore.NewRegistry()
	if err := data.RegisterRestore(r); err != nil {
		return nil, err
	}
	return r, nil
}

func cmdRestore(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) == 0 || args[0] != "reapply" {
		return errUsage
	}
	fs := flag.NewFlagSet("restore reapply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "shipped security-event NDJSON file")
	sinceRaw := fs.String("since", "", "include entries at or after this RFC3339 timestamp")
	configPath := fs.String("config", "", "JSON configuration file")
	confirm := fs.Bool("confirm", false, "re-apply tightening events")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *from == "" {
		return errUsage
	}
	if !*confirm {
		return errors.New("restore reapply needs --confirm; keep the maintenance hold on until replay and the epoch bump complete")
	}
	var since time.Time
	if *sinceRaw != "" {
		var err error
		since, err = time.Parse(time.RFC3339Nano, *sinceRaw)
		if err != nil {
			return errors.New("restore reapply: --since must be RFC3339")
		}
	}
	cfg, _, err := loadConfig([]string{"--config", *configPath}, stderr, env, "restore reapply")
	if err != nil {
		return err
	}
	if !cfg.Maintenance.Hold {
		return errors.New("restore reapply: maintenance.hold must be on")
	}
	input, err := os.Open(*from)
	if err != nil {
		return fmt.Errorf("restore reapply: open input: %w", err)
	}
	defer func() { _ = input.Close() }()
	_, pool, err := openOperatorPool(ctx, *configPath, stderr, env, "restore reapply")
	if err != nil {
		return err
	}
	defer pool.Close()
	registry, err := newRestoreRegistry(ctx, cfg, pool)
	if err != nil {
		return err
	}
	events, err := registry.Parse(input, since)
	if err != nil {
		return err
	}
	if err := registry.Reapply(ctx, pool, events, cfg.Maintenance.Hold, domain.Actor{Type: "operator", ID: operatorName()}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "re-applied %d tightening security event(s); maintenance hold remains on\nnext: keys bump-epochs --all --confirm before reopening gateway access\n", len(events))
	return nil
}
