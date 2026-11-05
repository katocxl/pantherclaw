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
	"time"

	intelapp "github.com/katocxl/pantherclaw/internal/intel/app"
	inteldomain "github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// cmdIntel is the operator's intel commands (G0 M38 D1103, D1105).
func cmdIntel(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "import":
		return cmdIntelImport(ctx, args[1:], stdout, stderr, env)
	case "export-contributions":
		return cmdIntelExport(ctx, args[1:], stdout, stderr, env)
	}
	return errUsage
}

// intelPool opens the app pool of the configuration at cfgPath.
func intelPool(ctx context.Context, cfgPath string, stderr io.Writer, env Env, name string) (*Config, *db.Pool, error) {
	cfg, _, err := loadConfig([]string{"--config", cfgPath}, stderr, env, name)
	if err != nil {
		return nil, nil, err
	}
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, 2)
	if err != nil {
		return nil, nil, err
	}
	pool, err := db.Open(ctx, appCfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, pool, nil
}

// cmdIntelImport implements `intel import` (D1103): it verifies a signed
// feed against the intel roots and, when its version rises, replaces the
// deployment's indicators. An older version, or another feed under the
// same version, is refused (HR-817).
func cmdIntelImport(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	fs := flag.NewFlagSet("intel import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	in := fs.String("in", "", "signed intel feed (pclaw-admin intel build)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *in == "" {
		fs.Usage()
		return errUsage
	}
	doc, err := os.ReadFile(*in) //nolint:gosec // G304: operator-chosen feed path
	if err != nil {
		return err
	}
	if len(doc) > inteldomain.MaxFeedBytes {
		return fmt.Errorf("intel import: the feed is over %d bytes", inteldomain.MaxFeedBytes)
	}
	cfg, pool, err := intelPool(ctx, *cfgPath, stderr, env, "intel import")
	if err != nil {
		return err
	}
	defer pool.Close()
	log := newLogger(cfg, stderr)
	roots, err := intelRoots(ctx, cfg, log)
	if err != nil {
		return err
	}
	res, err := (&intelapp.Importer{Pool: pool, Roots: roots, Log: log}).Import(ctx, string(doc), intelapp.SourceImport)
	if err != nil {
		return err
	}
	if !res.Changed {
		_, _ = fmt.Fprintf(stdout, "Intel feed version %d (%s) was imported before; nothing changed.\n", res.Version, res.KID)
		return nil
	}
	_, _ = fmt.Fprintf(stdout, "Imported intel feed version %d with %s: %d indicators; %d consuming orgs' gateways get a new configuration.\n",
		res.Version, res.KID, res.Indicators, res.Orgs)
	return nil
}

// cmdIntelExport implements `intel export-contributions` (D1105): every
// org's queued contributions, as hashes with no org identity (HR-821), into
// a new file; they are marked exported.
func cmdIntelExport(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	fs := flag.NewFlagSet("intel export-contributions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	outPath := fs.String("out", "", "where to write the contributions (a new file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *outPath == "" {
		fs.Usage()
		return errUsage
	}
	_, pool, err := intelPool(ctx, *cfgPath, stderr, env, "intel export-contributions")
	if err != nil {
		return err
	}
	defer pool.Close()
	// The file is taken first: nothing is marked exported that has nowhere to go.
	out, err := os.OpenFile(*outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: operator-chosen path
	if err != nil {
		return err
	}
	b, err := intelapp.ExportContributions(ctx, pool, time.Now())
	if err != nil {
		return errors.Join(err, out.Close(), os.Remove(*outPath))
	}
	if _, err := out.Write(append(b, '\n')); err != nil {
		return errors.Join(err, out.Close())
	}
	if err := out.Close(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Wrote intel contributions to %s\n", *outPath)
	return nil
}
