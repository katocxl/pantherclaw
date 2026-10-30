// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/hosting/agent"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func cmdHosting(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) == 0 || args[0] != "add-host" {
		return errUsage
	}
	return cmdHostingAddHost(ctx, args[1:], stdout, stderr, env)
}

// cmdHostingAddHost implements `hosting add-host` (G0 M19 D226): it records
// a shared hosting host and issues its agent's first certificate for the
// request `pantherclaw-host keygen` wrote. The bundle holds no secret; the
// agent installs it with `pantherclaw-host install`, pinned to the printed
// CA fingerprint.
func cmdHostingAddHost(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	fs := flag.NewFlagSet("hosting add-host", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	name := fs.String("name", "", "the host's name")
	domain := fs.String("domain", "", "the host's domain: agents reach an org as <slug>.gw.<domain>")
	capacity := fs.Int("capacity", 0, "the most hosted gateways the host runs")
	milliCPUs := fs.Int("milli-cpus", 0, "the host's CPU, in millicores")
	memoryMiB := fs.Int("memory-mib", 0, "the host's memory, in MiB")
	csrPath := fs.String("csr", "", "the certificate request from pantherclaw-host keygen")
	bundleOut := fs.String("bundle-out", "", "where to write the certificate bundle (a new file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *name == "" || *domain == "" || *csrPath == "" || *bundleOut == "" ||
		!fitsInt32(*capacity) || !fitsInt32(*milliCPUs) || !fitsInt32(*memoryMiB) {
		fs.Usage()
		return errUsage
	}
	der, err := os.ReadFile(*csrPath)
	if err != nil {
		return err
	}
	pub, err := ca.ParseRequest(der)
	if err != nil {
		return err
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "hosting add-host")
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
	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		return err
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, reg); err != nil {
		return err
	}
	authority, err := ca.New(reg)
	if err != nil {
		return err
	}
	// The file is taken first: no host is recorded whose bundle has nowhere to go.
	out, err := os.OpenFile(*bundleOut, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) //nolint:gosec // G302: certificates, no secret
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	hc, err := newHosting(cfg, pool, authority, kp, nil).AddHost(ctx, *name, *domain,
		int32(*capacity), int32(*milliCPUs), int32(*memoryMiB), pub) //nolint:gosec // G115: fitsInt32
	if err != nil {
		return errors.Join(err, out.Close(), os.Remove(*bundleOut))
	}
	b, err := json.Marshal(agent.Bundle{
		Certificate: base64.StdEncoding.EncodeToString(hc.Certificate),
		CA:          base64.StdEncoding.EncodeToString(hc.CACertificate),
	})
	if err != nil {
		return err
	}
	if _, err := out.Write(b); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "added host %s (%s); bundle in %s; install it with --ca-sha256 %s\n",
		hc.Identity.Host, *name, *bundleOut, ca.Fingerprint(hc.CACertificate))
	return nil
}

func fitsInt32(n int) bool { return n > 0 && n <= math.MaxInt32 }
