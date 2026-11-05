// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/azure"
)

// runAzure serves the simulated Azure: Entra client-credentials tokens,
// Foundry agents and Resource Manager runCommand (G0 M34 D998).
func runAzure(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("azure", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["azure"], "listen address (loopback)")
	clientFile := fs.String("client-file", "", "file holding the only accepted client as CLIENT_ID:SECRET (otherwise any client is)")
	rate := fs.Int("rate-limit", 0, "answer the first N API requests with 429 and Retry-After")
	invalidClient := fs.Bool("invalid-client", false, "refuse every token request (a deleted client secret)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var req azure.Require
	if *clientFile != "" {
		v, err := readSecret(*clientFile)
		if err != nil {
			return err
		}
		id, secret, ok := strings.Cut(v, ":")
		if !ok || id == "" || secret == "" {
			return errors.New("--client-file must hold CLIENT_ID:SECRET")
		}
		req = azure.Require{ClientID: id, ClientSecret: secret}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := azure.New(azure.Faults{RateLimit: *rate, InvalidClient: *invalidClient}, log).WithRequire(req)
	return serve(ctx, *addr, sim.Handler(), log, "sim.azure_listening")
}
