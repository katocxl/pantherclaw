// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/google"
	"github.com/katocxl/pantherclaw/internal/sim/m365"
)

// runGoogle serves the simulated Google Workspace API: Gmail, Drive,
// Calendar and a JWT-bearer token endpoint (G0 M31 D957).
func runGoogle(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("google", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["google"], "listen address (loopback)")
	accountFile := fs.String("service-account-file", "", "service account JSON key file whose key alone signs accepted assertions (otherwise any well-formed RS256 assertion is)")
	rate := fs.Int("rate-limit", 0, "answer the first N API requests with 429 and Retry-After")
	invalidGrant := fs.Bool("invalid-grant", false, "refuse every token request (a disabled key)")
	notFound := fs.Bool("not-found", false, "answer every API request 404")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var account *google.Account
	if *accountFile != "" {
		b, err := os.ReadFile(*accountFile)
		if err != nil {
			return err
		}
		if account, err = google.ParseAccount(b); err != nil {
			return err
		}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := google.New(account, google.Faults{RateLimit: *rate, InvalidGrant: *invalidGrant, NotFound: *notFound}, log)
	return serve(ctx, *addr, sim.Handler(), log, "sim.google_listening")
}

// runM365 serves the simulated Microsoft Graph with a client-credentials
// token endpoint (G0 M31 D957).
func runM365(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("m365", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["m365"], "listen address (loopback)")
	clientFile := fs.String("client-file", "", "file holding the only accepted client as CLIENT_ID:SECRET (otherwise any client is)")
	rate := fs.Int("rate-limit", 0, "answer the first N Graph requests with 429 and Retry-After")
	invalidClient := fs.Bool("invalid-client", false, "refuse every token request (a deleted client secret)")
	notFound := fs.Bool("not-found", false, "answer every Graph request 404")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var req m365.Require
	if *clientFile != "" {
		b, err := os.ReadFile(*clientFile)
		if err != nil {
			return err
		}
		id, secret, ok := strings.Cut(strings.TrimSpace(string(b)), ":")
		if !ok || id == "" || secret == "" {
			return errors.New("--client-file must hold CLIENT_ID:SECRET")
		}
		req = m365.Require{ClientID: id, ClientSecret: secret}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := m365.New(m365.Faults{RateLimit: *rate, InvalidClient: *invalidClient, NotFound: *notFound}, log).WithRequire(req)
	return serve(ctx, *addr, sim.Handler(), log, "sim.m365_listening")
}
