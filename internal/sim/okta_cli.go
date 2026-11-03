// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"flag"
	"io"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/okta"
)

// runOkta serves the simulated identity provider that issues ID-JAGs (G0
// M26 D400, D403). Its issuer is --base-url, which must be the address
// PantherClaw reaches it at.
func runOkta(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("okta", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9101", "listen address (loopback)")
	base := fs.String("base-url", "", "issuer identifier (default http://ADDR)")
	expired := fs.Bool("expired", false, "issue assertions that already expired")
	wrongAud := fs.Bool("wrong-audience", false, "address assertions to another authorization server")
	cnf := fs.Bool("cnf", false, "add a cnf claim to every assertion")
	if err := fs.Parse(args); err != nil {
		return err
	}
	issuer := *base
	if issuer == "" {
		issuer = "http://" + *addr
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim, err := okta.New(issuer, okta.Faults{Expired: *expired, WrongAudience: *wrongAud, Cnf: *cnf}, log)
	if err != nil {
		return err
	}
	return serve(ctx, *addr, sim.Handler(), log, "sim.okta_listening")
}
