// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"flag"
	"io"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/agentpay"
)

// runAgentPay serves the simulated AP2 merchant and credentials provider,
// with fixed development keys on loopback (G0 M39 D1124).
func runAgentPay(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("agentpay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["agentpay"], "listen address (loopback)")
	mismatch := fs.Bool("mismatch", false, "sign mandates for one minor unit more than the checkout")
	expired := fs.Bool("expired", false, "sign mandates that expired a minute ago")
	decline := fs.Bool("decline", false, "answer every checkout as declined")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := agentpay.New(agentpay.Faults{Mismatch: *mismatch, Expired: *expired, Decline: *decline}, log)
	return serve(ctx, *addr, sim.Handler(), log, "sim.agentpay_listening")
}
