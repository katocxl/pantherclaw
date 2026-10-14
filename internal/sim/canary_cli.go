// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"flag"
	"io"
	"log/slog"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/canary"
)

// runCanary serves the sandbox's external canary on its own (G0 M9
// decision 2): hits arrive on --host at the DNS (UDP and TCP), HTTPS and
// SSH ports, and GET /hits/{marker} on --query-addr, a loopback address,
// says which arrived. pclaw sandbox run runs the same canary in its own
// process and signs its report.
func runCanary(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("canary", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "127.0.0.1", "where hits arrive (outside every sandbox)")
	dns := fs.Int("dns-port", 18453, "DNS port, UDP and TCP")
	https := fs.Int("https-port", 18443, "HTTPS port")
	ssh := fs.Int("ssh-port", 18422, "SSH port")
	query := fs.String("query-addr", "127.0.0.1:18433", "where hits are queried (loopback)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	c := canary.New(log)
	p, err := c.Listen(ctx, *host, canary.Ports{DNS: *dns, HTTPS: *https, SSH: *ssh})
	if err != nil {
		return err
	}
	log.InfoContext(ctx, "sim.canary_listening", slog.String("host", *host), slog.Int("dns", p.DNS), slog.Int("https", p.HTTPS), slog.Int("ssh", p.SSH))
	return serve(ctx, *query, c.QueryHandler(), log, "sim.canary_query_listening")
}
