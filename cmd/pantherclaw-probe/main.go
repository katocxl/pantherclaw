// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-probe: the containment sandbox's closure probes (G0
// M9, internal/sandbox/probe). It runs in its own container on the agent's
// network, started by pclaw sandbox run, and prints its signed report.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/katocxl/pantherclaw/internal/sandbox/probe"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := probe.Main(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
