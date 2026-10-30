// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-host: the host agent of a PantherClaw hosting host
// (G0 M19 D203). It runs one isolated gateway container per org placed on
// its host and routes agents to it by TLS server name.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/katocxl/pantherclaw/internal/hosting/agent"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := agent.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}
