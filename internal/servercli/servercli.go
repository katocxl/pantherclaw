// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package servercli is the pantherclaw-server command line: the public
// binary and a private build call Main with their extension set
// (internal/extension), so both run every subcommand the same way.
package servercli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/server"
)

// Main runs pantherclaw-server with args (without the program name) and
// returns the exit code; SIGINT and SIGTERM stop it gracefully.
func Main(args []string, ext extension.Set) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.RunCommand(ctx, args, os.Stdout, os.Stderr, os.LookupEnv, ext)
}
