// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-server: PantherClaw control plane (API, Transaction Authority, workers).
package main

import (
	"os"

	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/servercli"
)

func main() {
	os.Exit(servercli.Main(os.Args[1:], extension.Set{}))
}
