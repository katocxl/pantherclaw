// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcagentpay embeds the reviewed tool package for agent payments
// with AP2 mandates in a sandbox (G0 M39 D1124), so development tooling
// (`pantherclaw-server dev seed --agentpay-url`) can import it without a
// path on disk. Production imports go through PackageService with a
// document signed by the offline package root.
package pcagentpay

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.agentpay"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
