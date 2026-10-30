// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcteams embeds the reviewed tool package for agents that post to
// Microsoft Teams channels (G0 M20 D254), so development tooling and tests
// can import it without a path on disk. Production imports go through
// PackageService with a document signed by the offline package root.
package pcteams

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.teams"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
