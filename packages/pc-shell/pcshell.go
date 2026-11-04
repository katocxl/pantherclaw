// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcshell embeds the reviewed tool package for shell commands asked
// for by a cooperative coding agent (the Claude Code hook, G0 M6), so
// development tooling and tests can import it without a path on disk.
// Production imports go through PackageService with a document signed by
// the offline package root.
package pcshell

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.shell"
	Version = "1.1.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
