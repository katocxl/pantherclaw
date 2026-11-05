// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pccomputer embeds the reviewed tool package for computer-use
// actions a cooperative agent asks to take on its screen (G0 M33 D984), so
// development tooling and tests can import it without a path on disk.
// Production imports go through PackageService with a document signed by
// the offline package root.
package pccomputer

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.computer"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
