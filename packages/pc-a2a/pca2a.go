// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pca2a embeds the reviewed tool package for peer agents reached
// over the A2A protocol (G0 M14 D32), so development tooling and tests can
// import it without a path on disk. Production imports go through
// PackageService with a document signed by the offline package root.
package pca2a

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.a2a"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
