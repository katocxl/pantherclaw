// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcpostgres embeds the reviewed tool package for read-only
// PostgreSQL queries (G0 M14, PN-017.4), so development tooling
// (`pantherclaw-server dev seed`) and tests can import it without a path on
// disk. Production imports go through PackageService with a document signed
// by the offline package root.
package pcpostgres

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.postgres"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
