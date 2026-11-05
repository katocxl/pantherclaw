// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcazurecompute embeds the reviewed tool package for agents that run a script on an Azure virtual machine
// (G0 M34 D993, D993a), so development tooling and tests can import it
// without a path on disk. Production imports go through PackageService with
// a document signed by the offline package root.
package pcazurecompute

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.azure-compute"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
