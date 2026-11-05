// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcawsssm embeds the reviewed tool package for agents that run
// commands on Amazon EC2 instances through AWS Systems Manager (G0 M34
// D993a item 3, D1002), so development tooling and tests can import it
// without a path on disk. Production imports go through PackageService with
// a document signed by the offline package root.
package pcawsssm

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.aws-ssm"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
