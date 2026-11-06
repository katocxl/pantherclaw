// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcawss3 embeds the reviewed tool package for agents that change
// who can reach an Amazon S3 bucket (G0 M30 D934, D934a), so development
// tooling and tests can import it without a path on disk. Production imports
// go through PackageService with a document signed by the offline package
// root.
package pcawss3

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.aws.s3"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
