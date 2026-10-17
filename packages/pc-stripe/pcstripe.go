// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcstripe embeds the reviewed tool package for Stripe in test
// mode, so development tooling (`pantherclaw-server dev seed --stripe`) and
// tests can import it without a path on disk. Production imports go through
// PackageService with a document signed by the offline package root.
package pcstripe

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.stripe"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
