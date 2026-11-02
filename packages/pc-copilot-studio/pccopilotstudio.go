// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pccopilotstudio embeds the reviewed package for SaaS agent
// discovery from Microsoft Copilot Studio (G0 M26 D407, D534), so development
// tooling and tests can import it without a path on disk. Production imports
// go through PackageService with a document signed by the offline package
// root. Its API shape is unconfirmed until a real tenant check: it is tested
// on synthetic fixtures and a simulator only.
package pccopilotstudio

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.copilot-studio"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
