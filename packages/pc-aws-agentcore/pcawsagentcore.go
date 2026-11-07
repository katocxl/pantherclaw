// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pcawsagentcore embeds the reviewed tool package for Amazon Bedrock AgentCore's control plane (reads only)
// (G0 M34 D993, D993a), so development tooling and tests can import it
// without a path on disk. Production imports go through PackageService with
// a document signed by the offline package root.
package pcawsagentcore

import _ "embed"

// Name and Version identify the embedded package.
const (
	Name    = "pc.aws-agentcore"
	Version = "1.0.0"
)

// Package is the exact package file (package.yaml).
//
//go:embed package.yaml
var Package []byte
