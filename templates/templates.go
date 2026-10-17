// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package templates holds the policy templates pclaw applies (G0 M8 C4):
// data only, applied through the server's existing APIs.
package templates

import "embed"

// FS holds each template in a directory of its name: template.json (its
// name, summary, task ref and disclosure), policy.json, the guardrails it
// sets up and, from M11.1, tests.json (its baseline scenario tests).
//
//go:embed coding-to-production/*.json refunds/*.json release-deployment/*.json production-diagnostics/*.json customer-support/*.json
var FS embed.FS
