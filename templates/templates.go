// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package templates holds the policy templates pclaw applies (G0 M8 C4):
// data only, applied through the server's existing APIs.
package templates

import "embed"

// FS holds each template in a directory of its name.
//
//go:embed coding-to-production/*.json
var FS embed.FS
