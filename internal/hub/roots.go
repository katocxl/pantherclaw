// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package hub holds the Hub root keys compiled into this binary (G0 M23
// D101). Until the founder commits the offline public key, roots.json is
// empty and only a loopback server or source trusts any key, the development
// Hub key; everywhere else verification ends in HUB_NO_ROOT.
package hub

import (
	_ "embed"

	"github.com/katocxl/pantherclaw/internal/hub/domain"
)

//go:embed roots.json
var embeddedRoots []byte

// EmbeddedRoots returns the Hub roots compiled into this binary.
func EmbeddedRoots() (domain.Roots, error) { return domain.ParseRoots(embeddedRoots) }
