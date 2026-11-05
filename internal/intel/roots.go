// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package intel holds the intel root keys compiled into this binary (G0 M38
// D1103). Until the founder commits the offline public key, roots.json is
// empty and only a loopback server trusts any key, the development intel
// key; everywhere else verification ends in INTEL_NO_ROOT.
package intel

import (
	_ "embed"

	"github.com/katocxl/pantherclaw/internal/intel/domain"
)

//go:embed roots.json
var embeddedRoots []byte

// EmbeddedRoots returns the intel roots compiled into this binary.
func EmbeddedRoots() (domain.Roots, error) { return domain.ParseRoots(embeddedRoots) }
