// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"maps"

	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// Catalog returns a copy of the fact types the bundle was compiled with.
// With Limits and the bundle itself it is everything a later compilation
// needs to evaluate the same rules the same way (decision replay, G0 M7
// design decision 11).
func (c *Compiled) Catalog() map[string]fdomain.Type { return maps.Clone(c.facts) }

// Limits returns the CEL limits the bundle was compiled with.
func (c *Compiled) Limits() celenv.Limits { return c.limits }
