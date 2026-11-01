// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// newCardSigner signs the A2A cards gateways serve (G0 M24 D232).
func newCardSigner(pool *db.Pool, reg *keys.Registry) *a2astore.CardSigner {
	return &a2astore.CardSigner{Pool: pool, Keys: reg}
}
