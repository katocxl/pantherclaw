// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// GenerateBetween is Generate calling between after its first evidence
// read and before it locks the finding (D98a).
func GenerateBetween(ctx context.Context, tx db.TenantTx, finding ids.UUID, between func()) (Outcome, error) {
	return generate(ctx, tx, finding, between)
}
