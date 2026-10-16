// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package grantstest

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// OpenGate is a promotion gate that passes every grant and caps none, for
// integration fixtures that test grants and authorization rather than the
// gate (G0 M11 part 2 D81, D116). A store without a gate refuses every
// production grant (D114); production code always wires the promotions
// gate, never this one.
type OpenGate struct{}

var _ app.PromotionGate = OpenGate{}

// Check implements app.PromotionGate: everything passes, nothing is capped.
func (OpenGate) Check(context.Context, pgx.Tx, ids.OrgID, ids.UUID, ids.UUID, domain.Ops) (*time.Time, error) {
	return nil, nil
}
