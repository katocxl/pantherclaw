// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// intelTexts are the injection_text indicators a gateway's content scan
// matches (G0 M38 D1104): none unless the org consumes the feed (HOLD or
// ALERT_ONLY). Setting the mode and importing a feed give the org's gateways
// a new configuration.
func intelTexts(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]dbq.IntelTextIndicatorsRow, error) {
	st, err := q.GetIntelSettings(ctx, org)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if st.Consume != "HOLD" && st.Consume != "ALERT_ONLY" {
		return nil, nil
	}
	return q.IntelTextIndicators(ctx)
}
