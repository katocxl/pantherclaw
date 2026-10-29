// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"context"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/investigations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// runGaps lists in a run's pack the coverage and telemetry gaps the run
// inspection reports (rows26 D21, F229): the gap reason is the
// inspection's kind in lower case. A run has one agent, so the gaps are
// listed only when the creator could read its transactions.
func (b *builder) runGaps() error {
	if len(b.txns) == 0 {
		return nil
	}
	run, err := ids.ParseUUID(b.r.scope.Run)
	if err != nil {
		return err
	}
	var gaps []investigations.Gap
	err = b.s.Pool.InTenantTx(b.ctx, b.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		gaps, err = investigations.RunEvidenceGaps(ctx, tx, run)
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	for _, g := range gaps {
		reason, at := strings.ToLower(g.Kind), g.At.UTC().Format(time.RFC3339Nano)
		switch {
		case g.Gateway != nil:
			b.gap("gateway "+g.Gateway.String(), reason, "unseen for longer than %s from %s, inside the run", investigations.HeartbeatWindow, at)
		case g.Kind == investigations.GapNoCoverageClaim:
			b.gap("transaction "+g.Transaction.String(), reason, "its decision on %s claims no coverage", g.Operation)
		default:
			b.gap("transaction "+g.Transaction.String(), reason, "its decision on %s claims coverage below ENFORCED, or expired", g.Operation)
		}
	}
	return nil
}
