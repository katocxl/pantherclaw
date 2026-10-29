// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"context"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/investigations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// GapCoverageGapsOmitted is the reason of the gap a run's pack carries in
// place of its coverage and telemetry gaps when its creator cannot read
// coverage where the run's agent lives.
const GapCoverageGapsOmitted = "coverage_gaps_omitted"

// runGaps lists in a run's pack the coverage and telemetry gaps the run
// inspection reports (rows26 D21, F229): the gap reason is the
// inspection's kind in lower case. A run has one agent, so the gaps are
// listed only when the creator could read its transactions, and only when
// the creator holds coverage.read where the run's agent lives (the gate
// of the inspection's gaps, D21a); otherwise one gap says so, with no
// count (rows26 D25).
func (b *builder) runGaps() error {
	if len(b.txns) == 0 {
		return nil
	}
	run, err := ids.ParseUUID(b.r.scope.Run)
	if err != nil {
		return err
	}
	p, err := b.agentPath(b.txns[0].Transaction.Agent)
	if err != nil {
		return err
	}
	if g := coverageGapsOmitted(b.c, p, run); g != nil {
		b.m.Gaps = append(b.m.Gaps, *g)
		return nil
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

// coverageGapsOmitted is the one gap a run's pack carries in place of its
// coverage and telemetry gaps when c cannot read coverage at the run
// agent's path p, or nil when c can (D21a's gate).
func coverageGapsOmitted(c tenancy.Caller, p td.Path, run ids.UUID) *pack.Gap {
	if c.Require(td.PermCoverageRead, p) == nil {
		return nil
	}
	return &pack.Gap{
		Subject: "run " + run.String(), Reason: GapCoverageGapsOmitted,
		Detail: "the pack's creator cannot read coverage where the run's agent lives",
	}
}
