// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/contentsignals/app"
	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// ContentSignals implements pipeline.Reader.
func (r *Reader) ContentSignals(ctx context.Context, org ids.OrgID, run ids.UUID) (pipeline.ContentState, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.ContentState, error) {
		return s.ContentSignals(ctx, org, run)
	})
}

// ContentSignals implements pipeline.Reader: the org's mode, and the kinds on
// the root of run's tree (G0 M27 D507).
func (s *snapshot) ContentSignals(ctx context.Context, org ids.OrgID, run ids.UUID) (pipeline.ContentState, error) {
	q := dbq.New(s.tx)
	mode, err := q.ContentSignalMode(ctx, org)
	if err != nil {
		return pipeline.ContentState{}, err
	}
	out := pipeline.ContentState{Mode: mode}
	if domain.Mode(mode) == domain.ModeOff || run.IsZero() {
		return out, nil
	}
	st, err := q.ContentRunState(ctx, org, run)
	if db.IsNoRows(err) {
		return out, nil
	} else if err != nil {
		return out, err
	}
	out.Kinds, _ = domain.ParseFlag(st.Flag)
	return out, nil
}

// contentResult lands a tool result's flags on the run, in the outcome's
// transaction: the outcome and the flag later decisions read commit together
// (HR-648). A delegated outcome is not inspected and carries none.
func (s *Store) contentResult(ctx context.Context, tx db.TenantTx, org ids.OrgID, e finalize.Execution, txn ids.UUID) error {
	if s.Content == nil || len(e.ContentFindings) == 0 {
		return nil
	}
	run, err := dbq.New(tx).ContentTransactionRun(ctx, org, txn)
	if err != nil {
		return err
	}
	return s.Content.Observe(ctx, tx, app.Observed{
		Org: org, Run: run, Transaction: txn, Surface: ports.SurfaceResult, Findings: findings(e.ContentFindings),
	})
}

// ContentOutbound records an outbound payload's findings, after its decision.
// The decision stands whatever this does: it read the mode and the findings
// itself, so what fails here is only counts and alerts, and is logged by ids.
func (s *Store) ContentOutbound(ctx context.Context, org ids.OrgID, txn ids.UUID, found []pipeline.PayloadFinding) {
	if s.Content == nil || len(found) == 0 {
		return
	}
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		run, err := dbq.New(tx).ContentTransactionRun(ctx, org, txn)
		if err != nil {
			return err
		}
		return s.Content.Observe(ctx, tx, app.Observed{
			Org: org, Run: run, Transaction: txn, Surface: ports.SurfaceOutbound, Findings: findings(found),
		})
	})
	if err != nil {
		slog.ErrorContext(ctx, "authz.content_outbound_not_recorded", slog.String("transaction_id", txn.String()), pclog.Err(err))
	}
}

func findings(in []pipeline.PayloadFinding) []domain.Finding {
	out := make([]domain.Finding, 0, len(in))
	for _, f := range in {
		out = append(out, domain.Finding{Kind: f.Kind, Location: f.Location})
	}
	return out
}
