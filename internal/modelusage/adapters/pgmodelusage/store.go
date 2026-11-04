// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgmodelusage keeps model usage rows in PostgreSQL and sums them
// for the monthly token report (G0 M29 D825). Rows are append-only.
package pgmodelusage

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/modelusage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Store reads and writes pc.model_usage in the caller's tenant
// transaction.
type Store struct{}

// Insert writes one model call's usage row. It runs in the transaction
// that records the call's outcome, so the row and the outcome commit
// together.
func (Store) Insert(ctx context.Context, tx db.TenantTx, r domain.Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	p := dbq.InsertModelUsageParams{
		OrgID: tx.OrgID(), ID: r.ID, TransactionID: r.TransactionID,
		RunID: r.RunID, AgentID: r.AgentID, TeamID: r.TeamID, ConnectionID: r.ConnectionID,
		Operation: r.Operation, Model: r.Model, Outcome: string(r.Outcome), Reported: r.Usage.Reported,
		InputTokens: r.Usage.InputTokens, OutputTokens: r.Usage.OutputTokens,
		CacheReadTokens: r.Usage.CacheReadTokens, CacheWriteTokens: r.Usage.CacheWriteTokens,
		RecordedAt: r.RecordedAt,
	}
	if r.Estimate != nil {
		amount, currency := r.Estimate.Amount, string(r.Estimate.Currency)
		p.Estimate, p.EstimateCurrency = &amount, &currency
	}
	return dbq.New(tx).InsertModelUsage(ctx, p)
}

// Call is a model call's outcome as RecordExecution has it (D825).
type Call struct {
	TransactionID ids.UUID
	ConnectionID  ids.UUID
	Outcome       domain.Outcome
	// Usage is what the gateway reported; zero (unreported) when it sent
	// none, and always zero for an UNKNOWN outcome.
	Usage domain.Usage
	// Estimates says whether the org is on Team or higher now (D829): only
	// then is an estimate written, from the connection's price.
	Estimates  bool
	RecordedAt time.Time
}

// RecordCall writes the usage row of a model create or count call in the
// caller's transaction (the one that records its outcome), reading the
// operation, run, agent, the agent's team and the model from the
// transaction. Other operations leave no row; it reports whether it wrote
// one.
func (s Store) RecordCall(ctx context.Context, tx db.TenantTx, c Call) (bool, error) {
	ctxRow, err := dbq.New(tx).ModelUsageContext(ctx, c.ConnectionID, tx.OrgID(), c.TransactionID)
	if err != nil {
		return false, err
	}
	if !domain.UsageOperations[ctxRow.Operation] {
		return false, nil
	}
	u := c.Usage
	if c.Outcome == domain.OutcomeUnknown || !u.Reported {
		u = domain.Usage{} // HR-003: nothing is known of an UNKNOWN call
	}
	run := ctxRow.RunID
	r := domain.Record{
		ID: ids.NewV7(), TransactionID: c.TransactionID, RunID: &run, AgentID: ctxRow.AgentID, TeamID: ctxRow.TeamID,
		ConnectionID: c.ConnectionID, Operation: ctxRow.Operation, Model: ctxRow.Model, Outcome: c.Outcome,
		Usage: u, RecordedAt: c.RecordedAt,
	}
	if utf8.RuneCountInString(r.Model) > domain.MaxModelLength {
		r.Model = string([]rune(r.Model)[:domain.MaxModelLength])
	}
	if c.Estimates && ctxRow.PriceCurrency != nil && ctxRow.PriceInput != nil && ctxRow.PriceOutput != nil {
		p := domain.Price{
			Currency: money.Currency(*ctxRow.PriceCurrency), Input: *ctxRow.PriceInput, Output: *ctxRow.PriceOutput,
			CacheRead: ctxRow.PriceCacheRead, CacheWrite: ctxRow.PriceCacheWrite,
		}
		if est, err := domain.Estimate(u, p); err == nil {
			r.Estimate = &est
		}
		// An estimate past the decimal range is left out, never wrapped.
	}
	return true, s.Insert(ctx, tx, r)
}

// ReportQuery is one page of a monthly token report.
type ReportQuery struct {
	Month domain.Month
	By    domain.GroupBy
	// After is the last key of the previous page; HasAfter is false on the
	// first page.
	After    string
	HasAfter bool
	// Limit is the number of groups to read (a page plus one).
	Limit int32
}

// Report sums the month's rows per key, in key order.
func (Store) Report(ctx context.Context, tx db.TenantTx, q ReportQuery) ([]domain.Group, error) {
	if !q.By.Valid() {
		return nil, fmt.Errorf("pgmodelusage: group by %q", q.By)
	}
	rows, err := dbq.New(tx).ModelUsageReport(ctx, dbq.ModelUsageReportParams{
		GroupBy: string(q.By), OrgID: tx.OrgID(), MonthStart: q.Month.Start, MonthEnd: q.Month.End,
		HasAfter: q.HasAfter, After: q.After, RowLimit: q.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Group, 0, len(rows))
	for _, r := range rows {
		g := domain.Group{
			Key: r.Key, Calls: r.Calls, UnreportedCalls: r.UnreportedCalls, UnknownCalls: r.UnknownCalls,
			InputTokens: r.InputTokens, OutputTokens: r.OutputTokens,
			CacheReadTokens: r.CacheReadTokens, CacheWriteTokens: r.CacheWriteTokens,
		}
		if len(r.EstimateCurrencies) != len(r.EstimateAmounts) {
			return nil, fmt.Errorf("pgmodelusage: %d estimate currencies, %d amounts", len(r.EstimateCurrencies), len(r.EstimateAmounts))
		}
		for i, c := range r.EstimateCurrencies {
			amount, err := money.Parse(r.EstimateAmounts[i])
			if err != nil {
				return nil, fmt.Errorf("pgmodelusage: estimate %q: %w", r.EstimateAmounts[i], err)
			}
			g.Estimates = append(g.Estimates, domain.Amount{Currency: money.Currency(c), Amount: amount})
		}
		out = append(out, g)
	}
	return out, nil
}
