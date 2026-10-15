// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rollout

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// samplesPerCategory is how many of the newest results of each changed
// category a summary shows.
const samplesPerCategory = 5

// ShadowSummary is what a rollout's shadow evaluation predicts (D13, F203):
// counts, and samples by id, decision and reason. It never carries a
// recorded input value (HR-237); those stay behind ReplayDecision and its
// own permission. Label says it is a prediction.
type ShadowSummary struct {
	Label   string
	Rollout ids.UUID
	// Total and ByCategory count every shadow evaluation; ByDay by UTC day.
	Total      int64
	ByCategory map[replay.Category]int64
	ByDay      []DayCount
	// NewlyHeldPerDay is the approval burden: decisions the version would
	// hold for approval or step-up that were not held.
	NewlyHeldPerDay []DayCount
	// ByOperation and ByAgent count the stored results; Truncated reports
	// that past 100 000 results only the totals above grew.
	ByOperation []GroupCount
	ByAgent     []GroupCount
	Truncated   bool
	Samples     []Sample
}

// DayCount is a count of one category on one UTC day.
type DayCount struct {
	Day      string
	Category replay.Category
	N        int64
}

// GroupCount is a count of one category for an operation or an agent.
type GroupCount struct {
	Key      string
	Category replay.Category
	N        int64
}

// Sample is one shadow result: ids, decisions and reasons only.
type Sample struct {
	Transaction      ids.UUID
	Evaluation       int
	Agent            ids.UUID
	Operation        string
	OriginalDecision string
	OriginalReason   string
	ShadowDecision   string
	ShadowReason     string
	Category         replay.Category
	Limitation       string
	At               time.Time
}

// GetShadowSummary returns a rollout's shadow summary (policy.read).
func (s *Service) GetShadowSummary(ctx context.Context, rollout ids.UUID) (ShadowSummary, error) {
	c, err := reader(ctx)
	if err != nil {
		return ShadowSummary{}, err
	}
	out := ShadowSummary{
		Label: ShadowLabel, Rollout: rollout, ByCategory: map[replay.Category]int64{}, ByDay: []DayCount{}, NewlyHeldPerDay: []DayCount{},
		ByOperation: []GroupCount{}, ByAgent: []GroupCount{}, Samples: []Sample{},
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetPolicyRollout(ctx, c.Org, rollout); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		days, err := q.ShadowCountsByDay(ctx, c.Org, rollout)
		if err != nil {
			return err
		}
		for _, d := range days {
			dc := DayCount{Day: d.Day.Time.Format(time.DateOnly), Category: replay.Category(d.Category), N: d.N}
			out.ByDay = append(out.ByDay, dc)
			out.ByCategory[dc.Category] += d.N
			out.Total += d.N
			if dc.Category == replay.NewlyHeld {
				out.NewlyHeldPerDay = append(out.NewlyHeldPerDay, dc)
			}
		}
		ops, err := q.ShadowResultsByOperation(ctx, c.Org, rollout)
		if err != nil {
			return err
		}
		var stored int64
		for _, o := range ops {
			out.ByOperation = append(out.ByOperation, GroupCount{Key: o.Operation, Category: replay.Category(o.Category), N: o.N})
			stored += o.N
		}
		out.Truncated = stored < out.Total
		agents, err := q.ShadowResultsByAgent(ctx, c.Org, rollout)
		if err != nil {
			return err
		}
		for _, a := range agents {
			out.ByAgent = append(out.ByAgent, GroupCount{Key: a.AgentID.String(), Category: replay.Category(a.Category), N: a.N})
		}
		samples, err := q.ShadowSamples(ctx, c.Org, rollout, samplesPerCategory)
		if err != nil {
			return err
		}
		for _, x := range samples {
			out.Samples = append(out.Samples, Sample{
				Transaction: x.TransactionID, Evaluation: int(x.Evaluation), Agent: x.AgentID, Operation: x.Operation,
				OriginalDecision: x.OriginalDecision, OriginalReason: x.OriginalReason, ShadowDecision: deref(x.ShadowDecision),
				ShadowReason: deref(x.ShadowReason), Category: replay.Category(x.Category), Limitation: deref(x.Limitation), At: x.CreatedAt,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
