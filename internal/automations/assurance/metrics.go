// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Automation outcome metrics (D38, F752, F753): the hourly
// automation.outcomes samples the operations collector writes, per
// automation or for all of them.

// ErrMetricsRange refuses a range beyond 30 days.
var ErrMetricsRange = pcerr.New(pcerr.InvalidArgument, "METRICS_RANGE_INVALID", "metrics cover at most 30 days")

// Outcomes is one hour's outcomes.
type Outcomes struct {
	Bucket                                                        time.Time
	Completed, Partial, Failed, Reconcile, Interventions, Refused int
}

// GetAutomationMetrics returns hourly outcomes in [from, to), for one
// automation or all; hours without a sample are left out.
func (s *Service) GetAutomationMetrics(ctx context.Context, automation *ids.UUID, from, to time.Time) ([]Outcomes, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return nil, err
	}
	if err := s.edition(ctx, false); err != nil {
		return nil, err
	}
	if !to.After(from) || to.Sub(from) > MaxSimulationRange {
		return nil, ErrMetricsRange
	}
	var out []Outcomes
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListMetricSamples(ctx, dbq.ListMetricSamplesParams{
			OrgID: c.Org, Metrics: []string{operations.MetricAutomationOutcomes}, RangeStart: from, RangeEnd: to,
		})
		if err != nil {
			return err
		}
		out = Aggregate(rows, automation)
		return nil
	}, db.ReadOnly())
	return out, err
}

// Aggregate folds samples ("<automation>/<outcome>") into hourly outcomes
// of one automation (nil: all). Org-wide resolved exceptions count as
// interventions only for all automations.
func Aggregate(rows []dbq.ListMetricSamplesRow, automation *ids.UUID) []Outcomes {
	by := map[time.Time]*Outcomes{}
	var order []time.Time
	for _, r := range rows {
		if r.Metric != operations.MetricAutomationOutcomes || !r.Collected {
			continue
		}
		o, ok := by[r.Bucket]
		if !ok {
			o = &Outcomes{Bucket: r.Bucket}
			by[r.Bucket] = o
			order = append(order, r.Bucket)
		}
		who, what, found := strings.Cut(r.Dimension, "/")
		if !found || (automation != nil && who != automation.String()) {
			continue
		}
		n := int(r.Value.Float64)
		switch what {
		case operations.OutcomeCompleted:
			o.Completed += n
		case operations.OutcomePartial:
			o.Partial += n
		case operations.OutcomeFailed:
			o.Failed += n
		case operations.OutcomeReconcile:
			o.Reconcile += n
		case operations.OutcomeInterventions:
			o.Interventions += n
		case operations.OutcomeRefused:
			o.Refused += n
		}
	}
	out := make([]Outcomes, 0, len(order))
	for _, b := range order {
		out = append(out, *by[b])
	}
	return out
}
