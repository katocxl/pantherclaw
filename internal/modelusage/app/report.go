// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the monthly token report use case (G0 M29 D825, D829;
// F988; HR-698): budget.read at the org, the Team edition, one UTC month
// of the org's model calls grouped by team, agent, connection or model.
package app

import (
	"context"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/modelusage/adapters/pgmodelusage"
	"github.com/katocxl/pantherclaw/internal/modelusage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	// ErrTeam refuses the report below the Team edition (D829).
	ErrTeam = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "the token report needs the Team edition or above")
	// ErrInvalidMonth refuses a month that is not YYYY-MM.
	ErrInvalidMonth = pcerr.New(pcerr.InvalidArgument, "INVALID_MONTH", "the month is not YYYY-MM")
	// ErrInvalidGroupBy refuses an unknown grouping.
	ErrInvalidGroupBy = pcerr.New(pcerr.InvalidArgument, "INVALID_GROUP_BY", "group by team, agent, connection or model")
	// ErrInvalidPageToken refuses a page token this report did not issue.
	ErrInvalidPageToken = pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE_TOKEN", "invalid page token")
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service serves the monthly token report.
type Service struct {
	Pool *db.Pool
	// Editions gates the report; nil is the Community edition (fail closed).
	Editions Editions
}

// ReportRequest is one page of a report.
type ReportRequest struct {
	Month     string
	By        domain.GroupBy
	PageSize  int32
	PageToken string
}

// Report is one page of the report and the statement it carries.
type Report struct {
	Rows      []domain.Row
	Next      string
	Statement string
}

// Report returns one page of the month's report, in key order.
func (s *Service) Report(ctx context.Context, in ReportRequest) (Report, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Report{}, err
	}
	if !c.Can(td.PermBudgetRead, td.OrgPath(c.Org)) {
		return Report{}, td.ErrPermissionDenied(td.PermBudgetRead)
	}
	if s.Editions == nil {
		return Report{}, ErrTeam
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return Report{}, err
	}
	if !e.TokenCostReports() {
		return Report{}, ErrTeam
	}
	month, err := domain.ParseMonth(in.Month)
	if err != nil {
		return Report{}, ErrInvalidMonth
	}
	if !in.By.Valid() {
		return Report{}, ErrInvalidGroupBy
	}
	after, hasAfter, err := domain.DecodeCursor(in.PageToken)
	if err != nil {
		return Report{}, ErrInvalidPageToken
	}
	size := domain.PageSize(in.PageSize)
	var out Report
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		groups, err := pgmodelusage.Store{}.Report(ctx, tx, pgmodelusage.ReportQuery{
			Month: month, By: in.By, After: after, HasAfter: hasAfter, Limit: int32(size + 1), //nolint:gosec // G115: ≤ MaxPageSize+1
		})
		if err != nil {
			return err
		}
		if len(groups) > size {
			groups = groups[:size]
			out.Next = domain.EncodeCursor(groups[size-1].Key)
		}
		labels, err := s.labels(ctx, tx, c.Org, in.By, groups)
		if err != nil {
			return err
		}
		out.Rows, err = domain.BuildRows(groups, labels)
		return err
	}, db.ReadOnly())
	if err != nil {
		return Report{}, err
	}
	out.Statement = domain.Statement
	return out, nil
}

// labels names the page's team, agent or connection keys; models and the
// empty key are their own labels.
func (s *Service) labels(ctx context.Context, tx db.TenantTx, org ids.OrgID, by domain.GroupBy, groups []domain.Group) (map[string]string, error) {
	if by == domain.ByModel {
		return nil, nil
	}
	keys := make([]ids.UUID, 0, len(groups))
	for _, g := range groups {
		if id, err := ids.ParseUUID(g.Key); err == nil {
			keys = append(keys, id)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	rows, err := dbq.New(tx).ModelUsageLabels(ctx, string(by), keys, org)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Key] = r.Label
	}
	return out, nil
}
