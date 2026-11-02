// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/campaigns/adapters/pgcampaigns"
	capp "github.com/katocxl/pantherclaw/internal/campaigns/app"
	"github.com/katocxl/pantherclaw/internal/campaigns/ports"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// newCampaigns is the campaign service RangeService serves (G0 M25 D309).
// Editions come from the licence; without one the server is Community, which
// runs no campaign.
func newCampaigns(d apiDeps) *capp.Service {
	svc := &capp.Service{Store: pgcampaigns.Store{Pool: d.pool}}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	return svc
}

// campaignResults is the read port compliance evidence uses (D312).
func campaignResults(pool *db.Pool) ports.ResultReader { return pgcampaigns.Store{Pool: pool} }

// appendCampaignJobs adds the campaign abandon sweep to the schedule.
func appendCampaignJobs(sched []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, log *slog.Logger) ([]*river.PeriodicJob, error) {
	more, err := pgcampaigns.RegisterAbandon(reg, pool, log)
	if err != nil {
		return nil, err
	}
	return append(sched, more...), nil
}
