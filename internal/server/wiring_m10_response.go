// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/response/sweep"
)

// responseContainment is graduated containment (G0 M10 D21–D23), the
// reflexdomain.Container the other streams call: failed containment raises
// a response signal through the core Raiser and an owned failure (HR-249).
// notify and bill may be nil (no notifications; Community).
func responseContainment(pool *db.Pool, notify rapp.Notifier, bill *billing.Service) *rapp.Containment {
	c := &rapp.Containment{Pool: pool, Raiser: &alerts.Raiser{}, Failures: &failures.Sink{}, Notify: notify}
	if bill != nil {
		c.Editions = bill
	}
	return c
}

// registerResponseJobs adds the containment confirmation sweep (G0 M10
// D22, HR-249) and returns its schedule.
func registerResponseJobs(reg *jobs.Registry, pool *db.Pool, notify rapp.Notifier, bill *billing.Service, log *slog.Logger) ([]*river.PeriodicJob, error) {
	return sweep.Register(reg, &sweep.Sweeper{Pool: pool, Advance: responseContainment(pool, notify, bill)}, log)
}

// responseNotifier is the M5 notifier, or nil (never a typed nil).
func responseNotifier(m5 *m5Services) rapp.Notifier {
	if m5 != nil && m5.notifications != nil {
		return m5.notifications
	}
	return nil
}
