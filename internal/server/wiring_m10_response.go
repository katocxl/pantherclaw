// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/response/adapters/responserpc"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/response/sweep"
)

// responseContainment is graduated containment (G0 M10 D21–D23), the
// reflexports.Container the other streams call: failed containment raises
// a response signal through the core Raiser and an owned failure (HR-249).
// notify and bill may be nil (no notifications; Community).
func responseContainment(pool *db.Pool, notify rapp.Notifier, bill *billing.Service) *rapp.Containment {
	c := &rapp.Containment{
		Pool: pool, Raiser: m10Raiser{pool: pool}, Failures: &failures.Sink{}, Notify: notify, Reach: m10Reach(pool, bill),
	}
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

// containmentHolds lets ResponseService decline writes held by a HOLD_WRITES
// control, through approvals (G0 M10 D44); approving stays on the approval
// page, which checks the same eligibility with a security key.
type containmentHolds struct {
	approvals *apapp.Service
	publicURL string
}

func (h containmentHolds) DeclineContainmentHold(ctx context.Context, transaction ids.UUID, note string) error {
	_, err := h.approvals.DeclineContainmentHold(ctx, transaction, note)
	return err
}

func (h containmentHolds) HoldPage(ctx context.Context, org ids.OrgID, transaction ids.UUID) (string, error) {
	id, err := h.approvals.ContainmentHold(ctx, org, transaction)
	if err != nil {
		return "", err
	}
	return h.publicURL + authnapp.ApprovalsPath + "/" + id.String(), nil
}

// registerResponse serves ResponseService on the public API (G0 M10
// D21–D26). The procedure permissions are in procedures_m10_response.go;
// the use cases check the scope's path, people-only rules and step-ups.
func registerResponse(rs *connect.Server, d apiDeps) {
	var notify rapp.Notifier
	if d.m5 != nil {
		notify = responseNotifier(d.m5)
	}
	r := &rapp.Response{C: responseContainment(d.pool, notify, d.billing), Replay: replayEngine(d.pool, d.kp)}
	if d.m5p2 != nil && d.m5p2.approvals != nil {
		r.Holds = containmentHolds{approvals: d.m5p2.approvals, publicURL: d.publicURL}
	}
	pantherclawv1connect.RegisterResponseServiceHandler(rs, responserpc.NewResponse(r))
}
