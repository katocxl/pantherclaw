// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"
	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/agents/adapters/agentsrpc"
	"github.com/katocxl/pantherclaw/internal/approvals/adapters/approvalsrpc"
	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/billing"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/waitlistrpc"
	wapp "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// m5p2Services are the M5 part 2 services (G0 M5 part 2): approvals and
// restorations, the waitlist's reads and writes, routing, wait handles and
// the waitlist histograms.
type m5p2Services struct {
	pool       *db.Pool
	approvals  *apapp.Service
	reader     *wapp.Reader
	writer     *wapp.Writer
	router     *wapp.Router
	notify     *napp.Service
	histograms *wapp.Histograms
	// waits serve one API server's waiters.
	waits *apapp.Waits
}

// newM5p2 wires approvals to the notifications, the edition, the
// definitions and the decision pipeline (for narrower proposals).
func newM5p2(cfg *Config, pool *db.Pool, bill *billing.Service, notify *napp.Service, log *slog.Logger) (*m5p2Services, error) {
	h, err := wapp.NewHistograms(nil)
	if err != nil {
		return nil, err
	}
	return &m5p2Services{
		pool: pool,
		approvals: &apapp.Service{
			Pool: pool, Simulator: &authority.Narrower{Pipeline: &pipeline.Pipeline{Reader: authorityReader(pool)}, Pool: pool},
			Defs: &defspg.Store{Pool: pool}, Ents: bill, Notify: notify,
		},
		reader: wapp.NewReader(pool).WithEntitlements(bill), writer: wapp.NewWriter(pool),
		router: &wapp.Router{Pool: pool, Notify: notify}, notify: notify, histograms: h,
		waits: apapp.NewWaits(pool, cfg.Waitlist.MaxWaitsPerInstance, cfg.Waitlist.MaxWaits, log).WithLongPoll(cfg.Waitlist.LongPollMax.D()),
	}, nil
}

// registerPublic adds ApprovalService to the public API.
func (m *m5p2Services) registerPublic(rs *connect.Server) {
	pantherclawv1connect.RegisterApprovalServiceHandler(rs, approvalsrpc.NewApprovals(m.approvals))
}

// waitlist is WaitlistService with its writes and metrics.
func (m *m5p2Services) waitlist() *waitlistrpc.Waitlist {
	return waitlistrpc.NewWaitlist(m.reader).WithWriter(m.writer)
}

// agents adds restoration requests to AgentService.
func (m *m5p2Services) agents(a *agentsrpc.Agents) *agentsrpc.Agents {
	return a.WithRestorations(m.approvals)
}

// workload adds waiting, evidence and access requests to WorkloadService.
func (m *m5p2Services) workload(w *workloadrpc.Workload) *workloadrpc.Workload {
	return w.WithApprovals(m.approvals, m.writer).WithWaits(m.waits)
}

// mount adds the SSE route of wait handles (HR-174).
func (m *m5p2Services) mount(mux *http.ServeMux, w *workloadrpc.Workload) {
	mux.HandleFunc("GET "+workloadrpc.WaitPath+"{transaction}", w.WaitStream)
}

// mountPages adds the approval page; approving needs security keys.
func (m *m5p2Services) mountPages(web *webhttp.Handler, m5 *m5Services) {
	if m5.webauthn != nil {
		web.WithApprovals(m.approvals, m5.webauthn)
	}
}

// serveWaits wakes this server's waiters on LISTEN pc_wait.
func (m *m5p2Services) serveWaits(ctx context.Context, g *errgroup.Group) {
	g.Go(func() error { return m.waits.Run(ctx) })
}

// registerWorkers adds the approvals janitor, routing and escalation, and
// the histogram observer.
func (m *m5p2Services) registerWorkers(reg *jobs.Registry, log *slog.Logger) error {
	if err := apapp.RegisterJanitor(reg, m.pool, m.notify, log); err != nil {
		return err
	}
	if err := wapp.RegisterRouting(reg, m.router, log); err != nil {
		return err
	}
	return wapp.RegisterObserver(reg, m.pool, m.histograms)
}

// periodicJobs are the M5 part 2 schedules.
func (m *m5p2Services) periodicJobs() []*river.PeriodicJob {
	out := apapp.JanitorPeriodicJobs()
	out = append(out, wapp.RoutingPeriodicJobs()...)
	return append(out, wapp.ObservePeriodicJobs()...)
}
