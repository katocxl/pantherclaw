// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Verification (G0 M7 design decision 1, HR-190): every VerifyEvery the
// gateway claims the verification tasks of the connections it serves,
// makes each reviewed read and reports what it observed. A task it cannot
// or may not read is left to its lease, which expires, so the server tries
// again later and, when the window closes, records the effect as UNKNOWN.

// VerifyEvery is how often the gateway claims due verification tasks.
const VerifyEvery = 10 * time.Second

// maxLeases is the most tasks one claim asks for.
const maxLeases = 16

// Verifications claims and reports verification tasks (GatewayService over
// mutual TLS).
type Verifications interface {
	Claim(ctx context.Context, limit int) ([]dispatch.Lease, error)
	Report(ctx context.Context, l dispatch.Lease, o dispatch.Observation) error
}

// watchVerifications claims and verifies due tasks until ctx ends.
func (g *Gateway) watchVerifications(ctx context.Context) error {
	if g.verifications == nil {
		<-ctx.Done()
		return nil
	}
	tick := time.NewTicker(g.verifyEvery)
	defer tick.Stop()
	for {
		g.verifyDue(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// verifyDue claims due tasks and verifies each.
func (g *Gateway) verifyDue(ctx context.Context) {
	cfg := g.config.Current()
	if cfg == nil {
		return
	}
	leases, err := g.verifications.Claim(ctx, maxLeases)
	if err != nil {
		g.log.WarnContext(ctx, "gateway.verifications_unavailable", pclog.Err(err))
		return
	}
	for _, l := range leases {
		conn := cfg.ByID[l.Connection]
		if conn == nil {
			g.log.WarnContext(ctx, "gateway.verification_unknown_connection", slog.String("task_id", l.Task),
				slog.String("connection_id", l.Connection))
			continue
		}
		o, err := g.engine.VerifyEffect(ctx, conn, l)
		switch {
		case errors.Is(err, dispatch.ErrNotReviewedRead):
			g.log.ErrorContext(ctx, "security.verification_refused", slog.String("task_id", l.Task),
				slog.String("connection_id", l.Connection), slog.String("operation", l.Operation))
			continue
		case err != nil:
			g.log.InfoContext(ctx, "gateway.verification_deferred", slog.String("task_id", l.Task), pclog.Err(err))
			continue
		}
		if err := g.verifications.Report(ctx, l, o); err != nil {
			g.log.WarnContext(ctx, "gateway.verification_not_reported", slog.String("task_id", l.Task), pclog.Err(err))
		}
	}
}

// controlVerifications is Verifications over the gateway's mTLS identity.
type controlVerifications struct{ ctl *control.Client }

// Claim implements Verifications.
func (c controlVerifications) Claim(ctx context.Context, limit int) ([]dispatch.Lease, error) {
	res, err := c.ctl.Gateway.ClaimVerifications(ctx, &pb.ClaimVerificationsRequest{MaxTasks: int32(min(limit, maxLeases))}) //nolint:gosec // G115: at most maxLeases
	if err != nil {
		return nil, err
	}
	out := make([]dispatch.Lease, 0, len(res.GetLeases()))
	for _, l := range res.GetLeases() {
		out = append(out, dispatch.Lease{
			Connection: l.GetConnectionId(), Task: l.GetTaskId(), Secret: l.GetLease(), Purpose: l.GetPurpose(),
			Operation: l.GetOperation(), Request: l.GetRequest(), Correlate: l.GetCorrelate(),
		})
	}
	return out, nil
}

// Report implements Verifications.
func (c controlVerifications) Report(ctx context.Context, l dispatch.Lease, o dispatch.Observation) error {
	req := &pb.ReportObservationRequest{
		TaskId: l.Task, Lease: l.Secret, HttpStatus: int32(min(max(o.HTTPStatus, 0), 599)), Found: o.Found,
		Complete: o.Complete, Fields: o.Fields, ResponseDigest: o.Digest,
	}
	for _, it := range o.Items {
		req.Items = append(req.Items, &pb.TargetLogItem{ObjectRef: it.ObjectRef, Correlation: it.Correlation, Created: it.Created})
	}
	_, err := c.ctl.Gateway.ReportObservation(ctx, req)
	return err
}
