// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// Status reports (G0 M15 D10, HR-410): each gateway process is a replica
// with a random id. It reports its version, build, start time, the config
// version it serves and each connection's serving state on start, every
// interval the server answers, and statusSettle after a connection's
// serving state changes. A failed report is logged and never stops the
// gateway serving.
const (
	// statusEvery is the interval until the server names one.
	statusEvery = 30 * time.Second
	// statusSettle is how long after a change the report goes.
	statusSettle = 5 * time.Second
	// statusPoll is how often the serving states are looked at.
	statusPoll = time.Second
	// statusTimeout bounds one report.
	statusTimeout = 10 * time.Second
)

// StatusReporter sends one status report and returns the seconds until
// the next one (GatewayService.ReportStatus).
type StatusReporter func(ctx context.Context, r *pb.ReportStatusRequest) (int32, error)

var servingStates = map[string]pb.ConnectionServingState{
	dispatch.ServingOK:               pb.ConnectionServingState_CONNECTION_SERVING_STATE_SERVING,
	dispatch.ServingCircuitOpen:      pb.ConnectionServingState_CONNECTION_SERVING_STATE_CIRCUIT_OPEN,
	dispatch.ServingDriftQuarantined: pb.ConnectionServingState_CONNECTION_SERVING_STATE_DRIFT_QUARANTINED,
	dispatch.ServingNotLoaded:        pb.ConnectionServingState_CONNECTION_SERVING_STATE_NOT_LOADED,
}

// status is this process's replica identity and its connections' drift
// check times.
type status struct {
	replica string
	started time.Time
	report  StatusReporter

	mu      sync.Mutex
	checked map[string]time.Time
}

func newStatus(report StatusReporter) *status {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return &status{
		replica: base64.RawURLEncoding.EncodeToString(raw[:]), started: time.Now(), report: report, checked: map[string]time.Time{},
	}
}

// driftChecked records that a connection's upstream tools were checked.
func (s *status) driftChecked(connection string, at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checked[connection] = at
}

// states is each served connection's serving state, by id.
func (g *Gateway) servingStates() map[string]string {
	cfg := g.config.Current()
	if cfg == nil {
		return nil
	}
	out := make(map[string]string, len(cfg.ByID))
	for id, conn := range cfg.ByID {
		out[id] = g.engine.ServingState(conn)
	}
	return out
}

func (g *Gateway) statusRequest(states map[string]string) *pb.ReportStatusRequest {
	v := version.Get()
	req := &pb.ReportStatusRequest{
		ReplicaId: g.status.replica, Version: truncate(v.Version, 64), Build: truncate(v.Commit, 64),
		StartTime: timestamppb.New(g.status.started), ConfigVersion: g.ConfigVersion(),
	}
	g.status.mu.Lock()
	defer g.status.mu.Unlock()
	for _, id := range slices.Sorted(maps.Keys(states)) {
		if len(req.Connections) == 1000 {
			break
		}
		c := &pb.ConnectionStatus{ConnectionId: id, State: servingStates[states[id]]}
		if at, ok := g.status.checked[id]; ok {
			c.LastDriftCheckTime = timestamppb.New(at)
		}
		req.Connections = append(req.Connections, c)
	}
	return req
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// watchStatus reports the replica's status until ctx ends.
func (g *Gateway) watchStatus(ctx context.Context) error {
	if g.status == nil || g.status.report == nil {
		return nil
	}
	every := statusEvery
	var last map[string]string
	next := time.Now() // report on start
	tick := time.NewTicker(statusPoll)
	defer tick.Stop()
	for {
		now := time.Now()
		states := g.servingStates()
		if !maps.Equal(states, last) {
			// A serving state changed (or the first configuration
			// loaded): report soon, not later than due.
			if soon := now.Add(statusSettle); soon.Before(next) {
				next = soon
			}
		}
		if !now.Before(next) {
			last = states
			if s := g.reportStatus(ctx, states); s > 0 {
				every = time.Duration(s) * time.Second
			}
			next = time.Now().Add(every)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// reportStatus sends one report; a failure is logged.
func (g *Gateway) reportStatus(ctx context.Context, states map[string]string) int32 {
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	next, err := g.status.report(ctx, g.statusRequest(states))
	if err != nil {
		g.log.WarnContext(ctx, "gateway.status_not_reported", pclog.Err(err))
		return 0
	}
	g.log.DebugContext(ctx, "gateway.status_reported", slog.String("replica_id", g.status.replica))
	return next
}
