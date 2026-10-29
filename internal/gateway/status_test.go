// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"testing"
	"time"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR410_AReplicaReportsItsStatusAndAFailedReportNeverStopsServing: a
// replica reports at start its random id, start time, config version and
// each connection's serving state, with the time of its last drift check;
// a report the server refuses is logged, and the gateway keeps serving
// (G0 M15 D10).
// Covers: PN-010.6
func TestHR410_AReplicaReportsItsStatusAndAFailedReportNeverStopsServing(t *testing.T) {
	h := setup(t)
	var (
		mu      sync.Mutex
		reports []*pb.ReportStatusRequest
	)
	got := make(chan struct{}, 4)
	h.gw.status = newStatus(func(_ context.Context, r *pb.ReportStatusRequest) (int32, error) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, r)
		got <- struct{}{}
		return 0, errors.New("server unavailable")
	})
	checked := time.Now().Add(-time.Minute).Truncate(time.Second)
	h.gw.status.driftChecked(connID, checked)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.gw.watchStatus(ctx) }()
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("no report at start")
	}
	if r := h.post(t, inbound, nil); r.code != http.StatusOK {
		t.Fatalf("a failed report stopped serving: %d %q", r.code, r.body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	r := reports[0]
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`).MatchString(r.GetReplicaId()) || r.GetStartTime() == nil ||
		r.GetConfigVersion() != h.gw.ConfigVersion() || r.GetVersion() == "" {
		t.Fatalf("report %+v", r)
	}
	if len(r.GetConnections()) != 1 || r.GetConnections()[0].GetConnectionId() != connID ||
		r.GetConnections()[0].GetState() != pb.ConnectionServingState_CONNECTION_SERVING_STATE_SERVING ||
		!r.GetConnections()[0].GetLastDriftCheckTime().AsTime().Equal(checked) {
		t.Fatalf("connections %+v", r.GetConnections())
	}
}
