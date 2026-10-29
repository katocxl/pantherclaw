// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
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

// TestHR410_AVersionIsCutOnARuneBoundary: a long non-ASCII version or
// build is cut to 64 bytes and stays valid UTF-8, so the report still
// marshals (G0 M15 D42).
func TestHR410_AVersionIsCutOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("é", 40) // 80 bytes
	got := truncate(long)
	if len(got) > 64 || !utf8.ValidString(got) || got != strings.Repeat("é", 32) {
		t.Fatalf("truncate = %q (%d bytes)", got, len(got))
	}
	if got := truncate("x" + strings.Repeat("é", 40)); len(got) != 63 || !utf8.ValidString(got) {
		t.Fatalf("an odd cut = %q (%d bytes)", got, len(got))
	}
}

// TestHR411_AGatewayWithoutABrokerKeyWarnsThatTasksAreNotShared: a
// gateway that serves a kind-mcp connection without a broker key logs at
// start that its MCP tasks stay in its own process (G0 M15 D42); one with
// no kind-mcp connection says nothing.
func TestHR411_AGatewayWithoutABrokerKeyWarnsThatTasksAreNotShared(t *testing.T) {
	for kind, want := range map[string]bool{"mcp": true, "http": false} {
		var logs bytes.Buffer
		g := &Gateway{
			config: newFakeConfig(&control.Connection{GatewayConnection: &pb.GatewayConnection{Id: connID, Name: "c", Kind: kind}}),
			log:    slog.New(slog.NewTextHandler(&logs, nil)),
		}
		if err := g.warnUnsharedTasks(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(logs.String(), "gateway.mcp_tasks_not_shared"); got != want {
			t.Errorf("%s connection: warned %v, want %v: %s", kind, got, want, logs.String())
		}
	}
}
