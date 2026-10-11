// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestIntServeM5p2ServicesRoutesAndJobs: the approval page (with security
// keys on), ApprovalService, the waitlist's metrics, the SSE route of wait
// handles and the waitlist's jobs are wired.
func TestIntServeM5p2ServicesRoutesAndJobs(t *testing.T) {
	d := dbtest.New(t)
	base := serveM5(t, testConfig(t, d, RoleAll, func(m map[string]any) {
		m["auth"] = map[string]any{"public_url": "http://localhost:8080"}
		m["waitlist"] = map[string]any{"max_waits_per_instance": 2, "long_poll_max": "10s"}
	}))
	org := ids.New[ids.Org]()
	if code := statusM5(t, http.MethodGet, base+"/approvals?org="+org.String()); code != http.StatusSeeOther {
		t.Errorf("/approvals = %d, want 303 (sign in)", code)
	}
	if code := statusM5(t, http.MethodGet, base+"/static/approvals.js"); code != http.StatusOK {
		t.Errorf("/static/approvals.js = %d", code)
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	tr := connecthttp.NewTransport(hc, base)
	approvals := pantherclawv1connect.NewApprovalServiceClient(connect.NewClient(tr))
	if _, err := approvals.ListApprovalRequests(context.Background(), &pantherclawv1.ListApprovalRequestsRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("ApprovalService anonymous: %v", err)
	}
	waitlist := pantherclawv1connect.NewWaitlistServiceClient(connect.NewClient(tr))
	if _, err := waitlist.GetWaitlistMetrics(context.Background(), &pantherclawv1.GetWaitlistMetricsRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("WaitlistService anonymous: %v", err)
	}
	if code := statusM5(t, http.MethodGet, base+workloadrpc.WaitPath+ids.NewV7().String()); code != http.StatusUnauthorized {
		t.Errorf("the wait stream without PAP/1 = %d, want 401", code)
	}
	if code := statusM5(t, http.MethodGet, base+workloadrpc.WaitPath+"x"); code != http.StatusNotFound {
		t.Errorf("the wait stream of no transaction = %d, want 404", code)
	}
	// The routing schedule runs its dispatcher, whose per-org jobs are
	// registered.
	deadline := time.Now().Add(40 * time.Second)
	for {
		var n int
		d.AdminQueryRow(t, "SELECT count(*) FROM pc.river_job WHERE kind = 'waitlist.route_dispatch' AND state = 'completed'", nil, &n)
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the routing dispatcher did not complete within 40 s")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
