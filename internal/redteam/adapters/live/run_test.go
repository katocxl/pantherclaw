// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package live_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/redteam/adapters/live"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

func TestSetupNeedsTheWorkloadServiceUnlessTestingOnly(t *testing.T) {
	d := live.New(live.Config{Gateway: "http://127.0.0.1:9", Client: http.DefaultClient, Run: "r", Capabilities: map[app.Capability]bool{app.CapGitHub: true}})
	res := run(t, d, "  - {id: a, do: agent.call, with: {face: sdk, connection: github, tool: t}, expect: {outcome: ALLOW}}\n")
	if res.Verdict != domain.VerdictError || !strings.Contains(res.Detail, "WorkloadService") {
		t.Fatalf("a driver with no WorkloadService ran a scenario: %+v", res)
	}
	d = live.New(live.Config{Gateway: "http://127.0.0.1:9", Client: http.DefaultClient, Run: "r", AgentID: "", Workload: nil})
	if res := run(t, d, "  - {id: a, do: agent.call, with: {face: sdk, connection: github, tool: t}, expect: {outcome: ALLOW}}\n"); res.Verdict != domain.VerdictError {
		t.Errorf("%+v", res)
	}
}

type endRunFake struct {
	pantherclawv1connect.UnimplementedWorkloadServiceHandler
	pantherclawv1connect.UnimplementedRunServiceHandler
	endErr error
}

func (f *endRunFake) StartChildRun(context.Context, *pantherclawv1.StartChildRunRequest) (*pantherclawv1.StartChildRunResponse, error) {
	return &pantherclawv1.StartChildRunResponse{Run: &pantherclawv1.Run{Id: childRun}}, nil
}

func (f *endRunFake) EndRun(context.Context, *pantherclawv1.EndRunRequest) (*pantherclawv1.EndRunResponse, error) {
	return nil, f.endErr
}

func TestTeardownNotesOnlyTheCodeOfAnEndRunFailure(t *testing.T) {
	f := &endRunFake{endErr: connect.NewError(connect.CodeInternal, "SECRET-DETAIL from the server")}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterWorkloadServiceHandler(cs, f)
	pantherclawv1connect.RegisterRunServiceHandler(cs, f)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL))
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"decision":"allow"}`)
	}))
	t.Cleanup(gw.Close)
	d := live.New(live.Config{
		Gateway: gw.URL, Client: gw.Client(), Run: "parent", AgentID: "0192aaaa-bbbb-7ccc-8ddd-0000000000a1",
		Workload: pantherclawv1connect.NewWorkloadServiceClient(c), Runs: pantherclawv1connect.NewRunServiceClient(c),
		Capabilities: map[app.Capability]bool{app.CapGitHub: true},
	})
	res := run(t, d, "  - {id: a, do: agent.call, with: {face: sdk, connection: github, tool: t}, expect: {outcome: ALLOW}}\n")
	notes := d.Notes()
	if res.Verdict != domain.VerdictPass || len(notes) != 1 || !strings.Contains(notes[0], "internal") || strings.Contains(notes[0], "SECRET-DETAIL") {
		t.Fatalf("%+v notes=%v", res, notes)
	}
}
