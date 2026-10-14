// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package live_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/redteam/adapters/live"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

const (
	rangeAgent = "0192aaaa-bbbb-7ccc-8ddd-0000000000a1"
	rangeInst  = "0192aaaa-bbbb-7ccc-8ddd-0000000000d1"
	rangeGrant = "0192aaaa-bbbb-7ccc-8ddd-0000000000a9"
)

func TestSetupNeedsItsRunServiceUnlessTestingOnly(t *testing.T) {
	cfg := live.Config{Gateway: "http://127.0.0.1:9", Client: &http.Client{}, Run: "r", Capabilities: map[app.Capability]bool{app.CapGitHub: true}}
	step := "  - {id: a, do: agent.call, with: {face: sdk, connection: github, tool: t}, expect: {outcome: ALLOW}}\n"
	if res := run(t, live.New(cfg), step); res.Verdict != domain.VerdictError || !strings.Contains(res.Detail, "RunService") {
		t.Fatalf("a driver with no RunService ran a scenario: %+v", res)
	}
	cfg.AgentID, cfg.InstanceID = rangeAgent, rangeInst // no grant
	if res := run(t, live.New(cfg), step); res.Verdict != domain.VerdictError {
		t.Errorf("a driver with no grant ran a scenario: %+v", res)
	}
}

// runsFake is the RunService of a range: it starts and ends root runs.
type runsFake struct {
	pantherclawv1connect.UnimplementedRunServiceHandler
	mu      sync.Mutex
	started []*pantherclawv1.StartRunRequest
	ended   []string
	endErr  error
	startEr error
}

func (f *runsFake) StartRun(_ context.Context, r *pantherclawv1.StartRunRequest) (*pantherclawv1.StartRunResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startEr != nil {
		return nil, f.startEr
	}
	f.started = append(f.started, r)
	return &pantherclawv1.StartRunResponse{Run: &pantherclawv1.Run{Id: fmt.Sprintf("0192aaaa-bbbb-7ccc-8ddd-%012d", len(f.started))}}, nil
}

func (f *runsFake) EndRun(_ context.Context, r *pantherclawv1.EndRunRequest) (*pantherclawv1.EndRunResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.endErr != nil {
		return nil, f.endErr
	}
	f.ended = append(f.ended, r.GetId())
	return &pantherclawv1.EndRunResponse{}, nil
}

// rangeDriver is a driver with a RunService and a gateway that caps holds at
// five per run (HR-037).
func rangeDriver(t *testing.T, f *runsFake, holds map[string]int) *live.Driver {
	t.Helper()
	cs := connect.NewServer()
	pantherclawv1connect.RegisterRunServiceHandler(cs, f)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		holds[r.Header.Get("PAP-Run-Id")]++
		over := holds[r.Header.Get("PAP-Run-Id")] > 5
		mu.Unlock()
		if over {
			_, _ = io.WriteString(w, `{"decision":"deny","error_class":"cannot_authorize","code":"HOLD_LIMIT_REACHED","reasons":["HOLD_LIMIT_REACHED"]}`)
			return
		}
		_, _ = io.WriteString(w, `{"decision":"hold","error_class":"held","code":"REQUIRE_APPROVAL","transaction_id":"t-1"}`)
	}))
	t.Cleanup(gw.Close)
	return live.New(live.Config{
		Gateway: gw.URL, Client: gw.Client(), Run: "instance-run", AgentID: rangeAgent, InstanceID: rangeInst, GrantID: rangeGrant,
		Runs:         pantherclawv1connect.NewRunServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL))),
		Capabilities: map[app.Capability]bool{app.CapGitHub: true},
	})
}

func TestEachScenarioRunsInARootRunOfItsOwn(t *testing.T) {
	f := &runsFake{}
	holds := map[string]int{}
	d := rangeDriver(t, f, holds)
	for i := 0; i < 8; i++ {
		res := run(t, d, "  - {id: a, do: agent.call, with: {face: sdk, connection: github, tool: t}, expect: {outcome: HOLD}}\n")
		if res.Verdict != domain.VerdictPass {
			t.Fatalf("scenario %d: %+v", i, res)
		}
	}
	if len(f.started) != 8 || len(f.ended) != 8 {
		t.Fatalf("runs started %d ended %d", len(f.started), len(f.ended))
	}
	for _, r := range f.started {
		if r.GetAgentId() != rangeAgent || r.GetInstanceId() != rangeInst || r.GetGrantId() != rangeGrant || r.GetTtlMinutes() != 5 || !strings.HasPrefix(r.GetTaskRef(), "range ") {
			t.Errorf("run request %v", r)
		}
	}
	if _, onParent := holds["instance-run"]; onParent {
		t.Error("a call was made in the instance's own run")
	}
	for run, n := range holds {
		if n != 1 {
			t.Errorf("run %s saw %d holds", run, n)
		}
	}
	// A run that cannot start makes the scenario an ERROR, not a call on the instance's run.
	f.startEr = connect.NewError(connect.CodePermissionDenied, "run.start is needed")
	if res := run(t, d, "  - {id: a, do: agent.call, with: {face: sdk, connection: github, tool: t}, expect: {outcome: HOLD}}\n"); res.Verdict != domain.VerdictError || !strings.Contains(res.Detail, "starting the scenario's run") {
		t.Errorf("%+v", res)
	}
}

func TestTeardownNotesOnlyTheCodeOfAnEndRunFailure(t *testing.T) {
	f := &runsFake{endErr: connect.NewError(connect.CodeInternal, "SECRET-DETAIL from the server")}
	d := rangeDriver(t, f, map[string]int{})
	res := run(t, d, "  - {id: a, do: agent.call, with: {face: sdk, connection: github, tool: t}, expect: {outcome: HOLD}}\n")
	notes := d.Notes()
	if res.Verdict != domain.VerdictPass || len(notes) != 1 || !strings.Contains(notes[0], "internal") || strings.Contains(notes[0], "SECRET-DETAIL") {
		t.Fatalf("%+v notes=%v", res, notes)
	}
	// A missing run.manage is the expected case and says what to do.
	f.endErr = connect.NewError(connect.CodePermissionDenied, "run.manage is needed")
	run(t, d, "  - {id: a, do: agent.call, with: {face: sdk, connection: github, tool: t}, expect: {outcome: HOLD}}\n")
	if got := strings.Join(d.Notes(), "|"); !strings.Contains(got, "left to expire: ending it needs run.manage") {
		t.Errorf("notes %q", got)
	}
}
