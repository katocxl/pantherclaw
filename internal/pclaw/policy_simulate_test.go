// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordSimulations struct {
	pantherclawv1connect.UnimplementedPolicySimulationServiceHandler
	simulate *pantherclawv1.SimulatePolicyVersionRequest
	samples  *pantherclawv1.ListSimulationSamplesRequest
	gets     int
}

func (r *recordSimulations) SimulatePolicyVersion(_ context.Context, req *pantherclawv1.SimulatePolicyVersionRequest) (
	*pantherclawv1.SimulatePolicyVersionResponse, error,
) {
	r.simulate = req
	return &pantherclawv1.SimulatePolicyVersionResponse{Simulation: &pantherclawv1.PolicySimulation{
		Id: "sim-1", State: pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_QUEUED,
	}}, nil
}

func (r *recordSimulations) GetSimulation(context.Context, *pantherclawv1.GetSimulationRequest) (*pantherclawv1.GetSimulationResponse, error) {
	r.gets++
	s := &pantherclawv1.PolicySimulation{Id: "sim-1", State: pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_RUNNING}
	if r.gets >= 2 {
		s.State, s.Evaluated, s.Limits = pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_DONE, 12, "predicts decisions"
		s.Counts = &pantherclawv1.PolicySimulationCounts{NewlyAllowed: 3}
		s.Notices = []string{"expanded exposure: 3"}
	}
	return &pantherclawv1.GetSimulationResponse{Simulation: s}, nil
}

func (r *recordSimulations) ListSimulationSamples(_ context.Context, req *pantherclawv1.ListSimulationSamplesRequest) (
	*pantherclawv1.ListSimulationSamplesResponse, error,
) {
	r.samples = req
	return &pantherclawv1.ListSimulationSamplesResponse{}, nil
}

// TestPolicySimulateCommands: simulate sends the version and bounds, and
// --wait polls until the report is done and prints it with its limits and
// notices; samples filter by category, and an unknown one is refused
// before anything is sent.
func TestPolicySimulateCommands(t *testing.T) {
	defer func(d time.Duration) { simulationPoll = d }(simulationPoll)
	simulationPoll = time.Millisecond
	rs := &recordSimulations{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterPolicySimulationServiceHandler(cs, rs)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const v = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	code, out, errs := run(t, env, "policy", "simulate", v, "--days", "14", "--max", "500", "--wait")
	if code != 0 || rs.simulate.GetVersionId() != v || rs.simulate.GetDays() != 14 || rs.simulate.GetMaxEvaluations() != 500 || rs.gets != 2 {
		t.Fatalf("simulate --wait: %d %s %+v %d", code, errs, rs.simulate, rs.gets)
	}
	if !regexp.MustCompile(`"newlyAllowed":\s*3`).MatchString(out) {
		t.Errorf("report lacks the newly allowed count:\n%s", out)
	}
	for _, want := range []string{"POLICY_SIMULATION_STATE_DONE", "expanded exposure", "predicts decisions"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if code, _, _ := run(t, env, "policy", "simulate", v, "--days", "31"); code == 0 {
		t.Fatal("a 31-day window was accepted")
	}
	if code, _, errs := run(t, env, "simulation", "samples", "sim-1", "--category", "newly_allowed"); code != 0 ||
		rs.samples.GetCategory() != pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_ALLOWED {
		t.Fatalf("samples: %d %s", code, errs)
	}
	rs.samples = nil
	if code, _, _ := run(t, env, "simulation", "samples", "sim-1", "--category", "worse"); code == 0 || rs.samples != nil {
		t.Fatal("an unknown category was sent")
	}
}
