// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"

	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

type fakeThreatMap struct {
	pantherclawv1connect.UnimplementedThreatMapServiceHandler
	matrix    *pb.GetThreatMatrixRequest
	technique *pb.GetThreatTechniqueRequest
	gaps      []*pb.ListThreatGapsRequest
	history   *pb.GetThreatMapHistoryRequest
	deny      bool
}

func (f *fakeThreatMap) GetThreatMatrix(_ context.Context, req *pb.GetThreatMatrixRequest) (*pb.GetThreatMatrixResponse, error) {
	f.matrix = req
	if f.deny {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			"Reading the threat map with an API key or access token needs Team or higher; the console shows it on every edition.")
	}
	return &pb.GetThreatMatrixResponse{
		Framework: req.GetFramework(), CatalogVersion: "2026.10", Statement: domain.Statement,
		EvaluatedAt:  timestamppb.New(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)),
		OrgWideLanes: []pb.ThreatLane{pb.ThreatLane_THREAT_LANE_DETECT},
		Tactics:      []*pb.ThreatTactic{{TacticId: "AML.TA0004", Name: "Initial Access", Evidenced: 1, Gap: 2}},
		Techniques: []*pb.ThreatTechniqueCell{{
			TechniqueId: "AML.T0051", Name: "LLM Prompt Injection", Status: pb.ThreatStatus_THREAT_STATUS_GAP,
			Prevent: pb.ThreatLaneState_THREAT_LANE_STATE_GAP, Detect: pb.ThreatLaneState_THREAT_LANE_STATE_EVIDENCED,
			Respond: pb.ThreatLaneState_THREAT_LANE_STATE_NONE_SHIPPED, Test: pb.ThreatTestState_THREAT_TEST_STATE_NOT_RUN,
		}},
	}, nil
}

func (f *fakeThreatMap) GetThreatTechnique(_ context.Context, req *pb.GetThreatTechniqueRequest) (*pb.GetThreatTechniqueResponse, error) {
	f.technique = req
	return &pb.GetThreatTechniqueResponse{Statement: domain.Statement, Technique: &pb.ThreatTechniqueDetail{
		Cell:   &pb.ThreatTechniqueCell{TechniqueId: req.GetTechniqueId(), Name: "Valid Accounts", Status: pb.ThreatStatus_THREAT_STATUS_PARTIAL},
		Detect: &pb.ThreatDetectLane{State: pb.ThreatLaneState_THREAT_LANE_STATE_PARTIAL, Reasons: []string{"RULE_SILENT"}},
		Gaps:   []*pb.ThreatGap{{Lane: pb.ThreatLane_THREAT_LANE_DETECT, TechniqueId: req.GetTechniqueId(), Label: "Send events", Command: "pclaw rules enable r1"}},
		Seen:   &pb.ThreatSeen{AlertsRaised: 3, Refusals: 2, Holds: 1, WindowDays: 30},
	}}, nil
}

func (f *fakeThreatMap) ListThreatGaps(_ context.Context, req *pb.ListThreatGapsRequest) (*pb.ListThreatGapsResponse, error) {
	f.gaps = append(f.gaps, req)
	if req.GetPageToken() == "" {
		return &pb.ListThreatGapsResponse{NextPageToken: "Mg", Gaps: []*pb.ThreatGap{{
			Lane: pb.ThreatLane_THREAT_LANE_DETECT, TechniqueId: "AML.T0051", FixKind: pb.ThreatFixKind_THREAT_FIX_KIND_ENABLE_RULE,
			TargetId: "r1", Label: "Turn rule r1 back on",
		}}}, nil
	}
	return &pb.ListThreatGapsResponse{Gaps: []*pb.ThreatGap{{
		Lane: pb.ThreatLane_THREAT_LANE_TEST, TechniqueId: "AML.T0054", FixKind: pb.ThreatFixKind_THREAT_FIX_KIND_RUN_SCENARIO,
		TargetId: "s9", Label: "Run scenario s9",
	}, {
		// No fix the organization can apply (D720c).
		Lane: pb.ThreatLane_THREAT_LANE_PREVENT, TechniqueId: "AML.T0002", Reason: "SUBTECHNIQUES_ONLY", Label: "covers 1 of 2 sub-techniques",
	}}}, nil
}

func (f *fakeThreatMap) ExportNavigatorLayer(_ context.Context, req *pb.ExportNavigatorLayerRequest) (*pb.ExportNavigatorLayerResponse, error) {
	if req.GetFramework() == pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "MITRE publishes no Navigator layer format for this ATLAS catalog")
	}
	return &pb.ExportNavigatorLayerResponse{LayerJson: []byte(`{"name":"x"}`), FileName: "pantherclaw-threat-map-attack-enterprise-20261104.json"}, nil
}

func (f *fakeThreatMap) GetThreatMapHistory(_ context.Context, req *pb.GetThreatMapHistoryRequest) (*pb.GetThreatMapHistoryResponse, error) {
	f.history = req
	return &pb.GetThreatMapHistoryResponse{
		Days:  []*pb.ThreatHistoryDay{{Day: "2026-11-03", Evidenced: 4, Gap: 1}},
		Drops: []*pb.ThreatDrop{{Day: "2026-11-03", TechniqueId: "T1078", Lane: pb.ThreatLane_THREAT_LANE_DETECT, From: "EVIDENCED", To: "GAP"}},
	}, nil
}

// TestThreatsCommands: `pclaw threats` sends the framework and filter it is
// given, ends every text output with the Statement, prints the API's JSON
// with --json, follows the gap pages, writes the Navigator layer to a new
// file, and prints a server error's message as is (G0 M28 D720, FQ1).
// Covers: F969, F970
func TestThreatsCommands(t *testing.T) {
	f := &fakeThreatMap{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterThreatMapServiceHandler(cs, f)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const envID = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	ends := func(out string) bool { return strings.HasSuffix(out, domain.Statement+"\n") }

	code, out, errs := run(t, env, "threats", "matrix", "--environment", envID)
	if code != 0 || f.matrix.GetFramework() != pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS || f.matrix.GetEnvironmentId() != envID ||
		!strings.Contains(out, "Initial Access") || !strings.Contains(out, "GAP (1)") ||
		!strings.Contains(out, "AML.T0051") || !strings.Contains(out, "Org-wide lanes (the filter does not apply): DETECT") || !ends(out) {
		t.Fatalf("matrix = %d %q %q", code, out, errs)
	}
	code, out, _ = run(t, env, "threats", "matrix", "--framework", "attack", "--json")
	if code != 0 || f.matrix.GetFramework() != pb.ThreatFramework_THREAT_FRAMEWORK_ATTACK_ENTERPRISE || !strings.Contains(out, `"statement"`) {
		t.Fatalf("matrix --json = %d %q", code, out)
	}
	if code, _, errs := run(t, env, "threats", "matrix", "--agent", envID, "--environment", envID); code != 2 {
		t.Fatalf("both filters = %d %q", code, errs)
	}
	if code, _, errs := run(t, env, "threats", "matrix", "--framework", "capec"); code == 0 || !strings.Contains(errs, "--framework") {
		t.Fatalf("unknown framework = %d %q", code, errs)
	}

	code, out, _ = run(t, env, "threats", "technique", "T1078")
	if code != 0 || f.technique.GetFramework() != pb.ThreatFramework_THREAT_FRAMEWORK_ATTACK_ENTERPRISE || f.technique.GetTechniqueId() != "T1078" ||
		!strings.Contains(out, "T1078 Valid Accounts: PARTIAL") || !strings.Contains(out, "RULE_SILENT") ||
		!strings.Contains(out, "fix: pclaw rules enable r1") ||
		!strings.Contains(out, "Seen in 30 days: 3 alerts raised, 2 refusals by mapped controls, 1 holds by mapped controls") || !ends(out) {
		t.Fatalf("technique = %d %q", code, out)
	}
	if code, _, _ := run(t, env, "threats", "technique", "AML.T0051"); code != 0 || f.technique.GetFramework() != pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS {
		t.Fatalf("ATLAS technique = %d %v", code, f.technique)
	}

	code, out, _ = run(t, env, "threats", "gaps")
	if code != 0 || len(f.gaps) != 2 || f.gaps[1].GetPageToken() != "Mg" || !strings.Contains(out, "ENABLE_RULE r1") ||
		!strings.Contains(out, "RUN_SCENARIO s9") || !strings.Contains(out, "covers 1 of 2 sub-techniques") ||
		strings.Contains(out, "UNSPECIFIED") || strings.Contains(out, "NO FIX") || !ends(out) {
		t.Fatalf("gaps = %d %q (%d pages)", code, out, len(f.gaps))
	}

	dir := t.TempDir()
	layer := filepath.Join(dir, "layer.json")
	code, out, errs = run(t, env, "threats", "export", "navigator", "--framework", "attack", "--out", layer)
	if b, err := os.ReadFile(layer); code != 0 || err != nil || string(b) != `{"name":"x"}` || !ends(out) {
		t.Fatalf("export navigator = %d %q %q (%v)", code, out, errs, err)
	}
	if code, _, _ := run(t, env, "threats", "export", "navigator", "--framework", "attack", "--out", layer); code == 0 {
		t.Fatal("export navigator overwrote a file")
	}
	code, _, errs = run(t, env, "threats", "export", "navigator", "--framework", "atlas", "--out", filepath.Join(dir, "atlas.json"))
	if code == 0 || !strings.Contains(errs, "MITRE publishes no Navigator layer format for this ATLAS catalog") {
		t.Fatalf("ATLAS navigator = %d %q", code, errs)
	}

	code, out, _ = run(t, env, "threats", "history", "--framework", "attack", "--days", "7")
	if code != 0 || f.history.GetDays() != 7 || !strings.Contains(out, "2026-11-03 T1078 DETECT: EVIDENCED -> GAP") || !ends(out) {
		t.Fatalf("history = %d %q", code, out)
	}

	f.deny = true
	code, _, errs = run(t, env, "threats", "matrix")
	if code == 0 || !strings.Contains(errs, "Reading the threat map with an API key or access token needs Team or higher; the console shows it on every edition.") {
		t.Fatalf("edition error = %d %q", code, errs)
	}
}
