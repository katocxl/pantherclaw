// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/durationpb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordCoverage struct {
	pantherclawv1connect.UnimplementedCoverageServiceHandler
	list    *pantherclawv1.ListCoverageRequest
	exclude *pantherclawv1.CreateExclusionRequest
}

func (r *recordCoverage) ListCoverage(_ context.Context, req *pantherclawv1.ListCoverageRequest) (*pantherclawv1.ListCoverageResponse, error) {
	r.list = req
	return &pantherclawv1.ListCoverageResponse{}, nil
}

func (r *recordCoverage) GetCoverage(_ context.Context, req *pantherclawv1.GetCoverageRequest) (*pantherclawv1.GetCoverageResponse, error) {
	return &pantherclawv1.GetCoverageResponse{Record: &pantherclawv1.CoverageRecord{
		Scope: req.GetScope(), State: pantherclawv1.CoverageState_COVERAGE_STATE_PARTIAL,
		ComputedState: pantherclawv1.CoverageState_COVERAGE_STATE_ENFORCED,
		Reasons:       []string{"invalidated:credential", "route_not_closed:git_ssh"},
		Routes: []*pantherclawv1.CoverageRoute{
			{Kind: pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_CHANNEL, Channel: "http", Status: pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_MEDIATED},
			{Kind: pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_GIT_SSH, Status: pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_NOT_OBSERVED},
		},
		LastValid: &pantherclawv1.CoverageLastValid{SnapshotId: "s1", LapseReason: "invalidated:credential"},
	}}, nil
}

func (r *recordCoverage) GetFreshnessContract(context.Context, *pantherclawv1.GetFreshnessContractRequest) (*pantherclawv1.GetFreshnessContractResponse, error) {
	return &pantherclawv1.GetFreshnessContractResponse{
		EnforcedTtl: durationpb.New(24 * time.Hour), InvalidationKinds: []string{"connection", "credential"},
		StaleState: pantherclawv1.CoverageState_COVERAGE_STATE_PARTIAL,
	}, nil
}

func (r *recordCoverage) CreateExclusion(_ context.Context, req *pantherclawv1.CreateExclusionRequest) (*pantherclawv1.CreateExclusionResponse, error) {
	r.exclude = req
	return &pantherclawv1.CreateExclusionResponse{}, nil
}

func TestCoverageCommands(t *testing.T) {
	rc := &recordCoverage{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterCoverageServiceHandler(cs, rc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const agent, conn = "0192aaaa-bbbb-7ccc-8ddd-000000000001", "0192aaaa-bbbb-7ccc-8ddd-000000000002"
	if code, _, errs := run(t, env, "coverage", "list", "--connection", conn); code != 0 || rc.list.GetConnectionId() != conn {
		t.Fatalf("list: %d %s", code, errs)
	}
	code, out, errs := run(t, env, "coverage", "explain", agent, conn, "github.pulls.merge")
	if code != 0 {
		t.Fatalf("explain: %d %s", code, errs)
	}
	for _, want := range []string{
		"PARTIAL  " + agent, "computed ENFORCED; reads PARTIAL now", "a change since the evidence invalidated it (credential)",
		"the git_ssh route is not proven closed", "git_ssh", "not_observed", "Last valid record: snapshot s1",
		"ENFORCED holds for 24h0m0s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain lacks %q:\n%s", want, out)
		}
	}
	if code, _, _ := run(t, env, "coverage", "exclude", conn, "--reason", "short", "--expires-in-days", "30"); code == 0 || rc.exclude != nil {
		t.Fatal("an exclusion without a written reason was sent")
	}
	if code, _, _ := run(t, env, "coverage", "exclude", conn, "--reason", "No browser in the build container.", "--expires-in-days", "30",
		"--route", "channel"); code == 0 || rc.exclude != nil {
		t.Fatal("a channel exclusion was sent")
	}
	if code, _, errs := run(t, env, "coverage", "exclude", conn, "--reason", "No browser in the build container.",
		"--expires-in-days", "30", "--route", "browser"); code != 0 ||
		rc.exclude.GetRouteKind() != pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_BROWSER {
		t.Fatalf("exclude: %d %s %+v", code, errs, rc.exclude)
	}
}
