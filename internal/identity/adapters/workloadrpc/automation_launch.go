// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadrpc

import (
	"context"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/runs/adapters/runsrpc"
)

// LaunchPrefix is the URL path prefix of AutomationLaunchService
// procedures, which RawBody covers like WorkloadService's (PAP/1 proofs
// sign the body).
const LaunchPrefix = "/" + pantherclawv1connect.AutomationLaunchServiceName + "/"

// Launches are the engine's launch use cases (G0 M11 part 2 D26).
type Launches interface {
	ClaimLaunch(ctx context.Context, org ids.OrgID, instance ids.UUID) (pgengine.ClaimedLaunch, bool, error)
	CompleteLaunch(ctx context.Context, org ids.OrgID, instance, launch ids.UUID, outcome string,
		results []pgengine.CallResult, note string) error
}

// AutomationLaunches serves AutomationLaunchService: an enrolled
// instance, authenticated by its PAP/1 token and proof exactly like
// WorkloadService, claims its own agent's launches and reports them
// (HR-285). It never runs a tool (F3).
type AutomationLaunches struct {
	pantherclawv1connect.UnimplementedAutomationLaunchServiceHandler
	w        *Workload
	launches Launches
}

// NewAutomationLaunches serves launches with w's workload authentication.
func NewAutomationLaunches(w *Workload, l Launches) *AutomationLaunches {
	return &AutomationLaunches{w: w, launches: l}
}

// ClaimLaunch implements AutomationLaunchServiceHandler.
func (s *AutomationLaunches) ClaimLaunch(ctx context.Context, _ *pantherclawv1.ClaimLaunchRequest) (*pantherclawv1.ClaimLaunchResponse, error) {
	info, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	org, inst, err := s.w.authenticate(ctx, info)
	if err != nil {
		return nil, err
	}
	l, ok, err := s.launches.ClaimLaunch(ctx, org, inst)
	if err != nil {
		return nil, err
	}
	s.w.setNonce(ctx, info, org)
	if !ok {
		return &pantherclawv1.ClaimLaunchResponse{}, nil
	}
	out := &pantherclawv1.ClaimLaunchResponse{
		Claimed: true, LaunchId: l.ID.String(), RunId: l.Run.String(), TaskRef: l.TaskRef, RunParams: l.RunParams,
		CompleteBy: timestamppb.New(l.CompleteBy.UTC().Truncate(time.Second)),
	}
	for _, c := range l.Calls {
		out.Calls = append(out.Calls, &pantherclawv1.AutomationRunnerCall{
			ConnectionId: c.Connection, ConnectionName: c.ConnectionName, Face: c.Face, Tool: c.Tool, Method: c.Method,
			Path: c.Path, Input: c.Input,
		})
	}
	return out, nil
}

// CompleteLaunch implements AutomationLaunchServiceHandler.
func (s *AutomationLaunches) CompleteLaunch(ctx context.Context, req *pantherclawv1.CompleteLaunchRequest) (*pantherclawv1.CompleteLaunchResponse, error) {
	info, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	org, inst, err := s.w.authenticate(ctx, info)
	if err != nil {
		return nil, err
	}
	launch, err := runsrpc.ParseID(req.GetLaunchId())
	if err != nil {
		return nil, err
	}
	results := make([]pgengine.CallResult, 0, len(req.GetResults()))
	for _, r := range req.GetResults() {
		results = append(results, pgengine.CallResult{
			CallIndex: int(r.GetCallIndex()), Status: r.GetStatus(), Transaction: r.GetTransactionId(), ErrorCode: r.GetErrorCode(),
		})
	}
	outcome := strings.TrimPrefix(req.GetOutcome().String(), "AUTOMATION_LAUNCH_OUTCOME_")
	if err := s.launches.CompleteLaunch(ctx, org, inst, launch, outcome, results, req.GetNote()); err != nil {
		return nil, err
	}
	s.w.setNonce(ctx, info, org)
	return &pantherclawv1.CompleteLaunchResponse{State: pantherclawv1.AutomationLaunchState_AUTOMATION_LAUNCH_STATE_COMPLETED}, nil
}
