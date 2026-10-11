// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

var levels = map[string]pb.CapabilityLevel{
	capp.Supported: pb.CapabilityLevel_CAPABILITY_LEVEL_SUPPORTED, capp.Partial: pb.CapabilityLevel_CAPABILITY_LEVEL_PARTIAL,
	capp.Unsupported: pb.CapabilityLevel_CAPABILITY_LEVEL_UNSUPPORTED,
}

func supportOf(s capp.Support) *pb.CapabilitySupport {
	return &pb.CapabilitySupport{Level: levels[s.Level], Detail: s.Detail}
}

// GetConnectionCapabilities implements ConnectionServiceHandler.
func (h *Handler) GetConnectionCapabilities(ctx context.Context, req *pb.GetConnectionCapabilitiesRequest) (*pb.GetConnectionCapabilitiesResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	c, err := h.s.Capabilities(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pb.ConnectionCapabilities{
		ConnectionId: id.String(), Discovery: supportOf(c.Discovery), Observation: supportOf(c.Observation),
		Enforcement: supportOf(c.Enforcement), Response: supportOf(c.Response), ResponseActions: c.ResponseActions,
		FailureBehavior: c.Failure,
	}
	for _, o := range c.Operations {
		out.Operations = append(out.Operations, &pb.ConnectionOperation{
			Operation: o.Operation, Summary: o.Summary, Route: o.Route, Access: o.Access, TargetType: o.TargetType,
			Reversibility: o.Reversibility, Verified: o.Verified, Mode: modeOf[o.Mode],
		})
	}
	for _, p := range c.Permissions {
		out.Permissions = append(out.Permissions, &pb.ConnectionPermission{Name: p.Name, Reasons: p.Reasons})
	}
	for _, l := range c.Limits {
		out.Limits = append(out.Limits, &pb.ConnectionLimit{Code: l.Code, Detail: l.Detail})
	}
	if c.LastPassedTest != nil {
		out.LastPassedTest = testOf(*c.LastPassedTest)
	}
	return &pb.GetConnectionCapabilitiesResponse{Capabilities: out}, nil
}

var testResults = map[string]pb.ConnectionTestResult{
	capp.TestPassed: pb.ConnectionTestResult_CONNECTION_TEST_RESULT_PASSED, capp.TestFailed: pb.ConnectionTestResult_CONNECTION_TEST_RESULT_FAILED,
}

func testOf(t capp.TestResult) *pb.ConnectionTest {
	out := &pb.ConnectionTest{
		Id: t.ID.String(), ConnectionId: t.Connection.String(), Result: testResults[t.Result], RequestedBy: t.RequestedBy, Kind: t.Kind,
		State: t.State, CreateTime: timestamppb.New(t.CreatedAt),
	}
	if t.FinishedAt != nil {
		out.FinishTime = timestamppb.New(*t.FinishedAt)
	}
	for _, c := range t.Checks {
		out.Checks = append(out.Checks, &pb.ConnectionTestCheck{Check: c.Check, Passed: c.Passed, Detail: c.Detail})
	}
	return out
}

// TestConnection implements ConnectionServiceHandler.
func (h *Handler) TestConnection(ctx context.Context, req *pb.TestConnectionRequest) (*pb.TestConnectionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := h.s.Test(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.TestConnectionResponse{Test: testOf(t)}, nil
}
