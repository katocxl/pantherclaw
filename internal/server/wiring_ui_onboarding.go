// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/onboarding"
)

// Onboarding progress (G0 UI D15; HR-362..364): computed from the org's
// records, never from client flags.

// onboardingService serves OnboardingService.
type onboardingService struct {
	pantherclawv1connect.UnimplementedOnboardingServiceHandler
	svc *onboarding.Service
}

// registerUIOnboarding serves OnboardingService.
func registerUIOnboarding(rs *connect.Server, d apiDeps) {
	s := onboardingService{}
	if d.ui != nil {
		s.svc = d.ui.onboarding
	}
	pantherclawv1connect.RegisterOnboardingServiceHandler(rs, s)
}

var stepProto = map[onboarding.StepID]pantherclawv1.StepId{
	onboarding.StepSecurityKey:      pantherclawv1.StepId_STEP_ID_SECURITY_KEY,
	onboarding.StepInviteTeam:       pantherclawv1.StepId_STEP_ID_INVITE_TEAM,
	onboarding.StepGatewayEnrolled:  pantherclawv1.StepId_STEP_ID_GATEWAY_ENROLLED,
	onboarding.StepAgentEnrolled:    pantherclawv1.StepId_STEP_ID_AGENT_ENROLLED,
	onboarding.StepFirstDecision:    pantherclawv1.StepId_STEP_ID_FIRST_DECISION,
	onboarding.StepTestAllowed:      pantherclawv1.StepId_STEP_ID_TEST_ALLOWED,
	onboarding.StepTestHeld:         pantherclawv1.StepId_STEP_ID_TEST_HELD,
	onboarding.StepTestDenied:       pantherclawv1.StepId_STEP_ID_TEST_DENIED,
	onboarding.StepApprovalDecided:  pantherclawv1.StepId_STEP_ID_APPROVAL_DECIDED,
	onboarding.StepSuspensionTested: pantherclawv1.StepId_STEP_ID_SUSPENSION_TESTED,
}

// GetProgress implements OnboardingServiceHandler.
func (s onboardingService) GetProgress(ctx context.Context, _ *pantherclawv1.GetProgressRequest) (*pantherclawv1.GetProgressResponse, error) {
	if s.svc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "onboarding is not served")
	}
	p, err := s.svc.GetProgress(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetProgressResponse{Complete: p.Complete}
	for _, st := range p.Steps {
		step := &pantherclawv1.OnboardingStep{Id: stepProto[st.ID], State: pantherclawv1.StepState_STEP_STATE_TODO}
		if st.Done() {
			step.State, step.DoneAt = pantherclawv1.StepState_STEP_STATE_DONE, timestamppb.New(*st.DoneAt)
			for _, e := range st.Evidence {
				step.Evidence = append(step.Evidence, &pantherclawv1.EvidenceRef{Kind: e.Kind, Id: e.ID.String()})
			}
		}
		out.Steps = append(out.Steps, step)
	}
	return out, nil
}
