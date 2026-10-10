// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agentsrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

var errNoRestorations = pcerr.New(pcerr.Unimplemented, "UNIMPLEMENTED", "this server does not serve restorations")

// WithRestorations adds RequestAgentRestoration (G0 M5 part 2).
func (s *Agents) WithRestorations(svc *approvals.Service) *Agents {
	s.restore = svc
	return s
}

// RequestAgentRestoration implements AgentServiceHandler: a person with
// agent.manage asks for a suspended agent to be restored, with a reason;
// an agent.restore holder other than them approves it on the approval page
// with a security key (decision 11).
func (s *Agents) RequestAgentRestoration(ctx context.Context, req *pantherclawv1.RequestAgentRestorationRequest) (*pantherclawv1.RequestAgentRestorationResponse, error) {
	if s.restore == nil {
		return nil, errNoRestorations
	}
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, entry, err := s.restore.RequestRestoration(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestAgentRestorationResponse{
		ApprovalRequestId: r.ID.String(), WaitlistEntryId: entry.String(), DeadlineTime: timestamppb.New(r.DeadlineAt),
	}, nil
}
