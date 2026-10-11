// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ToolObservations records tool calls an agent SDK ran without a mapping
// (G0 M8, HR-200); the connections service implements it.
type ToolObservations interface {
	RecordToolObservation(ctx context.Context, org ids.OrgID, gateway ids.UUID, o capp.ToolObservation) (ids.UUID, error)
}

// WithToolObservations sets the recorder of tool observations; without one
// RecordToolObservation is unavailable.
func (s *Service) WithToolObservations(o ToolObservations) *Service {
	s.observations = o
	return s
}

// ObserveTool verifies a workload in its run, as Verify does, and records
// the observation for the verified instance (HR-021: the gateway never
// verifies a workload itself, and the instance comes from the Authority).
func (s *Service) ObserveTool(ctx context.Context, gw Gateway, c *Credentials, run, conn ids.UUID, tool string, input []byte) (Verified,
	ids.UUID, error,
) {
	if s.observations == nil {
		return Verified{}, ids.UUID{}, errors.New("authority: tool observations are not configured")
	}
	v, err := s.Verify(ctx, gw, c, run)
	if err != nil {
		return v, ids.UUID{}, err
	}
	gateway, err := ids.ParseUUID(gw.ID)
	if err != nil {
		return v, ids.UUID{}, err
	}
	id, err := s.observations.RecordToolObservation(ctx, gw.Org, gateway, capp.ToolObservation{
		Run: run, Instance: v.Instance, Connection: conn, Tool: tool, InputSHA256: input,
	})
	return v, id, err
}

// RecordToolObservation implements AuthorityServiceHandler: a workload
// that does not verify is an answer, not an error, as for VerifyWorkload,
// and so is a connection this gateway does not serve. A request must name
// its run: the nil UUID would name none and skip its binding (HR-022).
func (h *Handler) RecordToolObservation(ctx context.Context, req *pantherclawv1.RecordToolObservationRequest) (*pantherclawv1.RecordToolObservationResponse,
	error,
) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	run, err := ids.ParseUUID(req.GetRunId())
	if err != nil || run.IsZero() {
		return nil, connect.NewError(connect.CodeInvalidArgument, "run_id must name a run")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "connection_id must be a UUID")
	}
	out := &pantherclawv1.RecordToolObservationResponse{}
	v, id, err := h.svc.ObserveTool(ctx, gw, credentials(req.GetWorkload()), run, conn, req.GetTool(), req.GetInputSha256())
	var pe *pap.Error
	switch {
	case errors.As(err, &pe):
		out.ErrorCode = string(pe.Code)
	case errors.Is(err, ErrAgentUnusable):
		out.ErrorCode = "agent_unusable"
	case errors.Is(err, capp.ErrNotServed):
		// The gateway's configuration is stale: nothing is recorded.
		out.ErrorCode = "connection_not_served"
	case err != nil:
		return nil, err
	default:
		out.Verified, out.InstanceId, out.ObservationId = true, v.Instance.String(), id.String()
	}
	out.Nonce = h.svc.nonce(ctx, gw)
	return out, nil
}
