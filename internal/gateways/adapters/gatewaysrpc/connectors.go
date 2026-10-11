// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"
	"encoding/json/v2"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// connectorOf is a connector's spec as its gateway receives it (G0 M9
// track C).
func connectorOf(s dbq.PcConnectorSpec) *pantherclawv1.ConnectorSpec {
	out := &pantherclawv1.ConnectorSpec{
		Image: s.Image, Command: s.Command, CredentialPlaceholders: s.CredentialPlaceholders, Revision: s.Revision,
		Limits: &pantherclawv1.ConnectorLimits{MemoryMib: s.MemoryMib, MilliCpus: s.MilliCpus, Pids: s.Pids},
	}
	_ = json.Unmarshal(s.Environment, &out.Environment)
	if s.EgressConnectionID != nil {
		out.EgressConnectionId = s.EgressConnectionID.String()
	}
	return out
}

// hosting is who runs a gateway, from the server's configuration alone.
func hosting(pantherclaw bool) pantherclawv1.GatewayHosting {
	if pantherclaw {
		return pantherclawv1.GatewayHosting_GATEWAY_HOSTING_PANTHERCLAW
	}
	return pantherclawv1.GatewayHosting_GATEWAY_HOSTING_CUSTOMER
}

var connectorStates = map[pantherclawv1.ConnectorState]string{
	pantherclawv1.ConnectorState_CONNECTOR_STATE_STARTING: "STARTING", pantherclawv1.ConnectorState_CONNECTOR_STATE_RUNNING: "RUNNING",
	pantherclawv1.ConnectorState_CONNECTOR_STATE_STOPPED: "STOPPED", pantherclawv1.ConnectorState_CONNECTOR_STATE_FAILED: "FAILED",
}

// ReportConnectorState implements GatewayServiceHandler, on the mTLS
// listener only (gateway.observe): a run of one of the calling gateway's
// connectors (G0 M9 track C). The org and gateway come from the
// certificate alone.
func (h *GatewayHandler) ReportConnectorState(ctx context.Context, req *pantherclawv1.ReportConnectorStateRequest,
) (*pantherclawv1.ReportConnectorStateResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	instance, err1 := ids.ParseUUID(req.GetInstanceId())
	conn, err2 := ids.ParseUUID(req.GetConnectionId())
	if err1 != nil || err2 != nil {
		return nil, errInvalidID
	}
	if _, err := h.s.ReportConnectorState(ctx, id, gwapp.ConnectorRun{
		Instance: instance, Connection: conn, SpecRevision: req.GetSpecRevision(), State: connectorStates[req.GetState()],
		Container: req.GetContainerName(), EngineVersion: req.GetEngineVersion(), APIVersion: req.GetApiVersion(),
		Runtime: req.GetRuntime(), ErrorClass: req.GetErrorClass(),
	}); err != nil {
		return nil, err
	}
	return &pantherclawv1.ReportConnectorStateResponse{}, nil
}
