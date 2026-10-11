// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

var accessModes = map[string]pantherclawv1.AccessControlMode{
	app.ModeTargetEnforced:     pantherclawv1.AccessControlMode_ACCESS_CONTROL_MODE_TARGET_ENFORCED,
	app.ModeNarrowTemporary:    pantherclawv1.AccessControlMode_ACCESS_CONTROL_MODE_NARROW_TEMPORARY,
	app.ModePantherClawHeld:    pantherclawv1.AccessControlMode_ACCESS_CONTROL_MODE_PANTHERCLAW_HELD,
	app.ModeConstrainedRuntime: pantherclawv1.AccessControlMode_ACCESS_CONTROL_MODE_CONSTRAINED_RUNTIME,
	app.ModeAgentHeld:          pantherclawv1.AccessControlMode_ACCESS_CONTROL_MODE_AGENT_HELD,
}

// GetAccessDisclosure implements CoverageServiceHandler.
func (h *Handler) GetAccessDisclosure(ctx context.Context, req *pantherclawv1.GetAccessDisclosureRequest) (*pantherclawv1.GetAccessDisclosureResponse, error) {
	conn, err := idOf(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	agent, err := optID(req.AgentId)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.GetAccessDisclosure(ctx, conn, agent)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.AccessDisclosure{
		ConnectionId: d.Connection.String(), AgentId: idText(d.Agent), Custodian: d.Custodian,
		CredentialVersion: d.CredentialVersion, CredentialHosts: d.CredentialHosts, Disclosures: d.Disclosures,
	}
	if !d.Gateway.IsZero() {
		out.GatewayId = d.Gateway.String()
	}
	for _, m := range d.Modes {
		out.Modes = append(out.Modes, accessModes[m])
	}
	if c := d.Closure; c != nil {
		out.ClosureId, out.ClosureExpireTime = c.ID.String(), ts(c.ExpiresAt)
	}
	for _, rt := range d.Residual {
		out.ResidualRoutes = append(out.ResidualRoutes, &pantherclawv1.CoverageRoute{
			Id: idText(rt.Route), Kind: kinds[domain.RouteKind(rt.Kind)], Channel: rt.Channel, Locator: rt.Locator,
			Status: statuses[domain.RouteStatus(rt.Status)],
		})
	}
	return &pantherclawv1.GetAccessDisclosureResponse{Disclosure: out}, nil
}
