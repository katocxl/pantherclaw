// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ReasonChannelNotAllowed: a gateway asked about an action on the authzen
// channel, which only the in-process external decision path decides
// (G0 M14 D61, D65).
const ReasonChannelNotAllowed = "CHANNEL_NOT_ALLOWED"

// channelAuthZEN is an external enforcement point's channel (D4).
const channelAuthZEN = "authzen"

// PermitChannels reads the channel of a permit's transaction for the
// gateway that holds it, empty for a permit it does not hold (the call
// itself then reports it); the Authority's store implements it.
type PermitChannels interface {
	PermitChannel(ctx context.Context, org ids.OrgID, gateway string, permit ids.UUID) (string, error)
}

// refusedChannel answers a gateway's Authorize of an authzen action:
// CANNOT_AUTHORIZE CHANNEL_NOT_ALLOWED, decided before the pipeline runs,
// so nothing is reserved and no transaction starts. A body that does not
// parse is left to the Service, which refuses it as before.
func refusedChannel(raw []byte) *pantherclawv1.AuthorizeResponse {
	p, err := actionir.Parse(raw)
	if err != nil || p.Action.Channel != channelAuthZEN {
		return nil
	}
	return &pantherclawv1.AuthorizeResponse{
		Decision: pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE,
		Reasons: []*pantherclawv1.Reason{{
			Code: ReasonChannelNotAllowed, Check: "scope", Decisive: true,
			Detail: "an authzen action is decided only for its enforcement point, never for a gateway",
		}},
	}
}

// gatewayPermit refuses a gateway's BeginDispatch or RecordExecution of a
// permit on the authzen channel: the external decision path commits and
// records those itself, in-process (D65).
func (h *Handler) gatewayPermit(ctx context.Context, gw Gateway, permit ids.UUID) error {
	pc, ok := h.svc.decider.Store.(PermitChannels)
	if !ok {
		return nil
	}
	ch, err := pc.PermitChannel(ctx, gw.Org, gw.ID, permit)
	if err != nil {
		return err
	}
	if ch == channelAuthZEN {
		return connect.NewError(connect.CodePermissionDenied, "a gateway cannot dispatch an authzen decision")
	}
	return nil
}
