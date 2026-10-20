// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"testing"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// channelStore answers permit channels; nothing else of the store is
// reached on the refused paths.
type channelStore struct {
	finalize.Store
	channels map[ids.UUID]string
}

func (c channelStore) PermitChannel(_ context.Context, _ ids.OrgID, _ string, permit ids.UUID) (string, error) {
	return c.channels[permit], nil
}

// TestM14_GatewayCannotSubmitAuthZENChannel: over the gateway RPC, an
// action on the authzen channel is CANNOT_AUTHORIZE CHANNEL_NOT_ALLOWED
// before the pipeline runs (no transaction, nothing reserved), and a
// gateway can neither begin nor record a permit on that channel: only the
// in-process external decision path decides, commits and records authzen
// actions (G0 M14 D61, D65).
func TestM14_GatewayCannotSubmitAuthZENChannel(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	req := s.Request(s.Run(g.ID, s.Alice), ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "10.00"))
	a := req.Action.Action
	a.Channel = "authzen"
	p, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	authzenPermit, httpPermit := ids.NewV7(), ids.NewV7()
	h := NewHandler(&Service{decider: &finalize.Authority{Store: channelStore{channels: map[ids.UUID]string{
		authzenPermit: "authzen", httpPermit: "http",
	}}}})
	ctx := WithGateway(context.Background(), Gateway{ID: s.Gateway.ID, Org: s.Org})

	res, err := h.Authorize(ctx, &pantherclawv1.AuthorizeRequest{ActionIr: p.Canonical})
	if err != nil || res.GetDecision() != pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE || res.GetPermit() != "" ||
		res.GetTransactionId() != "" || len(res.GetReasons()) != 1 || res.GetReasons()[0].GetCode() != ReasonChannelNotAllowed {
		t.Fatalf("authorize: %v %v", res, err)
	}
	if _, err := h.BeginDispatch(ctx, &pantherclawv1.BeginDispatchRequest{PermitId: authzenPermit.String()}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("begin dispatch: %v", err)
	}
	if _, err := h.RecordExecution(ctx, &pantherclawv1.RecordExecutionRequest{
		PermitId: authzenPermit.String(), Outcome: pantherclawv1.Outcome_OUTCOME_DELEGATED,
	}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("record execution: %v", err)
	}
	if err := h.gatewayPermit(ctx, Gateway{ID: s.Gateway.ID, Org: s.Org}, httpPermit); err != nil {
		t.Fatalf("an http permit: %v", err)
	}
	if out := refusedChannel(req.Action.Canonical); out != nil {
		t.Fatalf("an mcp action was refused: %v", out)
	}
}

// TestM14_GatewayPermitFailsClosedWithoutChannels: a store that cannot say
// a permit's channel lets no gateway begin or record it (D85).
func TestM14_GatewayPermitFailsClosedWithoutChannels(t *testing.T) {
	h := NewHandler(&Service{decider: &finalize.Authority{Store: struct{ finalize.Store }{}}})
	if err := h.gatewayPermit(context.Background(), Gateway{ID: "gw", Org: ids.New[ids.Org]()}, ids.NewV7()); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no PermitChannels: %v", err)
	}
}
