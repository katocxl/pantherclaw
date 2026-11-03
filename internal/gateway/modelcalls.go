// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/modelface"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// controlModelCalls asks the server about each model face call over the
// gateway's mTLS link (G0 M25 D313).
type controlModelCalls struct{ ctl *control.Client }

var _ modelface.Control = controlModelCalls{}

func (c controlModelCalls) Authorize(ctx context.Context, connection, run, host string, bytes int64) (string, error) {
	res, err := c.ctl.Gateway.AuthorizeModelCall(ctx, &pb.AuthorizeModelCallRequest{
		ConnectionId: connection, RunId: run, ModelHost: host, BytesToModel: bytes,
	})
	return res.GetCampaignId(), err
}

func (c controlModelCalls) Report(ctx context.Context, campaign, run string, bytes int64) error {
	_, err := c.ctl.Gateway.ReportModelUsage(ctx, &pb.ReportModelUsageRequest{CampaignId: campaign, RunId: run, BytesFromModel: bytes})
	return err
}
