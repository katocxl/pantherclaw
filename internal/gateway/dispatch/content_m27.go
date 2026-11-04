// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// contentScanKey holds a call's scan marker, for its tool result (record).
type contentScanKey struct{}

// contentScan says what the gateway does with a call's content (G0 M27 D504,
// D507, D533): it scans when the org has content signals on and the gateway
// itself carries the call. Hook, SDK and local connections are not scanned,
// delegated outcomes are not inspected, and they say so where they show.
func contentScan(c Call) pb.ContentScan {
	switch c.Connection.ContentSignals {
	case pb.ContentSignalMode_CONTENT_SIGNAL_MODE_WATCHING, pb.ContentSignalMode_CONTENT_SIGNAL_MODE_ACTIVE:
		if c.Connection.GetKind() == "local" || cooperative(c) || c.Action.Action.Channel == string(defs.ChannelHook) {
			return pb.ContentScan_CONTENT_SCAN_FACE_NOT_SCANNED
		}
		return pb.ContentScan_CONTENT_SCAN_SCANNED
	case pb.ContentSignalMode_CONTENT_SIGNAL_MODE_UNSPECIFIED, pb.ContentSignalMode_CONTENT_SIGNAL_MODE_OFF:
	}
	return pb.ContentScan_CONTENT_SCAN_OFF
}

// outboundContent scans the action's arguments, before the decision, and
// keeps the marker in ctx for the tool result (HR-649). Every Authorize
// carries the marker: in ACTIVE the Authority holds a gateway-carried call
// without SCANNED (D533). The Authority alone decides what a finding means.
func (e *Engine) outboundContent(ctx context.Context, c Call) (context.Context, []*pb.ContentFinding, pb.ContentScan) {
	scan := contentScan(c)
	ctx = context.WithValue(ctx, contentScanKey{}, scan)
	if scan != pb.ContentScan_CONTENT_SCAN_SCANNED {
		return ctx, nil, scan
	}
	found := e.content.Scan(context.WithoutCancel(ctx), ports.SurfaceOutbound, "arg", c.Action.Action.Params)
	return ctx, contentProto(found), scan
}

// resultContent scans a call's answer as the agent gets it, the credential
// removed (HR-076), and keeps none of it: only kinds and locations go on,
// with the marker. A call that never got an answer has nothing to scan.
func (e *Engine) resultContent(ctx context.Context, r Result) ([]*pb.ContentFinding, pb.ContentScan) {
	scan, ok := ctx.Value(contentScanKey{}).(pb.ContentScan)
	if !ok {
		return nil, pb.ContentScan_CONTENT_SCAN_UNSPECIFIED
	}
	if scan != pb.ContentScan_CONTENT_SCAN_SCANNED || r.Response == nil {
		return nil, scan
	}
	return contentProto(e.content.Scan(context.WithoutCancel(ctx), ports.SurfaceResult, "result", r.Response.Body)), scan
}

func contentProto(in []domain.Finding) []*pb.ContentFinding {
	var out []*pb.ContentFinding
	for _, f := range in {
		out = append(out, &pb.ContentFinding{Kind: f.Kind, Location: f.Location, Encoding: f.Encoding})
	}
	return out
}
