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

// contentScanKey marks a call whose tool result is scanned (record).
type contentScanKey struct{}

// scansContent reports whether a call's content is scanned (G0 M27 D504,
// D507): the org has content signals on, and the gateway itself carries the
// call. Hook, SDK and local connections are not scanned, delegated outcomes
// are not inspected, and they say so where they show.
func scansContent(c Call) bool {
	switch c.Connection.ContentSignals {
	case pb.ContentSignalMode_CONTENT_SIGNAL_MODE_WATCHING, pb.ContentSignalMode_CONTENT_SIGNAL_MODE_ACTIVE:
		return c.Connection.GetKind() != "local" && !cooperative(c) && c.Action.Action.Channel != string(defs.ChannelHook)
	case pb.ContentSignalMode_CONTENT_SIGNAL_MODE_UNSPECIFIED, pb.ContentSignalMode_CONTENT_SIGNAL_MODE_OFF:
	}
	return false
}

// outboundContent scans the action's arguments, before the decision, and
// marks ctx so the tool result is scanned too (HR-649). The Authority alone
// decides what a finding means.
func (e *Engine) outboundContent(ctx context.Context, c Call) (context.Context, []*pb.ContentFinding) {
	if !scansContent(c) {
		return ctx, nil
	}
	found := e.content.Scan(context.WithoutCancel(ctx), ports.SurfaceOutbound, "arg", c.Action.Action.Params)
	return context.WithValue(ctx, contentScanKey{}, true), contentProto(found)
}

// resultContent scans a call's answer as the agent gets it, the credential
// removed (HR-076), and keeps none of it: only kinds and locations go on.
func (e *Engine) resultContent(ctx context.Context, r Result) []*pb.ContentFinding {
	if ctx.Value(contentScanKey{}) == nil || r.Response == nil {
		return nil
	}
	return contentProto(e.content.Scan(context.WithoutCancel(ctx), ports.SurfaceResult, "result", r.Response.Body))
}

func contentProto(in []domain.Finding) []*pb.ContentFinding {
	var out []*pb.ContentFinding
	for _, f := range in {
		out = append(out, &pb.ContentFinding{Kind: f.Kind, Location: f.Location})
	}
	return out
}
