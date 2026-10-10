// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// maxCapture is the most a capture profile keeps of one body (64 KiB).
const maxCapture = 64 << 10

// profileFor returns the first active, unexpired capture profile of conn
// that covers op, or nil (G0 M7 design decision 10, HR-199).
func profileFor(conn *control.Connection, op string, now time.Time) *pb.GatewayCaptureProfile {
	for _, p := range conn.Captures {
		if exp := p.GetExpireTime(); exp == nil || !now.Before(exp.AsTime()) {
			continue
		}
		if slices.Contains(p.GetOperations(), op) && p.GetByteCap() > 0 {
			return p
		}
	}
	return nil
}

// captured is one body cut to the profile's cap.
func captured(p *pb.GatewayCaptureProfile, d pb.CaptureDirection, body []byte) *pb.PayloadCapture {
	if len(body) == 0 {
		return nil
	}
	limit := min(int(p.GetByteCap()), maxCapture)
	c := &pb.PayloadCapture{ProfileId: p.GetId(), Direction: d, Size: int64(len(body))}
	if len(body) > limit {
		body, c.Truncated = body[:limit], true
	}
	c.Content = append([]byte(nil), body...)
	return c
}

// captures returns the bodies of an enforced dispatch an active profile
// asks for: the outbound body the gateway built from the action (never its
// headers, so never the credential) and the target's response, both with
// any echo of the credential redacted (HR-076). Monitor-mode dispatches
// capture nothing; delegated outcomes never reach here.
func captures(conn *control.Connection, op string, monitor bool, request []byte, response *[]byte, secret []byte, now time.Time) []*pb.PayloadCapture {
	if monitor {
		return nil
	}
	p := profileFor(conn, op, now)
	if p == nil {
		return nil
	}
	var out []*pb.PayloadCapture
	if p.GetRequest() {
		if c := captured(p, pb.CaptureDirection_CAPTURE_DIRECTION_REQUEST, egress.Redacted(request, secret)); c != nil {
			out = append(out, c)
		}
	}
	if p.GetResponse() && response != nil {
		if c := captured(p, pb.CaptureDirection_CAPTURE_DIRECTION_RESPONSE, egress.Redacted(*response, secret)); c != nil {
			out = append(out, c)
		}
	}
	return out
}
