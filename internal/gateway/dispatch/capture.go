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
	if conn.GetKind() == KindModel && !conn.GetModel().GetCapturePrompts() {
		return nil // G0 M29 D820; opt-in per connection, G0 M30 D945b
	}
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
	// A model connection's prompts and replies are captured only while its
	// prompt capture is on (G0 M29 D820, HR-695; G0 M30 D945b); the model
	// path records them itself (modelCaptures).
	if monitor || conn.GetKind() == KindModel {
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

// modelKeep is how much of a model call's reply the answer keeps for
// capture: nothing unless an active profile asks for responses on a
// connection with prompt capture on (G0 M30 D945b), else the profile's cap
// plus the secret's length, so a secret cut at the cap is still redacted.
func modelKeep(conn *control.Connection, op string, monitor bool, secret []byte, now time.Time) int {
	if monitor || conn.GetKind() != KindModel {
		return 0
	}
	p := profileFor(conn, op, now)
	if p == nil || !p.GetResponse() {
		return 0
	}
	return min(int(p.GetByteCap()), maxCapture) + len(secret)
}

// modelCaptures returns the bodies of a model call an active profile asks
// for, on a connection with prompt capture on (G0 M30 D945b): the request
// body sent and the reply the answer kept, of size bytes in all, both with
// any echo of the credential redacted (HR-076). Content signals are
// unchanged.
func modelCaptures(conn *control.Connection, op string, monitor bool, request, kept []byte, size int64, secret []byte, now time.Time) []*pb.PayloadCapture {
	if monitor || conn.GetKind() != KindModel {
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
	if p.GetResponse() {
		if c := captured(p, pb.CaptureDirection_CAPTURE_DIRECTION_RESPONSE, egress.Redacted(kept, secret)); c != nil {
			if size > c.Size {
				c.Size, c.Truncated = size, true
			}
			out = append(out, c)
		}
	}
	return out
}
