// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const refundOp = "payments.refund.create"

// withCapture gives the payments connection a capture profile.
func withCapture(p *pb.GatewayCaptureProfile) func(*harness) {
	return func(h *harness) { h.conn.Captures = append(h.conn.Captures, p) }
}

func captureProfile(request, response bool, byteCap int32, expires time.Duration, ops ...string) *pb.GatewayCaptureProfile {
	if len(ops) == 0 {
		ops = []string{refundOp}
	}
	return &pb.GatewayCaptureProfile{
		Id: ids.NewV7().String(), ConnectionIds: []string{connID}, Operations: ops, Request: request, Response: response,
		ByteCap: byteCap, ExpireTime: timestamppb.New(time.Now().Add(expires)),
	}
}

// captured returns the captures the gateway reported with its one outcome.
func capturedBodies(t *testing.T, h *harness) map[pb.CaptureDirection]*pb.PayloadCapture {
	t.Helper()
	s := h.auth.snap()
	if len(s.records) != 1 {
		t.Fatalf("%d outcomes recorded", len(s.records))
	}
	out := map[pb.CaptureDirection]*pb.PayloadCapture{}
	for _, c := range s.records[0].GetCaptures() {
		out[c.GetDirection()] = c
	}
	return out
}

// TestHR199_NothingIsCapturedWithoutAnActiveProfile: without a profile, or
// with one that expired, does not cover the operation, or covers neither
// body, the outcome carries no capture.
func TestHR199_NothingIsCapturedWithoutAnActiveProfile(t *testing.T) {
	for name, opts := range map[string][]func(*harness){
		"no profile":           nil,
		"an expired profile":   {withCapture(captureProfile(true, true, 1024, -time.Second))},
		"another operation":    {withCapture(captureProfile(true, true, 1024, time.Hour, "payments.charge.create"))},
		"monitor mode":         {withCapture(captureProfile(true, true, 1024, time.Hour)), func(h *harness) { h.auth.mode = pb.DispatchMode_DISPATCH_MODE_MONITOR }},
		"another connection's": {func(h *harness) { h.conn.Captures = nil }},
	} {
		h := setup(t, opts...)
		if r := h.post(t, inbound, nil); r.code != http.StatusOK {
			t.Fatalf("%s: refund = %d %+v", name, r.code, r.refusal)
		}
		if c := capturedBodies(t, h); len(c) != 0 {
			t.Errorf("%s: captured %v", name, c)
		}
	}
}

// TestHR199_TheGatewayCapturesTheBuiltBodyAndTheRedactedResponse: under an
// active profile the outcome carries the outbound body the gateway built
// (never the agent's bytes, headers or the credential) and the target's
// response with an echoed credential redacted (HR-076), each cut to the
// profile's cap.
func TestHR199_TheGatewayCapturesTheBuiltBodyAndTheRedactedResponse(t *testing.T) {
	p := captureProfile(true, true, 1024, time.Hour)
	h := setup(t, withCredential(t, []string{"127.0.0.1"}), func(h *harness) { h.target.echo = "Authorization" }, withCapture(p))
	if r := h.post(t, inbound, map[string]string{"X-Agent-Secret": "agent-header-value"}); r.code != http.StatusOK {
		t.Fatalf("refund = %d %+v", r.code, r.refusal)
	}
	c := capturedBodies(t, h)
	req, resp := c[pb.CaptureDirection_CAPTURE_DIRECTION_REQUEST], c[pb.CaptureDirection_CAPTURE_DIRECTION_RESPONSE]
	if req == nil || string(req.GetContent()) != outbound || req.GetProfileId() != p.GetId() || req.GetTruncated() ||
		req.GetSize() != int64(len(outbound)) {
		t.Fatalf("request capture = %+v", req)
	}
	if resp == nil || !bytes.Contains(resp.GetContent(), []byte("[REDACTED]")) {
		t.Fatalf("response capture = %+v", resp)
	}
	for _, x := range []*pb.PayloadCapture{req, resp} {
		for _, secret := range []string{testSecret, "agent-header-value", "X-Agent-Secret"} {
			if bytes.Contains(x.GetContent(), []byte(secret)) {
				t.Errorf("%s capture holds %q: %q", x.GetDirection(), secret, x.GetContent())
			}
		}
	}

	// A small cap truncates; a profile of the response only takes no
	// request.
	h = setup(t, withCapture(captureProfile(false, true, 8, time.Hour)))
	if r := h.post(t, inbound, nil); r.code != http.StatusOK {
		t.Fatalf("refund = %d %+v", r.code, r.refusal)
	}
	c = capturedBodies(t, h)
	resp = c[pb.CaptureDirection_CAPTURE_DIRECTION_RESPONSE]
	if c[pb.CaptureDirection_CAPTURE_DIRECTION_REQUEST] != nil || resp == nil || len(resp.GetContent()) != 8 || !resp.GetTruncated() ||
		resp.GetSize() <= 8 {
		t.Fatalf("captures with an 8-byte cap = %v", c)
	}
}
