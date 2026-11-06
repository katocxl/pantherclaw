// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR716_AModelConnectionIsCapturedOnlyWhileCaptureIsOn (G0 M30 D945b,
// HR-716): a capture profile covering a model call keeps nothing while the
// connection's prompt capture is off (the default); with it on, the
// profile keeps the request and the reply within its cap, with the
// credential's echo redacted; monitor mode keeps nothing.
func TestHR716_AModelConnectionIsCapturedOnlyWhileCaptureIsOn(t *testing.T) {
	now := time.Now()
	profile := &pb.GatewayCaptureProfile{
		Id: "p1", Operations: []string{"model.chat"}, Request: true, Response: true, ByteCap: 1024,
		ExpireTime: timestamppb.New(now.Add(time.Hour)),
	}
	conn := func(capture bool) *control.Connection {
		return &control.Connection{
			GatewayConnection: &pb.GatewayConnection{Kind: KindModel, Model: &pb.ModelConfig{CapturePrompts: capture}},
			Captures:          []*pb.GatewayCaptureProfile{profile},
		}
	}
	secret := []byte("sk-test-secret")
	req, reply := []byte(`{"prompt":"hi sk-test-secret"}`), []byte(`{"text":"hello"}`)

	off := conn(false)
	if profileFor(off, "model.chat", now) != nil || modelKeep(off, "model.chat", false, secret, now) != 0 ||
		modelCaptures(off, "model.chat", false, req, reply, int64(len(reply)), secret, now) != nil {
		t.Fatal("a model connection with capture off was captured")
	}

	on := conn(true)
	if modelKeep(on, "model.chat", false, secret, now) != 1024+len(secret) {
		t.Fatalf("keep %d", modelKeep(on, "model.chat", false, secret, now))
	}
	got := modelCaptures(on, "model.chat", false, req, reply, int64(len(reply)), secret, now)
	if len(got) != 2 || got[0].GetDirection() != pb.CaptureDirection_CAPTURE_DIRECTION_REQUEST ||
		string(got[1].GetContent()) != string(reply) {
		t.Fatalf("captures %v", got)
	}
	if string(got[0].GetContent()) == string(req) {
		t.Fatal("the credential's echo was kept")
	}
	if modelCaptures(on, "model.chat", true, req, reply, int64(len(reply)), secret, now) != nil {
		t.Fatal("a monitor-mode model call was captured")
	}
}
