// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package deviceflow_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/github/deviceflow"
	"github.com/katocxl/pantherclaw/internal/platform/log"
	simgithub "github.com/katocxl/pantherclaw/internal/sim/github"
)

// TestTheDeviceFlowWaitsForTheSignIn (P2f): the flow shows the code to
// enter, polls while the person has not signed in, and returns the user
// access token once they have; a sign-in refused at GitHub is ErrDenied,
// and another App's client id gets no code.
func TestTheDeviceFlowWaitsForTheSignIn(t *testing.T) {
	sim := simgithub.New(log.Discard())
	sim.RegisterApp(1, "Iv1.app", nil)
	gh := httptest.NewServer(sim.Handler())
	t.Cleanup(gh.Close)
	ctx := context.Background()
	var code string
	polls := 0
	flow := &deviceflow.Flow{WebURL: gh.URL, ClientID: "Iv1.app", Wait: func(context.Context, time.Duration) error {
		if polls++; polls == 3 {
			return sim.AuthorizeDevice(code, simgithub.DeviceUser{ID: 5, Login: "carol-gh"})
		}
		return nil
	}}
	token, err := flow.Token(ctx, func(c deviceflow.Code) { code = c.UserCode })
	if err != nil || !strings.HasPrefix(token, "ghu_") || polls != 3 || code == "" {
		t.Fatalf("token %q after %d polls: %v", token, polls, err)
	}
	flow.Wait = func(context.Context, time.Duration) error { return nil }
	if _, err := flow.Token(ctx, func(c deviceflow.Code) { _ = sim.DenyDevice(c.UserCode) }); !errors.Is(err, deviceflow.ErrDenied) {
		t.Fatalf("refused: %v", err)
	}
	other := &deviceflow.Flow{WebURL: gh.URL, ClientID: "Iv1.other", Wait: flow.Wait}
	if _, err := other.Token(ctx, func(deviceflow.Code) { t.Error("another App was shown a code") }); err == nil {
		t.Fatal("another App's client id got a token")
	}
}
