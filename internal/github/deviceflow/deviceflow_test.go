// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package deviceflow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
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
	sim.RegisterSignInApp("Iv1.app", "secret")
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

// fakeGitHub answers the device flow's two requests: the device code with
// page as its sign-in page, then each poll in turn.
func fakeGitHub(t *testing.T, page string, polls ...string) *httptest.Server {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/login/device/code" {
			if page == "" {
				page = "http://" + r.Host + "/login/device"
			}
			_, _ = w.Write([]byte(`{"device_code": "d", "user_code": "AB-CD", "verification_uri": "` + page + `", "expires_in": 900, "interval": 5}`))
			return
		}
		_, _ = w.Write([]byte(polls[min(n, len(polls)-1)]))
		n++
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestTheDeviceFlowShowsOnlyGitHubsPageAndSlowsDown (P2f, review
// 2026-10-13): a sign-in page that is not on GitHub's web origin is never
// shown, so a code is entered only at GitHub; slow_down adds five seconds
// to every later wait; and a code that expires, at GitHub or by the
// 15-minute cap, is ErrExpired.
func TestTheDeviceFlowShowsOnlyGitHubsPageAndSlowsDown(t *testing.T) {
	ctx := context.Background()
	for _, page := range []string{"https://github.com.evil.example/login/device", "https://evil.example/login/device", "javascript:alert(1)"} {
		gh := fakeGitHub(t, page, `{"error": "authorization_pending"}`)
		flow := &deviceflow.Flow{WebURL: gh.URL, ClientID: "Iv1.app", Wait: func(context.Context, time.Duration) error { return nil }}
		if _, err := flow.Token(ctx, func(deviceflow.Code) { t.Errorf("%s was shown", page) }); err == nil {
			t.Errorf("%s: no error", page)
		}
	}

	gh := fakeGitHub(t, "", `{"error": "authorization_pending"}`, `{"error": "slow_down", "interval": 10}`,
		`{"error": "authorization_pending"}`, `{"access_token": "ghu_x"}`)
	var waits []time.Duration
	flow := &deviceflow.Flow{WebURL: gh.URL, ClientID: "Iv1.app", Wait: func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}}
	if token, err := flow.Token(ctx, func(deviceflow.Code) {}); err != nil || token != "ghu_x" {
		t.Fatalf("token %q: %v", token, err)
	}
	if want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}; !slices.Equal(waits, want) {
		t.Fatalf("waits %v, want %v", waits, want)
	}

	gh = fakeGitHub(t, "", `{"error": "expired_token"}`)
	flow.WebURL = gh.URL
	if _, err := flow.Token(ctx, func(deviceflow.Code) {}); !errors.Is(err, deviceflow.ErrExpired) {
		t.Fatalf("expired at GitHub: %v", err)
	}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	sim := simgithub.New(log.Discard()).WithClock(func() time.Time { return now })
	sim.RegisterSignInApp("Iv1.app", "secret")
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	flow = &deviceflow.Flow{WebURL: srv.URL, ClientID: "Iv1.app", Wait: func(context.Context, time.Duration) error {
		now = now.Add(16 * time.Minute)
		return nil
	}}
	if _, err := flow.Token(ctx, func(deviceflow.Code) {}); !errors.Is(err, deviceflow.ErrExpired) {
		t.Fatalf("expired in the simulator: %v", err)
	}
}
