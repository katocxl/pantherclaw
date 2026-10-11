// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// TestHR010_TheGatewayDispatchesNothingWithoutFreshContainment: a stale
// containment view, a revoked gateway and the kill switch each stop a
// request before the Authority is asked; nothing reaches the target.
func TestHR010_TheGatewayDispatchesNothingWithoutFreshContainment(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code int
		want string
	}{
		"stale":       {control.ErrStale, http.StatusServiceUnavailable, "containment_stale"},
		"revoked":     {control.ErrRevoked, http.StatusServiceUnavailable, "gateway_revoked"},
		"kill switch": {control.ErrKillSwitch, http.StatusForbidden, "kill_switch"},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, func(h *harness) { h.containment.err = tc.err })
			if err := h.gw.Contained(); !errors.Is(err, tc.err) {
				t.Fatalf("Contained() = %v, want %v", err, tc.err)
			}
			r := h.post(t, inbound, nil)
			if r.code != tc.code || r.refusal.ErrorClass != "enforcement_failed" || r.refusal.Error != tc.want ||
				h.auth.snap().authorize != 0 || h.target.calls() != 0 {
				t.Fatalf("%d %+v, authorize %d, target %d", r.code, r.refusal, h.auth.snap().authorize, h.target.calls())
			}
		})
	}
}

// TestHR010_ContainmentChangingDuringTheDecisionStopsDispatch: when the
// view goes stale or the epoch moves past the permit's while the Authority
// decides, BeginDispatch is never called and nothing is sent.
func TestHR010_ContainmentChangingDuringTheDecisionStopsDispatch(t *testing.T) {
	for name, after := range map[string]func(*fakeContainment){
		"epoch moved":  func(f *fakeContainment) { f.epoch = 2 },
		"stream stale": func(f *fakeContainment) { f.err = control.ErrStale },
		"kill switch":  func(f *fakeContainment) { f.err = control.ErrKillSwitch },
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, func(h *harness) { h.containment.after = after })
			r := h.post(t, inbound, nil)
			if s := h.auth.snap(); r.code == http.StatusOK || s.authorize != 1 || len(s.begins) != 0 || h.target.calls() != 0 {
				t.Fatalf("%d, authorize %d, begins %d, target %d", r.code, s.authorize, len(s.begins), h.target.calls())
			}
		})
	}
}

// TestHR010_ServingWaitsForTheFirstSnapshot: WaitReady blocks until the
// containment view has its first snapshot, and gives up after its timeout.
func TestHR010_ServingWaitsForTheFirstSnapshot(t *testing.T) {
	h := setup(t)
	pending := &fakeContainment{ready: make(chan struct{})}
	h.gw.containment = pending
	if err := h.gw.WaitReady(context.Background(), 50*time.Millisecond); err == nil {
		t.Fatal("ready without a snapshot")
	}
	close(pending.ready)
	if err := h.gw.WaitReady(context.Background(), time.Second); err != nil {
		t.Fatalf("not ready after the snapshot: %v", err)
	}
}

// TestServingWaitsForTheFirstConfiguration: with a containment snapshot
// but no configuration, the gateway is not ready (decision 19: a gateway
// whose configuration is unavailable at start does not serve).
func TestServingWaitsForTheFirstConfiguration(t *testing.T) {
	h := setup(t)
	pending := &fakeConfig{ready: make(chan struct{})}
	h.gw.config = pending
	if err := h.gw.WaitReady(context.Background(), 50*time.Millisecond); err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("ready without a configuration: %v", err)
	}
	close(pending.ready)
	if err := h.gw.WaitReady(context.Background(), time.Second); err != nil {
		t.Fatalf("not ready after the configuration: %v", err)
	}
}
