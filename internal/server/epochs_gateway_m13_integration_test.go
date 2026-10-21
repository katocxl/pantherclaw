// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR373_GatewayRefetchesContainmentAfterBumpEpochs: a connected
// gateway's containment view moves to the bumped epoch without a restart,
// and a permit issued before the bump can no longer begin dispatch.
func TestHR373_GatewayRefetchesContainmentAfterBumpEpochs(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAll, publicAt(freeAddr(t)), gatewayAt(freeAddr(t)))
	org, enrollFile, keyFile, factsFile := seed(t, cfgPath, "100.00", true)
	base := serve(t, cfgPath)
	ctl := enrollGateway(t, enrollFile)
	wl := seededWorkload(t, base, keyFile)
	refundable(t, base, factsFile)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	view := control.NewContainment(ctl, pclog.Discard())
	go func() { _ = view.Run(ctx) }()
	select {
	case <-view.Ready():
	case <-ctx.Done():
		t.Fatal("no containment snapshot")
	}
	before, err := view.Check()
	if err != nil {
		t.Fatal(err)
	}

	nonce, err := ctl.Authority.GetNonce(ctx, &pantherclawv1.GetNonceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := authorize(ctl.Authority, refund(t, org, wl, "30.00"), wl.creds(t, nonce.GetNonce()))
	if err != nil || res.GetDecision() != pantherclawv1.Decision_DECISION_ALLOW || res.GetEpoch() != before {
		t.Fatalf("Authorize = %v, %v (gateway epoch %d)", res, err, before)
	}

	floor := time.Now().Add(-time.Minute).UnixMilli()
	if code, out, errs := runKeys(t, cfgPath, "bump-epochs", "--all", "--confirm"); code != 0 {
		t.Fatalf("bump-epochs = %d %s %s", code, out, errs)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		now, err := view.Check()
		if err == nil && now >= floor && now > before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the gateway's epoch is %d (%v) a minute after the bump, want above %d and %d", now, err, before, floor)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := ctl.Authority.BeginDispatch(ctx, &pantherclawv1.BeginDispatchRequest{
		PermitId: res.GetPermitId(), Epoch: res.GetEpoch(),
	}); err == nil {
		t.Fatal("a permit from before the bump began dispatch")
	}
}
