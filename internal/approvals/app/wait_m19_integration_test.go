// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
)

// TestHR491_WaitsPerInstanceHoldAcrossReplicas: two replicas (two pools)
// share an instance's wait slots: with one slot, a wait on one replica
// refuses a second on the other; the slot is free again when it ends.
// Covers: HR-491, T-214
func TestHR491_WaitsPerInstanceHoldAcrossReplicas(t *testing.T) {
	f := newFx(t, 1)
	inst := f.bound()
	f.request(1)
	a := approvals.NewWaits(f.p, 1, 0, nil)
	b := approvals.NewWaits(f.d.AppPool(t), 1, 0, nil)
	ctx := context.Background()
	held := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(held)
		if _, _, err := a.Wait(ctx, f.org, inst, f.run, f.txn, "PENDING", 2*time.Second); err != nil {
			t.Error(err)
		}
	}()
	<-held
	time.Sleep(300 * time.Millisecond) // replica a holds the slot
	if _, _, err := b.Wait(ctx, f.org, inst, f.run, f.txn, "PENDING", time.Second); !errors.Is(err, approvals.ErrTooManyWaits) {
		t.Fatalf("a second wait on the other replica: %v", err)
	}
	<-done
	if _, timedOut, err := b.Wait(ctx, f.org, inst, f.run, f.txn, "PENDING", 200*time.Millisecond); err != nil || !timedOut {
		t.Fatalf("after the first wait ended: %v %v", timedOut, err)
	}
}

// TestHR493_AWaitWithoutListenSeesAChangeWithinItsRecheck (ADR-0040,
// wait handles): the state is always read from the database; a waiter
// that misses pc_wait (no listener runs) still sees a change within
// Recheck.
// Covers: HR-493
func TestHR493_AWaitWithoutListenSeesAChangeWithinItsRecheck(t *testing.T) {
	f := newFx(t, 1)
	inst := f.bound()
	req := f.request(1)
	w := approvals.NewWaits(f.p, 0, 0, nil) // Run is never started
	go func() {
		time.Sleep(200 * time.Millisecond)
		if _, err := f.svc.Decline(f.as(f.bob), req, "TOO_RISKY", "", ""); err != nil {
			t.Error(err)
		}
	}()
	begin := time.Now()
	v, timedOut, err := w.Wait(context.Background(), f.org, inst, f.run, f.txn, "PENDING", 20*time.Second)
	if err != nil || timedOut || v.State != "DECLINED" {
		t.Fatalf("change: %+v %v %v", v, timedOut, err)
	}
	if took := time.Since(begin); took > approvals.Recheck+2*time.Second {
		t.Fatalf("the change took %s, the recheck is %s", took, approvals.Recheck)
	}
}
