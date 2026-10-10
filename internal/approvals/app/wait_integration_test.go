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
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// bound binds the fixture's run to a new instance and returns it.
func (f *fx) bound() ids.UUID {
	f.t.Helper()
	inst := ids.NewV7()
	f.exec(`INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, f.org, inst, f.agent, inst.String()[:36]+"0000000")
	f.d.AdminExec(f.t, "UPDATE pc.runs SET instance_id = $1 WHERE id = $2", inst, f.run)
	return inst
}

// TestHR174_AWaitServesOnlyItsOwnRunAndInstance: the handle's state, codes
// and times for the instance its run is bound to; anyone else, another run
// or an unknown handle gets "no wait handle".
func TestHR174_AWaitServesOnlyItsOwnRunAndInstance(t *testing.T) {
	f := newFx(t, 1)
	inst := f.bound()
	req := f.request(1)
	w := approvals.NewWaits(f.p, 0, 0, nil)
	ctx := context.Background()
	v, err := w.Read(ctx, f.org, inst, f.run, f.txn)
	if err != nil || v.State != "PENDING" || v.RequestID != req || v.Handle != f.txn || v.RetryAfter != approvals.RetryAfter || v.Final() {
		t.Fatalf("read: %+v, %v", v, err)
	}
	for name, c := range map[string][3]ids.UUID{
		"another instance": {ids.NewV7(), f.run, f.txn}, "another run": {inst, ids.NewV7(), f.txn}, "unknown handle": {inst, f.run, ids.NewV7()},
	} {
		if _, err := w.Read(ctx, f.org, c[0], c[1], c[2]); !errors.Is(err, approvals.ErrNoWait) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.RequestEvidence(f.as(f.bob), req, "WHY_NEEDED", "a note never shown to the agent", time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if v, _ := w.Read(ctx, f.org, inst, ids.UUID{}, f.txn); v.State != "EVIDENCE_REQUESTED" || v.Code != "WHY_NEEDED" || v.EvidenceDeadline == nil {
		t.Fatalf("evidence: %+v", v)
	}
}

// TestHR174_AWaitAnswersOnAChangeOrItsTimeout: a long poll returns at its
// timeout, at once when the state differs from the known one, and on a
// change, woken by pc_wait well before its 5-second recheck; it is bounded
// per instance.
func TestHR174_AWaitAnswersOnAChangeOrItsTimeout(t *testing.T) {
	f := newFx(t, 1)
	inst := f.bound()
	req := f.request(1)
	w := approvals.NewWaits(f.p, 1, 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	time.Sleep(200 * time.Millisecond) // LISTEN is in place

	if v, timedOut, err := w.Wait(ctx, f.org, inst, f.run, f.txn, "PENDING", time.Second); err != nil || !timedOut || v.State != "PENDING" {
		t.Fatalf("timeout: %+v %v %v", v, timedOut, err)
	}
	if v, timedOut, err := w.Wait(ctx, f.org, inst, f.run, f.txn, "READY", 0); err != nil || timedOut || v.State != "PENDING" {
		t.Fatalf("a different known state: %+v %v %v", v, timedOut, err)
	}

	started := make(chan struct{})
	go func() {
		<-started
		time.Sleep(300 * time.Millisecond)
		if _, err := f.svc.Decline(f.as(f.bob), req, "TOO_RISKY", "", ""); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		// While the first wait holds the instance's only slot, a second one is refused.
		time.Sleep(100 * time.Millisecond)
		if _, _, err := w.Wait(ctx, f.org, inst, f.run, f.txn, "PENDING", time.Second); !errors.Is(err, approvals.ErrTooManyWaits) {
			t.Errorf("a second wait: %v", err)
		}
		close(started)
	}()
	begin := time.Now()
	v, timedOut, err := w.Wait(ctx, f.org, inst, f.run, f.txn, "PENDING", 20*time.Second)
	if err != nil || timedOut || v.State != "DECLINED" || v.Code != "APPROVAL_DECLINED" || !v.Final() || v.RetryAfter != 0 {
		t.Fatalf("change: %+v %v %v", v, timedOut, err)
	}
	if took := time.Since(begin); took > 4*time.Second {
		t.Fatalf("the change took %s: pc_wait did not wake the waiter", took)
	}
	if _, timedOut, err := w.Wait(ctx, f.org, inst, f.run, f.txn, "DECLINED", 5*time.Second); err != nil || timedOut {
		t.Fatalf("a final state answers at once: %v %v", timedOut, err)
	}
}

// TestHR174_AStreamSendsChangesAndEndsAtAFinalState: the SSE stream's
// source sends the state at once and each change, and ends at a final one.
func TestHR174_AStreamSendsChangesAndEndsAtAFinalState(t *testing.T) {
	f := newFx(t, 1)
	inst := f.bound()
	req := f.request(1)
	w := approvals.NewWaits(f.p, 0, 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	var states []string
	done := make(chan error, 1)
	go func() {
		done <- w.Stream(ctx, f.org, inst, f.txn, func(v approvals.WaitView, heartbeat bool) error {
			if !heartbeat {
				states = append(states, v.State)
			}
			if len(states) == 1 && v.State == "PENDING" {
				go func() {
					if _, err := f.approve(f.bob, req); err != nil {
						t.Error(err)
					}
				}()
			}
			if v.State == "READY" {
				f.exec("UPDATE pc.approval_requests SET state = 'INVALIDATED', end_reason = 'RUN_ENDED', ended_at = now() WHERE id = $1", req)
			}
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil || len(states) != 3 || states[0] != "PENDING" || states[1] != "READY" || states[2] != "INVALIDATED" {
			t.Fatalf("states %v, %v", states, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the stream did not end: %v", states)
	}
}
