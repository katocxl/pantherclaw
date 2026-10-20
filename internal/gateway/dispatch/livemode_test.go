// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

type reasonReports struct {
	mu   sync.Mutex
	got  []string
	fail bool
}

func (r *reasonReports) report(_ context.Context, _, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, reason)
	if r.fail {
		return errors.New("server unavailable")
	}
	return nil
}

func (r *reasonReports) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

// TestHR303_ALivemodeAnswerOpensTheCircuit: one live-mode answer opens the
// circuit at once, whatever the outcomes, and reports stripe_livemode (not
// the outcome counts) until the server has it; a restore under a newer
// revision closes it (D54).
func TestHR303_ALivemodeAnswerOpensTheCircuit(t *testing.T) {
	ctx := context.Background()
	counts := &reports{}
	reasons := &reasonReports{fail: true}
	b := newBreaker(time.Now, counts.report, pclog.Discard()).withReason(reasons.report)
	c := conn(3, "ACTIVE")
	b.trip(ctx, c, QuarantineStripeLivemode)
	if !b.open(ctx, c) {
		t.Fatal("the circuit is closed after a live-mode answer")
	}
	deadline := time.Now().Add(5 * time.Second)
	for reasons.count() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("a failed report was not sent again")
		}
		b.open(ctx, c)
		time.Sleep(5 * time.Millisecond)
	}
	reasons.mu.Lock()
	reasons.fail = false
	reasons.mu.Unlock()
	for b.open(ctx, c); ; b.open(ctx, c) {
		b.mu.Lock()
		done := b.circuits[c.GetId()].reported
		b.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the report never succeeded")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if counts.count() != 0 {
		t.Fatalf("outcome counts reported for a live-mode trip: %v", counts.got)
	}
	for _, r := range reasons.got {
		if r != QuarantineStripeLivemode {
			t.Fatalf("reason %q", r)
		}
	}
	// A second trip while open changes nothing.
	n := reasons.count()
	b.trip(ctx, c, QuarantineStripeLivemode)
	time.Sleep(20 * time.Millisecond)
	if reasons.count() != n {
		t.Fatal("an open circuit was reported again")
	}
	if b.open(ctx, conn(4, "ACTIVE")) {
		t.Fatal("a restored connection is still open")
	}
}

// TestHR303_LivemodeAnswers: which Stripe answers are in live mode.
func TestHR303_LivemodeAnswers(t *testing.T) {
	for body, want := range map[string]bool{
		`{"id":"re_1","livemode":true}`:                                   true,
		`{"id":"re_1","livemode":false}`:                                  false,
		`{"object":"list","data":[{"livemode":false},{"livemode":true}]}`: true,
		`{"object":"list","data":[{"livemode":false}]}`:                   false,
		`{"error":{"type":"api_error"}}`:                                  false,
		`not json`:                                                        false,
	} {
		if got := answersLivemode([]byte(body)); got != want {
			t.Errorf("%s: %v, want %v", body, got, want)
		}
	}
}

// TestStripeAnswerLiveOnlyWatchesPCStripe: another package's answer is
// never read for livemode.
func TestStripeAnswerLiveOnlyWatchesPCStripe(t *testing.T) {
	pkg, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	reasons := &reasonReports{}
	e := &Engine{log: pclog.Discard(), breaker: newBreaker(time.Now, nil, pclog.Discard()).withReason(reasons.report)}
	c := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c-2", Revision: 1, State: "ACTIVE"}, Package: pkg}
	if e.stripeAnswerLive(context.Background(), c, []byte(`{"livemode":true}`), "dispatch") || e.breaker.open(context.Background(), c) {
		t.Fatal("a pc.mock-payments answer opened the circuit")
	}
	pkg.Name = StripePackage
	if !e.stripeAnswerLive(context.Background(), c, []byte(`{"livemode":true}`), "dispatch") || !e.breaker.open(context.Background(), c) {
		t.Fatal("a pc.stripe live-mode answer did not open the circuit")
	}
}
