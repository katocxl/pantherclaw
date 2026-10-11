// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// script is a stream that delivers its messages, then ends.
type script struct {
	msgs []*pb.WatchContainmentResponse
	end  error
}

func (s *script) Receive() (*pb.WatchContainmentResponse, error) {
	if len(s.msgs) == 0 {
		return nil, s.end
	}
	m := s.msgs[0]
	s.msgs = s.msgs[1:]
	return m, nil
}

func (s *script) Close() error { return nil }

func msg(kind pb.ContainmentStateKind, epoch, config int64, kill bool) *pb.WatchContainmentResponse {
	return &pb.WatchContainmentResponse{
		Kind: kind, Epoch: epoch, ConfigVersion: config, KillSwitch: kill, GatewayActive: true,
		Connections: []*pb.ConnectionStateEntry{{ConnectionId: "c1", State: "ACTIVE"}},
	}
}

// clock is a settable time.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// TestHR010_AStaleContainmentViewRefusesDispatch: nothing is allowed before
// the first snapshot or once the last message is more than 2 seconds old;
// the kill switch and a revoked gateway refuse too.
func TestHR010_AStaleContainmentViewRefusesDispatch(t *testing.T) {
	clk := &clock{now: time.Now()}
	k := newContainment(nil, pclog.Discard())
	k.now = clk.Now
	if _, err := k.Check(); !errors.Is(err, ErrStale) {
		t.Fatalf("before a snapshot: %v", err)
	}
	select {
	case <-k.Ready():
		t.Fatal("ready before a snapshot")
	default:
	}
	k.apply(msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_SNAPSHOT, 7, 1, false))
	<-k.Ready()
	if e, err := k.Check(); err != nil || e != 7 {
		t.Fatalf("fresh view: %d %v", e, err)
	}
	if k.Connection("c1") != "ACTIVE" {
		t.Fatal("connection state not kept")
	}
	clk.add(MaxStaleness + time.Millisecond)
	if _, err := k.Check(); !errors.Is(err, ErrStale) {
		t.Fatalf("2 s without a message: %v", err)
	}
	k.apply(msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT, 7, 1, false))
	if _, err := k.Check(); err != nil {
		t.Fatalf("a heartbeat makes the view fresh again: %v", err)
	}
	if k.Connection("c1") != "ACTIVE" {
		t.Fatal("a heartbeat must not drop connection states")
	}
	k.apply(msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_CHANGE, 8, 1, true))
	if e, err := k.Check(); !errors.Is(err, ErrKillSwitch) || e != 8 {
		t.Fatalf("kill switch: %d %v", e, err)
	}
	revoked := msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_CHANGE, 9, 1, false)
	revoked.GatewayActive = false
	k.apply(revoked)
	if _, err := k.Check(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked gateway: %v", err)
	}
}

// TestHR010_TheStreamReconnectsAndReportsConfigurationChanges: a stream
// that ends is opened again, and a moved configuration version is reported.
func TestHR010_TheStreamReconnectsAndReportsConfigurationChanges(t *testing.T) {
	var opened atomic.Int32
	streams := []*script{
		{msgs: []*pb.WatchContainmentResponse{msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_SNAPSHOT, 1, 1, false)}, end: io.EOF},
		{msgs: []*pb.WatchContainmentResponse{msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_SNAPSHOT, 1, 2, false)}, end: errors.New("reset")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	versions := make(chan int64, 4)
	k := newContainment(func(context.Context) (receiver, error) {
		i := int(opened.Add(1)) - 1
		if i >= len(streams) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return streams[i], nil
	}, pclog.Discard())
	k.OnConfig(func(v int64) { versions <- v })
	go func() { _ = k.Run(ctx) }()
	for _, want := range []int64{1, 2} {
		select {
		case v := <-versions:
			if v != want {
				t.Fatalf("config version %d, want %d", v, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no configuration version %d", want)
		}
	}
	if opened.Load() < 2 {
		t.Fatal("the stream was not opened again")
	}
}

// TestHR190_TheVerificationsHintWakesWithoutChangingContainment: a message
// that says verification tasks are due signals VerificationsWaiting, at
// most one pending wake-up, whatever its kind; one without the hint does
// not; and the hint changes nothing the gateway may dispatch (G0 M7 design
// decision 1).
func TestHR190_TheVerificationsHintWakesWithoutChangingContainment(t *testing.T) {
	k := newContainment(nil, pclog.Discard())
	pending := func() bool {
		select {
		case <-k.VerificationsWaiting():
			return true
		default:
			return false
		}
	}
	k.apply(msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_SNAPSHOT, 3, 1, false))
	if pending() {
		t.Fatal("a message without the hint woke the verifier")
	}
	hinted := msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT, 3, 1, false)
	hinted.VerificationsWaiting = true
	k.apply(hinted)
	k.apply(hinted)
	if !pending() || pending() {
		t.Fatal("two hints must leave exactly one wake-up pending")
	}
	if e, err := k.Check(); err != nil || e != 3 || k.Connection("c1") != "ACTIVE" {
		t.Fatalf("the hint changed containment: %d %v %q", e, err, k.Connection("c1"))
	}
	killed := msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_CHANGE, 4, 1, true)
	killed.VerificationsWaiting = true
	k.apply(killed)
	if _, err := k.Check(); !errors.Is(err, ErrKillSwitch) {
		t.Fatalf("a hint beside the kill switch: %v", err)
	}
}
