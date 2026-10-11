// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// MaxStaleness is how old the last containment message may be before the
// gateway refuses to dispatch (HR-010).
const MaxStaleness = 2 * time.Second

// Refusals: why the gateway will not dispatch now. Each is reported to the
// agent as enforcement_failed with its own code (containment_stale,
// kill_switch, gateway_revoked): nothing was sent.
var (
	ErrStale      = errors.New("containment_stale")
	ErrKillSwitch = errors.New("kill_switch_engaged")
	ErrRevoked    = errors.New("gateway_revoked")
)

// Containment is the gateway's view of its org's containment, kept fresh
// by the WatchContainment stream (HR-010).
type Containment struct {
	stream func(ctx context.Context) (receiver, error)
	log    *slog.Logger
	now    func() time.Time

	mu       sync.Mutex
	ready    chan struct{}
	gotFirst bool
	last     time.Time // monotonic time of the last message
	epoch    int64
	kill     bool
	active   bool
	config   int64
	conns    map[string]string
	onConfig func(version int64)
	// waiting is signaled for every message that hints that verification
	// tasks are due (G0 M7 design decision 1).
	waiting chan struct{}
}

// receiver is the client side of WatchContainment.
type receiver interface {
	Receive() (*pb.WatchContainmentResponse, error)
	Close() error
}

// NewContainment returns the view for c's gateway; Run keeps it fresh.
func NewContainment(c *Client, log *slog.Logger) *Containment {
	return newContainment(func(ctx context.Context) (receiver, error) {
		st, err := c.Stream.WatchContainment(ctx, &pb.WatchContainmentRequest{})
		if err != nil {
			return nil, err
		}
		return st, nil
	}, log)
}

func newContainment(stream func(ctx context.Context) (receiver, error), log *slog.Logger) *Containment {
	return &Containment{
		stream: stream, log: log, now: time.Now, ready: make(chan struct{}), conns: map[string]string{},
		waiting: make(chan struct{}, 1),
	}
}

// VerificationsWaiting receives when a message of the stream says that
// verification tasks are due on the gateway's connections: a hint to claim
// them now. It changes nothing the gateway may dispatch.
func (k *Containment) VerificationsWaiting() <-chan struct{} { return k.waiting }

// OnConfig registers a callback for configuration version changes.
func (k *Containment) OnConfig(f func(version int64)) {
	k.mu.Lock()
	k.onConfig = f
	k.mu.Unlock()
}

// Ready is closed once the first snapshot arrived.
func (k *Containment) Ready() <-chan struct{} { return k.ready }

// Check reports whether the gateway may dispatch now: a view at most
// MaxStaleness old, no kill switch, the gateway still active. It returns
// the current epoch; a permit from an older epoch is stale.
func (k *Containment) Check() (int64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case !k.gotFirst || k.now().Sub(k.last) > MaxStaleness:
		return 0, ErrStale
	case k.kill:
		return k.epoch, ErrKillSwitch
	case !k.active:
		return k.epoch, ErrRevoked
	}
	return k.epoch, nil
}

// Connection reports a connection's state ("" when the stream does not
// name it).
func (k *Containment) Connection(id string) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.conns[id]
}

// Run keeps the stream open, reconnecting with backoff, until ctx ends.
func (k *Containment) Run(ctx context.Context) error {
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		got, err := k.receive(ctx)
		select {
		case <-ctx.Done():
			return nil // shutdown, not a stream failure
		default:
		}
		if got {
			backoff = 100 * time.Millisecond
		}
		k.log.WarnContext(ctx, "gateway.containment_stream_ended", pclog.Err(err))
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		backoff = min(backoff*2, time.Second)
	}
	return nil
}

// receive reads one stream until it ends; got reports any message.
func (k *Containment) receive(ctx context.Context) (got bool, err error) {
	st, err := k.stream(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = st.Close() }()
	for {
		m, err := st.Receive()
		if errors.Is(err, io.EOF) {
			return got, errors.New("stream closed by the server")
		} else if err != nil {
			return got, err
		}
		got = true
		k.apply(m)
	}
}

func (k *Containment) apply(m *pb.WatchContainmentResponse) {
	k.mu.Lock()
	k.last, k.epoch, k.kill, k.active = k.now(), m.GetEpoch(), m.GetKillSwitch(), m.GetGatewayActive()
	if m.GetKind() != pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT {
		conns := make(map[string]string, len(m.GetConnections()))
		for _, c := range m.GetConnections() {
			conns[c.GetConnectionId()] = c.GetState()
		}
		k.conns = conns
	}
	moved := k.config != m.GetConfigVersion()
	k.config = m.GetConfigVersion()
	f := k.onConfig
	first := !k.gotFirst
	k.gotFirst = true
	k.mu.Unlock()
	if first {
		close(k.ready)
	}
	if moved && f != nil {
		f(m.GetConfigVersion())
	}
	if m.GetVerificationsWaiting() {
		select {
		case k.waiting <- struct{}{}:
		default: // a wake-up is already pending
		}
	}
}
