// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Containment stream timing (HR-010, G0 M6 design decision 4).
const (
	// PollEvery is how often each watched org's containment is read, so a
	// missed notification costs at most this long.
	PollEvery = 250 * time.Millisecond
	// HeartbeatEvery is how often a stream sends its state when nothing
	// changed.
	HeartbeatEvery = 500 * time.Millisecond
	// ConfirmedWithin bounds how old the server's last successful read may
	// be for a stream to send anything; older, and the stream goes quiet so
	// that its gateway fails closed.
	ConfirmedWithin = time.Second
	// StreamLifetime caps a stream; the gateway reconnects and loads a new
	// snapshot.
	StreamLifetime = 15 * time.Minute
	// MaxStreamsPerCert caps concurrent streams of one certificate.
	MaxStreamsPerCert = 4
)

// ErrTooManyStreams reports a certificate that already has
// MaxStreamsPerCert streams.
var ErrTooManyStreams = errors.New("gateways: too many containment streams for this certificate")

// Containment is what a gateway is told: its org's epoch and kill switch,
// its own configuration version and state, and the states of the
// connections it serves.
type Containment struct {
	Epoch         int64
	KillSwitch    bool
	ConfigVersion int64
	GatewayActive bool
	Connections   map[ids.UUID]string
	AsOf          time.Time
	// VerificationsWaiting hints that verification tasks are due on the
	// gateway's active connections and the kill switch is off, so that
	// ClaimVerifications would lease them now (G0 M7 design decision 1).
	// It is not containment: every message carries it, and it never makes
	// a change on its own.
	VerificationsWaiting bool
}

// Equal reports whether two views differ only in AsOf and the
// verifications hint, which heartbeats carry too.
func (c Containment) Equal(o Containment) bool {
	return c.Epoch == o.Epoch && c.KillSwitch == o.KillSwitch && c.ConfigVersion == o.ConfigVersion &&
		c.GatewayActive == o.GatewayActive && maps.Equal(c.Connections, o.Connections)
}

// Hub watches the containment of the orgs that have streams: one poller
// per org, woken early by LISTEN pc_containment (whose payload is the org
// id only, HR-056).
type Hub struct {
	pool *db.Pool
	log  *slog.Logger
	now  func() time.Time
	// done closes when Run ends (server shutdown), ending every stream.
	done     chan struct{}
	doneOnce sync.Once

	mu      sync.Mutex
	orgs    map[ids.OrgID]*orgWatch
	streams map[ids.UUID]int // per certificate
}

type orgWatch struct {
	subs map[*Subscription]struct{}
	wake chan struct{}
	stop context.CancelFunc

	mu        sync.Mutex
	gateways  map[ids.UUID]Containment
	confirmed time.Time
}

// NewHub returns a Hub. Run must be running for early wake-ups; without it
// changes still arrive within PollEvery.
func NewHub(pool *db.Pool, log *slog.Logger) *Hub {
	if log == nil {
		log = pclog.Discard()
	}
	return &Hub{pool: pool, log: log, now: time.Now, done: make(chan struct{}), orgs: map[ids.OrgID]*orgWatch{}, streams: map[ids.UUID]int{}}
}

// Done closes when the hub stops; streams end with it.
func (s *Subscription) Done() <-chan struct{} { return s.hub.done }

// Subscription is one stream's view of its gateway's containment.
type Subscription struct {
	hub     *Hub
	org     ids.OrgID
	gateway ids.UUID
	cert    ids.UUID
	ch      chan struct{}
	w       *orgWatch
}

// Subscribe opens a view for a gateway certificate.
func (h *Hub) Subscribe(id Identity) (*Subscription, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streams[id.Cert] >= MaxStreamsPerCert {
		return nil, ErrTooManyStreams
	}
	w, ok := h.orgs[id.Org]
	if !ok {
		ctx, cancel := context.WithCancel(context.Background())
		w = &orgWatch{subs: map[*Subscription]struct{}{}, wake: make(chan struct{}, 1), stop: cancel, gateways: map[ids.UUID]Containment{}}
		h.orgs[id.Org] = w
		go h.poll(ctx, id.Org, w)
	}
	s := &Subscription{hub: h, org: id.Org, gateway: id.Gateway, cert: id.Cert, ch: make(chan struct{}, 1), w: w}
	w.subs[s] = struct{}{}
	h.streams[id.Cert]++
	signal(w.wake)
	return s, nil
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Close ends the subscription; the org's poller stops with its last one.
func (s *Subscription) Close() {
	h := s.hub
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := s.w.subs[s]; !ok {
		return
	}
	delete(s.w.subs, s)
	if h.streams[s.cert]--; h.streams[s.cert] <= 0 {
		delete(h.streams, s.cert)
	}
	if len(s.w.subs) == 0 {
		s.w.stop()
		delete(h.orgs, s.org)
	}
}

// Changed is signaled after every read of the org's containment.
func (s *Subscription) Changed() <-chan struct{} { return s.ch }

// State returns the gateway's containment and whether the server confirmed
// it from the database within ConfirmedWithin. A stream sends nothing that
// is not confirmed (HR-010).
func (s *Subscription) State() (Containment, bool) {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	c, ok := s.w.gateways[s.gateway]
	return c, ok && s.hub.now().Sub(s.w.confirmed) <= ConfirmedWithin
}

// poll reads the org's containment every PollEvery, or at once when woken,
// until the last subscriber leaves.
func (h *Hub) poll(ctx context.Context, org ids.OrgID, w *orgWatch) {
	t := time.NewTicker(PollEvery)
	defer t.Stop()
	for {
		if err := h.read(ctx, org, w); err != nil && ctx.Err() == nil {
			h.log.WarnContext(ctx, "gateways.containment_read_failed", slog.String("org_id", org.String()), pclog.Err(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.wake:
		}
	}
}

func (h *Hub) read(ctx context.Context, org ids.OrgID, w *orgWatch) error {
	next := map[ids.UUID]Containment{}
	err := h.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		c, err := q.GetContainmentNow(ctx, org)
		if db.IsNoRows(err) {
			// No containment row yet: epoch 1 and no kill switch (the defaults).
			c = dbq.GetContainmentNowRow{Epoch: 1, Now: h.now()}
		} else if err != nil {
			return err
		}
		gws, err := q.WatchedGateways(ctx, org)
		if err != nil {
			return err
		}
		conns, err := q.WatchedConnections(ctx, org)
		if err != nil {
			return err
		}
		for _, g := range gws {
			s := Containment{
				Epoch: c.Epoch, KillSwitch: c.KillSwitch, ConfigVersion: g.ConfigVersion, GatewayActive: g.State == "ACTIVE",
				Connections: map[ids.UUID]string{}, AsOf: c.Now,
			}
			for _, cn := range conns {
				if cn.GatewayID == g.ID {
					s.Connections[cn.ID] = cn.State
					s.VerificationsWaiting = s.VerificationsWaiting || (cn.VerificationsDue && !c.KillSwitch)
				}
			}
			next[g.ID] = s
		}
		return nil
	})
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.gateways, w.confirmed = next, h.now()
	w.mu.Unlock()
	h.mu.Lock()
	for s := range w.subs {
		signal(s.ch)
	}
	h.mu.Unlock()
	return nil
}

// Run listens for pc_containment notifications and wakes the org's poller
// at once, reconnecting with backoff, until ctx ends.
func (h *Hub) Run(ctx context.Context) error {
	defer h.doneOnce.Do(func() { close(h.done) })
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		err := h.listen(ctx)
		if ctx.Err() != nil {
			return nil
		}
		h.log.WarnContext(ctx, "gateways.containment_listen_failed", pclog.Err(err))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Second)
	}
	return nil
}

func (h *Hub) listen(ctx context.Context) error {
	conn, err := h.pool.Pgx().Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "UNLISTEN *")
		conn.Release()
	}()
	if _, err := conn.Exec(ctx, "LISTEN pc_containment"); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		org, err := ids.Parse[ids.Org](n.Payload)
		if err != nil {
			continue
		}
		h.mu.Lock()
		if w := h.orgs[org]; w != nil {
			signal(w.wake)
		}
		h.mu.Unlock()
	}
}
