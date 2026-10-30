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
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
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
	// MaxStreamsPerCert caps concurrent streams of one certificate across
	// every replica (pc.stream_leases, G0 M19 D201, HR-491).
	MaxStreamsPerCert = 4
	// leaseWithin bounds taking a stream's lease.
	leaseWithin = 5 * time.Second
	// listenRetryFirst and listenRetryMax bound the wait before LISTEN is
	// tried again: a long outage never leaves it asleep once the database
	// is back (G0 M19 D224).
	listenRetryFirst = 100 * time.Millisecond
	listenRetryMax   = 500 * time.Millisecond
)

// ErrTooManyStreams reports a certificate that already has
// MaxStreamsPerCert streams.
var ErrTooManyStreams = errors.New("gateways: too many containment streams for this certificate")

// errOrgInactive stops confirming the containment state of an org that is
// not ACTIVE: its open streams go quiet and its gateways stop dispatching
// within 2 seconds (D22, HR-392).
var errOrgInactive = errors.New("gateways: the org is not active")

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
	// pollEvery is PollEvery; listenDown, if set, runs each time LISTEN is
	// lost. Tests set them.
	pollEvery  time.Duration
	listenDown func()

	// notified, when set, is told the org of every notification, watched
	// or not: the gateway certificate cache forgets the org's entries
	// (HR-492).
	notified func(ids.OrgID)
	// leases counts each certificate's streams across replicas.
	leases *ratelimit.Leases

	mu   sync.Mutex
	orgs map[ids.OrgID]*orgWatch
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
	return &Hub{
		pool: pool, log: log, now: time.Now, done: make(chan struct{}), pollEvery: PollEvery, leases: ratelimit.NewLeases(pool, log),
		orgs: map[ids.OrgID]*orgWatch{},
	}
}

// ForgetOnNotify makes every pc_containment notification also forget the
// org's cached certificate checks in svc (G0 M19 D201, HR-492). Call it
// before Run.
func (h *Hub) ForgetOnNotify(svc *Service) *Hub {
	h.notified = svc.ForgetOrg
	return h
}

// Done closes when the hub stops or the stream's lease is lost; the stream
// ends with it.
func (s *Subscription) Done() <-chan struct{} { return s.done }

// Subscription is one stream's view of its gateway's containment.
type Subscription struct {
	hub     *Hub
	org     ids.OrgID
	gateway ids.UUID
	cert    ids.UUID
	ch      chan struct{}
	w       *orgWatch
	lease   *ratelimit.Lease
	done    chan struct{}
	closed  chan struct{}
}

// Subscribe opens a view for a gateway certificate. It takes one of the
// certificate's MaxStreamsPerCert leases first; if the leases cannot be
// read, the stream is refused.
func (h *Hub) Subscribe(id Identity) (*Subscription, error) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseWithin)
	defer cancel()
	lease, err := h.leases.Acquire(ctx, id.Org, ratelimit.LeaseContainmentStream, id.Cert.String(), MaxStreamsPerCert)
	if errors.Is(err, ratelimit.ErrLeaseLimit) {
		return nil, ErrTooManyStreams
	} else if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	w, ok := h.orgs[id.Org]
	if !ok {
		ctx, cancel := context.WithCancel(context.Background())
		w = &orgWatch{subs: map[*Subscription]struct{}{}, wake: make(chan struct{}, 1), stop: cancel, gateways: map[ids.UUID]Containment{}}
		h.orgs[id.Org] = w
		go h.poll(ctx, id.Org, w)
	}
	s := &Subscription{
		hub: h, org: id.Org, gateway: id.Gateway, cert: id.Cert, ch: make(chan struct{}, 1), w: w, lease: lease,
		done: make(chan struct{}), closed: make(chan struct{}),
	}
	w.subs[s] = struct{}{}
	signal(w.wake)
	go func() {
		select {
		case <-h.done:
		case <-lease.Lost():
		case <-s.closed:
		}
		close(s.done)
	}()
	return s, nil
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Close ends the subscription and releases its lease; the org's poller
// stops with its last one.
func (s *Subscription) Close() {
	h := s.hub
	h.mu.Lock()
	if _, ok := s.w.subs[s]; !ok {
		h.mu.Unlock()
		return
	}
	delete(s.w.subs, s)
	close(s.closed)
	if len(s.w.subs) == 0 {
		s.w.stop()
		delete(h.orgs, s.org)
	}
	h.mu.Unlock()
	s.lease.Release()
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
	t := time.NewTicker(h.pollEvery)
	defer t.Stop()
	for {
		if err := h.read(ctx, org, w); err != nil && ctx.Err() == nil && !errors.Is(err, errOrgInactive) {
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
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return errOrgInactive
		} else if err != nil {
			return err
		}
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
// at once, reconnecting with backoff, until ctx ends. Each new LISTEN wakes
// every poller: a notification sent while it was down is lost (D224).
func (h *Hub) Run(ctx context.Context) error {
	defer h.doneOnce.Do(func() { close(h.done) })
	backoff := listenRetryFirst
	for ctx.Err() == nil {
		err := h.listen(ctx, func() {
			backoff = listenRetryFirst
			h.wakeAll()
		})
		if ctx.Err() != nil {
			return nil
		}
		h.log.WarnContext(ctx, "gateways.containment_listen_failed", pclog.Err(err))
		if h.listenDown != nil {
			h.listenDown()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, listenRetryMax)
	}
	return nil
}

// wakeAll wakes every org's poller.
func (h *Hub) wakeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, w := range h.orgs {
		signal(w.wake)
	}
}

// listen runs one LISTEN until it fails; listening runs once it is up.
func (h *Hub) listen(ctx context.Context, listening func()) error {
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
	listening()
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		org, err := ids.Parse[ids.Org](n.Payload)
		if err != nil {
			continue
		}
		if h.notified != nil {
			h.notified(org)
		}
		h.mu.Lock()
		if w := h.orgs[org]; w != nil {
			signal(w.wake)
		}
		h.mu.Unlock()
	}
}

// Delivered records that the stream sent its gateway epoch (G0 M10 D22):
// a containment action's gateway path is confirmed once its gateway was
// sent the action's epoch. Only a higher epoch is written, so a stream
// writes once per change, not per heartbeat.
func (s *Subscription) Delivered(ctx context.Context, epoch int64) error {
	if epoch <= 0 {
		return nil
	}
	return s.hub.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).RecordEpochDelivery(ctx, s.org, s.gateway, epoch)
	})
}
