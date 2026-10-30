// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Lease timing (G0 M19 D201): a holder renews its lease every
// LeaseHeartbeat; a lease not renewed for LeaseExpiry no longer counts.
const (
	LeaseHeartbeat = 10 * time.Second
	LeaseExpiry    = 30 * time.Second
)

// LeaseKind names what a lease caps (pc.stream_leases.kind).
type LeaseKind string

// Lease kinds.
const (
	// LeaseOpsStream: operations streams per caller.
	LeaseOpsStream LeaseKind = "OPS_STREAM"
	// LeaseContainmentStream: containment streams per gateway certificate.
	LeaseContainmentStream LeaseKind = "CONTAINMENT_STREAM"
	// LeaseWait: wait handles per instance.
	LeaseWait LeaseKind = "WAIT"
)

// ErrLeaseLimit refuses a lease when the key already has its maximum.
var ErrLeaseLimit = errors.New("ratelimit: the key has its maximum of leases")

// Leases caps concurrent streams and waits per key across every replica
// (pc.stream_leases, HR-491). A lease is inserted when a stream or wait
// opens and the key's live leases are counted in the same transaction,
// under a transaction lock of the key; it is renewed every LeaseHeartbeat
// on the database's clock and deleted on release. A replica that dies
// leaves leases that expire after LeaseExpiry.
type Leases struct {
	pool   *db.Pool
	log    *slog.Logger
	holder string
	// heartbeat is LeaseHeartbeat; tests shorten it.
	heartbeat time.Duration
}

// NewLeases returns the lease store over pool. Each Leases is one holder
// (a replica's process).
func NewLeases(pool *db.Pool, log *slog.Logger) *Leases {
	if log == nil {
		log = pclog.Discard()
	}
	return &Leases{pool: pool, log: log, holder: ids.NewV7().String(), heartbeat: LeaseHeartbeat}
}

// Acquire takes one of key's limit leases of kind in org. It returns
// ErrLeaseLimit when the key has limit live leases already; any other error
// means nothing is known, and the caller refuses (fail closed).
func (l *Leases) Acquire(ctx context.Context, org ids.OrgID, kind LeaseKind, key string, limit int) (*Lease, error) {
	if key == "" || len(key) > 256 || limit < 1 {
		return nil, ErrKey
	}
	x := &Lease{
		l: l, org: org, kind: kind, key: key, id: ids.NewV7(), stop: make(chan struct{}), done: make(chan struct{}),
		lost: make(chan struct{}),
	}
	err := l.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockStreamLeaseKey(ctx, org.UUID(), string(kind), key); err != nil {
			return err
		}
		if _, err := q.DeleteExpiredStreamLeases(ctx, org); err != nil {
			return err
		}
		n, err := q.CountStreamLeases(ctx, org, string(kind), key)
		if err != nil {
			return err
		}
		if int(n) >= limit {
			return ErrLeaseLimit
		}
		return q.InsertStreamLease(ctx, dbq.InsertStreamLeaseParams{
			OrgID: org, Kind: string(kind), Key: key, ID: x.id, Holder: l.holder, TtlSeconds: LeaseExpiry.Seconds(),
		})
	})
	if errors.Is(err, ErrLeaseLimit) {
		return nil, ErrLeaseLimit
	} else if err != nil {
		return nil, fmt.Errorf("ratelimit: lease: %w", err)
	}
	go x.renew() //nolint:gosec,contextcheck // G118: the lease outlives the request that took it; Release stops the goroutine
	return x, nil
}

// Lease is one held slot; Release it when the stream or wait ends.
type Lease struct {
	l    *Leases
	org  ids.OrgID
	kind LeaseKind
	key  string
	id   ids.UUID

	once sync.Once
	stop chan struct{}
	done chan struct{}
	lost chan struct{}
}

// Lost closes when the lease expired before it was renewed (the database
// was out of reach for LeaseExpiry): its slot may be someone else's now,
// so the holder ends its stream.
func (x *Lease) Lost() <-chan struct{} { return x.lost }

// renew renews the lease every heartbeat until it is released or lost.
func (x *Lease) renew() {
	defer close(x.done)
	t := time.NewTicker(x.l.heartbeat)
	defer t.Stop()
	for {
		select {
		case <-x.stop:
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), x.l.heartbeat)
		var n int64
		err := x.l.pool.InTenantTx(ctx, x.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			n, err = dbq.New(tx).RenewStreamLease(ctx, dbq.RenewStreamLeaseParams{
				OrgID: x.org, Kind: string(x.kind), Key: x.key, ID: x.id, TtlSeconds: LeaseExpiry.Seconds(),
			})
			return err
		})
		cancel()
		switch {
		case err != nil:
			// Try again at the next beat; the lease lapses after LeaseExpiry.
			x.l.log.Warn("ratelimit.lease_renew_failed", slog.String("kind", string(x.kind)), pclog.Err(err))
		case n == 0:
			x.l.log.Warn("ratelimit.lease_lost", slog.String("kind", string(x.kind)))
			close(x.lost)
			return
		}
	}
}

// Release ends the lease and deletes it. It is safe to call more than
// once; a delete that fails leaves a lease that expires after LeaseExpiry.
func (x *Lease) Release() {
	x.once.Do(func() {
		close(x.stop)
		<-x.done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := x.l.pool.InTenantTx(ctx, x.org, func(ctx context.Context, tx db.TenantTx) error {
			return dbq.New(tx).DeleteStreamLease(ctx, dbq.DeleteStreamLeaseParams{OrgID: x.org, Kind: string(x.kind), Key: x.key, ID: x.id})
		}); err != nil {
			x.l.log.Warn("ratelimit.lease_release_failed", slog.String("kind", string(x.kind)), pclog.Err(err))
		}
	})
}
