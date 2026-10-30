// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package ratelimit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// leaseReplicas is two replicas (two pools, two holders) on one database,
// with an org.
func leaseReplicas(t *testing.T) (a, b *Leases, org ids.OrgID, exec func(sql string, args ...any)) {
	t.Helper()
	d := dbtest.New(t)
	pa, pb := d.AppPool(t), d.AppPool(t)
	org = ids.New[ids.Org]()
	exec = func(sql string, args ...any) {
		t.Helper()
		if err := pa.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'leases')", org)
	return NewLeases(pa, nil), NewLeases(pb, nil), org, exec
}

// TestHR491_CapsHoldAcrossReplicas: two replicas taking leases of one key
// concurrently hold at most max between them; a released lease frees its
// slot on the other replica; other keys and kinds are separate.
// Covers: HR-491, T-214
func TestHR491_CapsHoldAcrossReplicas(t *testing.T) {
	a, b, org, _ := leaseReplicas(t)
	ctx := context.Background()
	const max = 4
	replicas := []*Leases{a, b}
	var (
		mu   sync.Mutex
		held []*Lease
		refd atomic.Int32
		wg   sync.WaitGroup
	)
	for i := range 20 {
		wg.Go(func() {
			l, err := replicas[i%2].Acquire(ctx, org, LeaseOpsStream, "principal-1", max)
			switch {
			case errors.Is(err, ErrLeaseLimit):
				refd.Add(1)
			case err != nil:
				t.Error(err)
			default:
				mu.Lock()
				held = append(held, l)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(held) != max || refd.Load() != 20-max {
		t.Fatalf("%d leases held across two replicas (%d refused), want %d", len(held), refd.Load(), max)
	}
	if _, err := a.Acquire(ctx, org, LeaseOpsStream, "principal-2", max); err != nil {
		t.Fatalf("another key: %v", err)
	}
	if _, err := a.Acquire(ctx, org, LeaseWait, "principal-1", max); err != nil {
		t.Fatalf("another kind: %v", err)
	}
	held[0].Release()
	held[0].Release() // twice is safe
	l, err := b.Acquire(ctx, org, LeaseOpsStream, "principal-1", max)
	if err != nil {
		t.Fatalf("after a release on the other replica: %v", err)
	}
	if _, err := a.Acquire(ctx, org, LeaseOpsStream, "principal-1", max); !errors.Is(err, ErrLeaseLimit) {
		t.Fatalf("the freed slot was taken again: %v", err)
	}
	l.Release()
	for _, l := range held[1:] {
		l.Release()
	}
}

// TestHR491_AnExpiredLeaseFreesItsSlot: a replica that died leaves leases
// that stop counting once they expire; a lease that expired is lost to its
// holder at its next renewal, and a live one is renewed.
// Covers: HR-491
func TestHR491_AnExpiredLeaseFreesItsSlot(t *testing.T) {
	a, b, org, exec := leaseReplicas(t)
	a.heartbeat, b.heartbeat = 100*time.Millisecond, 100*time.Millisecond
	ctx := context.Background()
	dead, err := a.Acquire(ctx, org, LeaseContainmentStream, "cert-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(ctx, org, LeaseContainmentStream, "cert-1", 1); !errors.Is(err, ErrLeaseLimit) {
		t.Fatalf("a live lease on the other replica: %v", err)
	}
	// Replica a stops renewing (it died) and its lease passes its expiry.
	close(dead.stop)
	<-dead.done
	exec("UPDATE pc.stream_leases SET expires_at = now() - interval '1 second' WHERE id = $1", dead.id)
	l, err := b.Acquire(ctx, org, LeaseContainmentStream, "cert-1", 1)
	if err != nil {
		t.Fatalf("after the dead replica's lease expired: %v", err)
	}
	// The live lease is renewed past its expiry by its heartbeats.
	exec("UPDATE pc.stream_leases SET expires_at = now() + interval '200 milliseconds' WHERE id = $1", l.id)
	time.Sleep(500 * time.Millisecond)
	select {
	case <-l.Lost():
		t.Fatal("a renewed lease was lost")
	default:
	}
	if _, err := a.Acquire(ctx, org, LeaseContainmentStream, "cert-1", 1); !errors.Is(err, ErrLeaseLimit) {
		t.Fatalf("the renewed lease stopped counting: %v", err)
	}
	// A lease that lapsed is lost at its next renewal.
	exec("UPDATE pc.stream_leases SET expires_at = now() - interval '1 second' WHERE id = $1", l.id)
	select {
	case <-l.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("a lapsed lease was never reported lost")
	}
	l.Release()
}

// TestHR491_LeaseTiming: a lease lives LeaseExpiry on the database's clock
// and is renewed every LeaseHeartbeat (D201).
// Covers: HR-491
func TestHR491_LeaseTiming(t *testing.T) {
	if LeaseHeartbeat != 10*time.Second || LeaseExpiry != 30*time.Second {
		t.Fatalf("heartbeat %v, expiry %v; want 10s and 30s", LeaseHeartbeat, LeaseExpiry)
	}
	a, _, org, _ := leaseReplicas(t)
	l, err := a.Acquire(context.Background(), org, LeaseWait, "instance-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	var left float64
	if err := a.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT extract(epoch FROM expires_at - now()) FROM pc.stream_leases WHERE id = $1", l.id).Scan(&left)
	}); err != nil {
		t.Fatal(err)
	}
	if left < 25 || left > 30.5 {
		t.Fatalf("a new lease expires in %.1fs, want about 30s", left)
	}
}

// TestHR491_AStoreErrorRefuses: a lease that cannot be counted is refused.
// Covers: HR-491
func TestHR491_AStoreErrorRefuses(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	l := NewLeases(p, nil)
	p.Close()
	if x, err := l.Acquire(context.Background(), ids.New[ids.Org](), LeaseWait, "k", 1); err == nil || errors.Is(err, ErrLeaseLimit) || x != nil {
		t.Fatalf("a closed pool: %v %v", x, err)
	}
}

// TestT214_ACallerSpreadAcrossReplicasIsBounded: a caller that spreads its
// API calls and its streams over two replicas gets no more than one
// replica would give it: the leased API limit stays within its bound, and
// the stream cap holds in total.
// Covers: T-214, HR-490, HR-491
func TestT214_ACallerSpreadAcrossReplicasIsBounded(t *testing.T) {
	d := dbtest.New(t)
	pa, pb := d.AppPool(t), d.AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	if err := pa.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 't214')", org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	const limit = 48
	limiters := []*Leased{NewLeased(NewStore(pa), nil), NewLeased(NewStore(pb), nil)}
	key := org.String() + "/key:" + ids.NewV7().String()
	allowed := 0
	for i := range 3 * limit {
		dec, err := limiters[i%2].Take(ctx, "api.credential", key, time.Hour, 1, limit)
		if err != nil {
			t.Fatal(err)
		}
		if dec.Allowed {
			allowed++
		}
	}
	if k := ChunkSize(limit); allowed > limit+k {
		t.Fatalf("%d calls admitted across two replicas, the bound is %d", allowed, limit+k)
	}
	leases := []*Leases{NewLeases(pa, nil), NewLeases(pb, nil)}
	var held []*Lease
	for i := range 10 {
		l, err := leases[i%2].Acquire(ctx, org, LeaseOpsStream, "principal", 5)
		if errors.Is(err, ErrLeaseLimit) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		held = append(held, l)
	}
	if len(held) != 5 {
		t.Fatalf("%d streams held across two replicas, the cap is 5", len(held))
	}
	for _, l := range held {
		l.Release()
	}
}
