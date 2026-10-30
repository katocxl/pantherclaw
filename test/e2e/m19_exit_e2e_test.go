// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
)

// TestE2E_M19_Exit is M19's exit journey (G0 M19 exit criteria, D225), one
// path per feature on one stack. The held budget row goes through the
// running gateway and server. The shared limit and the stream lease run two
// in-process replicas of their services against the stack's database, which
// is what they share. Failover has its own run (`task failover`), since CI
// does not run it.
//
// Covers: PN-010.7, PN-011.1
func TestE2E_M19_Exit(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	t.Run("a held budget row is retried, not refused", func(t *testing.T) {
		if code, r := s.refund(t, ids.NewV7(), "5.01"); code != http.StatusOK || r.Outcome != "ACCEPTED" {
			t.Fatalf("the first refund prepares the row: %d %+v", code, r)
		}
		release := holdBudgetRows(t, s)
		began := time.Now()
		type answer struct {
			code int
			r    reply
			err  error
		}
		done := make(chan answer, 1)
		go func() {
			code, r, err := s.tryRefund(ids.NewV7(), "5.02")
			done <- answer{code, r, err}
		}()
		time.Sleep(150 * time.Millisecond) // past the 100 ms budget lock timeout
		release()
		a := <-done
		if a.err != nil || a.code != http.StatusOK || a.r.Outcome != "ACCEPTED" {
			t.Fatalf("held 150 ms: %d %+v %v, want accepted", a.code, a.r, a.err)
		}
		if took := time.Since(began); took < 100*time.Millisecond {
			t.Fatalf("answered after %s: the row was never waited on", took)
		}
	})

	t.Run("shared limits hold across two replicas", func(t *testing.T) {
		ctx := context.Background()
		const replicas, limit = 2, 160
		store := ratelimit.NewStore(s.pool)
		rs := [replicas]*ratelimit.Leased{ratelimit.NewLeased(store, clock.System{}), ratelimit.NewLeased(store, clock.System{})}
		allowed := 0
		for i := range 2 * limit {
			d, err := rs[i%replicas].Take(ctx, "api.org", s.org.String(), time.Hour, 1, limit)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed {
				allowed++
			}
		}
		if k := ratelimit.ChunkSize(limit); allowed > limit || allowed < limit-(replicas-1)*k {
			t.Fatalf("%d allowed across %d replicas with a limit of %d (chunk %d)", allowed, replicas, limit, k)
		}
	})

	t.Run("a stream lease is enforced across replicas", func(t *testing.T) {
		a, b := gwapp.NewHub(s.pool, nil), gwapp.NewHub(s.pool, nil)
		id := gwapp.Identity{Org: s.org, Gateway: ids.NewV7(), Cert: ids.NewV7()}
		var open []*gwapp.Subscription
		defer func() {
			for _, sub := range open {
				sub.Close()
			}
		}()
		for i := range gwapp.MaxStreamsPerCert {
			hub := a
			if i%2 == 1 {
				hub = b
			}
			sub, err := hub.Subscribe(id)
			if err != nil {
				t.Fatalf("stream %d: %v", i, err)
			}
			open = append(open, sub)
		}
		for _, hub := range []*gwapp.Hub{a, b} {
			if _, err := hub.Subscribe(id); !errors.Is(err, gwapp.ErrTooManyStreams) {
				t.Fatalf("past the cap: %v, want refused on either replica", err)
			}
		}
		open[0].Close() // on a; its slot frees on b
		sub, err := b.Subscribe(id)
		if err != nil {
			t.Fatalf("after a close on the other replica: %v", err)
		}
		open[0] = sub
	})
}

// gatewayLog is where a gateway of the stack logs.
func (s *stack) gatewayLog() *slog.Logger {
	if !s.logGateways {
		return pclog.Discard()
	}
	return slog.New(slog.NewJSONHandler(&s.gatewayLogs, nil))
}

// holdBudgetRows locks the org's budget rows until the returned func runs.
func holdBudgetRows(t *testing.T, s *stack) func() {
	t.Helper()
	locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
			if _, err := tx.Exec(ctx, "UPDATE pc.budget_accounts SET reserved = reserved"); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-done:
		t.Fatalf("hold the budget rows: %v", err)
	}
	return func() {
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
