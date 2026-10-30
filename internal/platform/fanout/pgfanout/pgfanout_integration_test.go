// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgfanout_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/fanout"
	"github.com/katocxl/pantherclaw/internal/platform/fanout/pgfanout"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestIntFanoutDeliversAtCommitOnly: a payload published in a committed
// transaction reaches the subscriber; one from a rolled-back transaction
// never does.
func TestIntFanoutDeliversAtCommitOnly(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	bus := pgfanout.New(pool, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 4)
	done := make(chan error, 1)
	go func() { done <- bus.Subscribe(ctx, "pc_fanout_test", func(p string) { got <- p }) }()

	publish := func(payload string, rollback bool) {
		t.Helper()
		errRollback := errors.New("rollback")
		err := pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
			if err := bus.Publish(ctx, tx, "pc_fanout_test", payload); err != nil {
				return err
			}
			if rollback {
				return errRollback
			}
			return nil
		})
		if err != nil && !(rollback && errors.Is(err, errRollback)) {
			t.Fatal(err)
		}
	}
	// The LISTEN starts asynchronously: publish until the first arrives.
	deadline := time.After(10 * time.Second)
	for first := false; !first; {
		publish("hello", false)
		select {
		case p := <-got:
			first = p == "hello"
		case <-time.After(200 * time.Millisecond):
		case <-deadline:
			t.Fatal("no notification delivered")
		}
	}
	for len(got) > 0 {
		<-got
	}
	publish("rolled-back", true)
	publish("committed", false)
	select {
	case p := <-got:
		if p != "committed" {
			t.Fatalf("delivered %q, want only the committed payload", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("committed payload not delivered")
	}
	if err := bus.Publish(ctx, nil, "bad channel", ""); !errors.Is(err, fanout.ErrInvalid) {
		t.Fatalf("bad channel: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Subscribe after cancel = %v", err)
	}
}
