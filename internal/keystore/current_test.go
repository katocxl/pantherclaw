// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type countingDEKs struct {
	current, versions int
	version           uint32
	fail              bool
}

func (c *countingDEKs) CurrentDEK(context.Context, ids.OrgID, string) (uint32, pclog.Secret[[]byte], error) {
	c.current++
	if c.fail {
		return 0, pclog.Secret[[]byte]{}, errors.New("unavailable")
	}
	return c.version, pclog.NewSecret([]byte{byte(c.version)}), nil
}

func (c *countingDEKs) DEK(context.Context, ids.OrgID, string, uint32) (pclog.Secret[[]byte], error) {
	c.versions++
	return pclog.NewSecret([]byte{1}), nil
}

// TestCurrentCacheReadsTheCurrentDEKOncePerTTL: within the TTL the
// current version comes from memory; after it, from the source again, so a
// new version is used at most a TTL late. Failures are not cached, and
// versions for decryption always come from the source.
func TestCurrentCacheReadsTheCurrentDEKOncePerTTL(t *testing.T) {
	src := &countingDEKs{version: 1}
	clk := clock.NewFake(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	c := keystore.NewCurrentCache(src, time.Minute, clk)
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	ctx := context.Background()
	for range 3 {
		if v, _, err := c.CurrentDEK(ctx, org, "evaluation_inputs"); err != nil || v != 1 {
			t.Fatalf("v = %d, %v", v, err)
		}
	}
	if src.current != 1 {
		t.Fatalf("source reads = %d, want 1", src.current)
	}
	_, _, _ = c.CurrentDEK(ctx, other, "evaluation_inputs")
	_, _, _ = c.CurrentDEK(ctx, org, "payload_captures")
	if src.current != 3 {
		t.Fatalf("each org and purpose has its own entry: reads = %d", src.current)
	}
	src.version = 2
	clk.Advance(time.Minute)
	if v, _, _ := c.CurrentDEK(ctx, org, "evaluation_inputs"); v != 2 {
		t.Fatalf("after the TTL: v = %d, want 2", v)
	}
	src.fail = true
	clk.Advance(time.Minute)
	for range 2 {
		if _, _, err := c.CurrentDEK(ctx, org, "evaluation_inputs"); err == nil {
			t.Fatal("a failing source was answered from memory after the TTL")
		}
	}
	if _, err := c.DEK(ctx, org, "evaluation_inputs", 1); err != nil || src.versions != 1 {
		t.Fatalf("DEK: %v, reads %d", err, src.versions)
	}
}
