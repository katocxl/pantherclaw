// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// CurrentCache is a crypto.DEKSource that remembers each (org, purpose)'s
// current DEK for TTL, so a hot path does not read it in a transaction of
// its own every time: the Authority seals every evaluation's replay inputs
// (G0 M7 design decision 22). A DEK retired meanwhile keeps sealing for at
// most TTL; what it sealed stays readable, because DEK returns any stored
// version.
type CurrentCache struct {
	src   pccrypto.DEKSource
	ttl   time.Duration
	clock clock.Clock

	mu sync.Mutex
	m  map[currentRef]currentDEK
}

type currentRef struct {
	org     ids.OrgID
	purpose string
}

type currentDEK struct {
	version uint32
	key     pclog.Secret[[]byte]
	until   time.Time
}

var _ pccrypto.DEKSource = (*CurrentCache)(nil)

// NewCurrentCache returns a CurrentCache over src.
func NewCurrentCache(src pccrypto.DEKSource, ttl time.Duration, c clock.Clock) *CurrentCache {
	return &CurrentCache{src: src, ttl: ttl, clock: c, m: map[currentRef]currentDEK{}}
}

// CurrentDEK implements crypto.DEKSource.
func (c *CurrentCache) CurrentDEK(ctx context.Context, org ids.OrgID, purpose string) (uint32, pclog.Secret[[]byte], error) {
	ref, now := currentRef{org, purpose}, c.clock.Now()
	c.mu.Lock()
	d, ok := c.m[ref]
	c.mu.Unlock()
	if ok && now.Before(d.until) {
		return d.version, d.key, nil
	}
	version, key, err := c.src.CurrentDEK(ctx, org, purpose)
	if err != nil {
		return 0, pclog.Secret[[]byte]{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxCachedDEKs {
		clear(c.m)
	}
	c.m[ref] = currentDEK{version: version, key: key, until: now.Add(c.ttl)}
	return version, key, nil
}

// DEK implements crypto.DEKSource.
func (c *CurrentCache) DEK(ctx context.Context, org ids.OrgID, purpose string, version uint32) (pclog.Secret[[]byte], error) {
	return c.src.DEK(ctx, org, purpose, version)
}
