// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation

import (
	"context"
	"sync"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// maxCachedVersions bounds a VersionCache; when full it starts over.
const maxCachedVersions = 16

// VersionCache is a replay source that reads each proposed policy version
// once, not once per replayed decision (D34). A stored version never
// changes, so a cached one never goes stale; every other read goes to the
// source. Replay only reads the bundle it is given.
type VersionCache struct {
	replay.Source

	mu       sync.Mutex
	versions map[versionKey]*pdomain.Bundle
}

type versionKey struct {
	org ids.OrgID
	id  ids.UUID
}

// PolicyVersion implements replay.Source.
func (c *VersionCache) PolicyVersion(ctx context.Context, org ids.OrgID, id ids.UUID) (*pdomain.Bundle, error) {
	k := versionKey{org, id}
	c.mu.Lock()
	b, ok := c.versions[k]
	c.mu.Unlock()
	if ok {
		return b, nil
	}
	b, err := c.Source.PolicyVersion(ctx, org, id)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.versions == nil || len(c.versions) >= maxCachedVersions {
		c.versions = map[versionKey]*pdomain.Bundle{}
	}
	c.versions[k] = b
	c.mu.Unlock()
	return b, nil
}
