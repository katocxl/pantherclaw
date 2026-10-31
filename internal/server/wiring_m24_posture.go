// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
)

// postureSourceFactory builds one source of the ranked posture queue.
type postureSourceFactory func(pool *db.Pool, ents exapp.Entitlements) ports.Source

// postureSourceFactories are the queue's sources (G0 M24 D204). A stream
// that owns a source adds it from an init in its own wiring file:
//
//	func init() { postureSourceFactories = append(postureSourceFactories, newMySource) }
var postureSourceFactories []postureSourceFactory

// postureSources builds every source.
func postureSources(pool *db.Pool, ents exapp.Entitlements) []ports.Source {
	out := make([]ports.Source, 0, len(postureSourceFactories))
	for _, f := range postureSourceFactories {
		out = append(out, f(pool, ents))
	}
	return out
}
