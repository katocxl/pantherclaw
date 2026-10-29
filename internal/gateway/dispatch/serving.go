// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import "github.com/katocxl/pantherclaw/internal/gateway/control"

// Serving states a status report carries (G0 M15 D10).
const (
	ServingOK               = "SERVING"
	ServingCircuitOpen      = "CIRCUIT_OPEN"
	ServingDriftQuarantined = "DRIFT_QUARANTINED"
	ServingNotLoaded        = "NOT_LOADED"
)

// ServingState says whether the engine serves conn now: its circuit is
// open, the last drift check of its revision found a drifted tool, its
// package did not load, or it is served. It only reads.
func (e *Engine) ServingState(conn *control.Connection) string {
	if conn.Package == nil {
		return ServingNotLoaded
	}
	e.breaker.mu.Lock()
	c := e.breaker.circuits[conn.GetId()]
	open := c != nil && c.open && (conn.GetRevision() <= c.revision || conn.GetState() != "ACTIVE")
	e.breaker.mu.Unlock()
	if open {
		return ServingCircuitOpen
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if d, ok := e.drift[conn.GetId()]; ok && d.revision == conn.GetRevision() && len(d.tools) > 0 {
		return ServingDriftQuarantined
	}
	return ServingOK
}
