// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "github.com/katocxl/pantherclaw/internal/connections/ports"

// m14Core is what the M14 streams' wiring builds on (G0 M14 D64): the
// stores of the postgres and a2a configurations, which the data and a2a
// wiring register (wiring_m14_data.go, wiring_m14_a2a.go).
type m14Core struct {
	kinds *ports.KindConfigs
}

// wireM14Core gives the connections and gateways services one registry of
// kind configuration stores. Until a stream registers a kind, connections
// of that kind are refused with KIND_NOT_IMPLEMENTED.
func wireM14Core(m6 *m6Services) *m14Core {
	c := &m14Core{kinds: &ports.KindConfigs{}}
	if m6 != nil {
		m6.connections.WithKindConfigs(c.kinds)
		m6.gateways.WithKindConfigs(c.kinds)
	}
	return c
}
