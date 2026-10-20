// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

// m14Probe, when a test sets it, receives each M14 instance the server
// wires, by kind (TestM14_WiringComplete, G0 M14 D41); nil in production.
var m14Probe func(kind string, v any)

func probeM14(kind string, v any) {
	if m14Probe != nil {
		m14Probe(kind, v)
	}
}
