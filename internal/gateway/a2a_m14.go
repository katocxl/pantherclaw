// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"github.com/katocxl/pantherclaw/internal/gateway/a2aface"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// a2aPeer returns an a2a connection's pinned peer for the A2A face (G0 M14
// D30, D31). The configuration does not carry an a2a connection's pinned
// card yet, so no connection is served (fail closed).
func a2aPeer(conn *control.Connection) (a2aface.Peer, bool) {
	if conn == nil || conn.GetKind() != "a2a" {
		return a2aface.Peer{}, false
	}
	return a2aface.Peer{}, false
}
