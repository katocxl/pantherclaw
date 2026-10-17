// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
)

// wireM14A2A registers the a2a kind's configuration store (G0 M14 D30,
// D64): a2a connections can then be created, their card pinned in the
// creating transaction, and gateways get the pin with the connection.
func wireM14A2A(core *m14Core) {
	if core == nil {
		return
	}
	core.kinds.Register(capp.KindA2A, &a2astore.Adapter{Pinner: a2astore.NewPinner()})
}
