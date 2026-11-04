// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmodel"
)

// wireM29Model registers the model kind's configuration store (G0 M29
// D811): model connections can then be created, their settings saved in
// the creating transaction, and gateways get them with the connection.
func wireM29Model(core *m14Core) {
	if core == nil {
		return
	}
	core.kinds.Register(capp.KindModel, pgmodel.Store{})
}
