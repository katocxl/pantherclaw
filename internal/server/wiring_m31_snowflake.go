// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/sfmanifest"
)

// wireM31Snowflake registers the snowflake kind's configuration store (G0
// M31 D962): snowflake connections can then be created, their manifest
// proposed in the creating transaction, and gateways get the confirmed one
// with the connection.
func wireM31Snowflake(core *m14Core) {
	if core == nil {
		return
	}
	core.kinds.Register(capp.KindSnowflake, sfmanifest.Store{})
}
