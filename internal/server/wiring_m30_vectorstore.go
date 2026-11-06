// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgvectorstore"
)

// wireM30Vectorstore registers the vectorstore kind's configuration store
// (G0 M30 D922-D925a): vectorstore connections can then be created, their
// settings saved in the creating transaction, and gateways get them with
// the connection. internal is refused on a connection a PantherClaw-hosted
// gateway serves, as for postgres.
func wireM30Vectorstore(core *m14Core, m6 *m6Services) {
	if core == nil {
		return
	}
	core.kinds.Register(capp.KindVectorstore, pgvectorstore.Store{Hosted: pgHosted(m6)})
}
