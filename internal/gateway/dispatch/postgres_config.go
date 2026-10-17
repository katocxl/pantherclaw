// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// postgresOf is a postgres connection's configuration from the gateway's
// configuration (G0 M14 D64), or nil without one: the dispatch then fails
// closed. Until the configuration carries it, no connection has one.
func postgresOf(*control.Connection) *pb.PostgresConfig { return nil }

// sendPostgres is the dispatch of kind postgres; it joins the kind
// registry with core's final A2 (G0 M14 D75).
var _ = (*Engine).sendPostgres
