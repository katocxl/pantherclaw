// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

func init() { kindSenders["postgres"] = (*Engine).sendPostgres }

// postgresOf is a postgres connection's configuration from the gateway's
// configuration (G0 M14 D64), or nil without one: the dispatch then fails
// closed.
func postgresOf(conn *control.Connection) *pb.PostgresConfig { return conn.GetPostgres() }
