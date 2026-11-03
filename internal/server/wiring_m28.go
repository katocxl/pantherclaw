// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// registerM28ThreatMap serves ThreatMapService (G0 M28 D721). Until the
// evaluator lands every procedure answers Unimplemented; the procedure
// permissions and classes are in procedures_m28_threatmap.go.
func registerM28ThreatMap(rs *connect.Server, _ apiDeps) {
	pantherclawv1connect.RegisterThreatMapServiceHandler(rs, pantherclawv1connect.UnimplementedThreatMapServiceHandler{})
}
