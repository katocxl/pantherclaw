// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"encoding/json/v2"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// connectorOf is a connector's spec as its gateway receives it (G0 M9
// track C).
func connectorOf(s dbq.PcConnectorSpec) *pantherclawv1.ConnectorSpec {
	out := &pantherclawv1.ConnectorSpec{
		Image: s.Image, Command: s.Command, CredentialPlaceholders: s.CredentialPlaceholders, Revision: s.Revision,
		Limits: &pantherclawv1.ConnectorLimits{MemoryMib: s.MemoryMib, MilliCpus: s.MilliCpus, Pids: s.Pids},
	}
	_ = json.Unmarshal(s.Environment, &out.Environment)
	if s.EgressConnectionID != nil {
		out.EgressConnectionId = s.EgressConnectionID.String()
	}
	return out
}

// hosting is who runs a gateway, from the server's configuration alone.
func hosting(pantherclaw bool) pantherclawv1.GatewayHosting {
	if pantherclaw {
		return pantherclawv1.GatewayHosting_GATEWAY_HOSTING_PANTHERCLAW
	}
	return pantherclawv1.GatewayHosting_GATEWAY_HOSTING_CUSTOMER
}
