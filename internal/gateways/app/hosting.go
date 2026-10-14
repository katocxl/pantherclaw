// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// kindMCPContainer is a connector connection's kind (G0 M9 track C).
const kindMCPContainer = "mcp_container"

// WithPantherClawHosted names the gateways PantherClaw hosts. It comes from
// the server's configuration only, never from a tenant or a gateway
// (decision 7); their configuration carries no connector (HR-084).
func (s *Service) WithPantherClawHosted(gateways []ids.UUID) *Service {
	s.hosted = map[ids.UUID]bool{}
	for _, g := range gateways {
		s.hosted[g] = true
	}
	return s
}

// PantherClawHosted reports whether PantherClaw hosts a gateway.
func (s *Service) PantherClawHosted(gateway ids.UUID) bool { return s.hosted[gateway] }

// withoutConnectors drops connector connections from a PantherClaw-hosted
// gateway's configuration, whatever the database holds (HR-084).
func (s *Service) withoutConnectors(gateway ids.UUID, conns []dbq.PcConnection) []dbq.PcConnection {
	if !s.hosted[gateway] {
		return conns
	}
	out := conns[:0]
	for _, c := range conns {
		if c.Kind != kindMCPContainer {
			out = append(out, c)
		}
	}
	return out
}
