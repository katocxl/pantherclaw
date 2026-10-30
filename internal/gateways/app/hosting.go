// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// kindMCPContainer is a connector connection's kind (G0 M9 track C).
const kindMCPContainer = "mcp_container"

// WithPantherClawHosted names the gateways PantherClaw hosts in the
// server's configuration, never from a tenant or a gateway (decision 7);
// their configuration carries no connector (HR-084). Since G0 M19 D203 the
// hosted gateway records (migration 00229) name them too; the configured
// list stays as a fallback for one release.
func (s *Service) WithPantherClawHosted(gateways []ids.UUID) *Service {
	s.hosted = map[ids.UUID]bool{}
	for _, g := range gateways {
		s.hosted[g] = true
	}
	return s
}

// PantherClawHosted reports whether the configured list names a gateway.
func (s *Service) PantherClawHosted(gateway ids.UUID) bool { return s.hosted[gateway] }

// hostedIn reports, in the caller's transaction, whether PantherClaw hosts
// a gateway: the configured list, or a hosted gateway record that names it,
// whatever its state, so a gateway once hosted never takes connectors.
func (s *Service) hostedIn(ctx context.Context, q *dbq.Queries, org ids.OrgID, gateway ids.UUID) (bool, error) {
	if s.hosted[gateway] {
		return true, nil
	}
	return q.IsHostedGateway(ctx, org, gateway)
}

// withoutConnectors drops connector connections from a PantherClaw-hosted
// gateway's configuration, whatever the database holds (HR-084).
func withoutConnectors(hosted bool, conns []dbq.PcConnection) []dbq.PcConnection {
	if !hosted {
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
