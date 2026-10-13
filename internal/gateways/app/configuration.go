// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// Configuration is what one gateway serves (G0 M6 design decision 19).
type Configuration struct {
	Version     int64
	Unchanged   bool
	Connections []dbq.PcConnection
	Routes      []dbq.GatewayConnectionRoutesRow
	Packages    []dbq.GatewayPackagesRow
	Credentials []dbq.GatewaySealedCredentialsRow
	// Captures are the active capture profiles covering those connections
	// (G0 M7 design decision 10).
	Captures []dbq.GatewayCaptureProfilesRow
}

// Configuration returns the calling gateway's configuration: its
// connections (active and quarantined) with their route modes, the pinned
// packages they use, and their active sealed credentials, but only those
// sealed to this gateway's broker keys (HR-182). When known is the current
// version, only the version is returned. The org and gateway come from the
// verified certificate alone (HR-020).
func (s *Service) Configuration(ctx context.Context, id Identity, known int64) (Configuration, error) {
	var out Configuration
	err := s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.GetGateway(ctx, id.Org, id.Gateway)
		if err != nil || g.State != "ACTIVE" {
			return ErrGatewayCredentials
		}
		out.Version = g.ConfigVersion
		if known == g.ConfigVersion {
			out.Unchanged = true
			return nil
		}
		if out.Connections, err = q.GatewayConnections(ctx, id.Org, id.Gateway); err != nil {
			return err
		}
		if out.Routes, err = q.GatewayConnectionRoutes(ctx, id.Org, id.Gateway); err != nil {
			return err
		}
		if out.Packages, err = q.GatewayPackages(ctx, id.Org, id.Gateway); err != nil {
			return err
		}
		if out.Credentials, err = q.GatewaySealedCredentials(ctx, id.Org, id.Gateway); err != nil {
			return err
		}
		out.Captures, err = q.GatewayCaptureProfiles(ctx, id.Org, id.Gateway)
		return err
	})
	return out, err
}
