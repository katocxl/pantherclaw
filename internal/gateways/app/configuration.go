// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Configuration is what one gateway serves (G0 M6 design decision 19).
type Configuration struct {
	Version     int64
	Unchanged   bool
	Connections []dbq.PcConnection
	Routes      []dbq.GatewayConnectionRoutesRow
	Packages    []dbq.GatewayPackagesRow
	Credentials []dbq.GatewaySealedCredentialsRow
	// GitHub are the GitHub App installations behind those connections (G0
	// M8).
	GitHub []dbq.GatewayConnectionGitHubRow
	// Captures are the active capture profiles covering those connections
	// (G0 M7 design decision 10).
	Captures []dbq.GatewayCaptureProfilesRow
	// Connectors are the current specs of its connector connections (G0
	// M9 track C); none for a PantherClaw-hosted gateway (HR-084).
	Connectors []dbq.PcConnectorSpec
	// KindConfigs are the M14 kinds' configurations of those connections,
	// by connection id (*pb.PostgresConfig, *pb.A2AConfig; G0 M14 D64).
	KindConfigs map[ids.UUID]proto.Message
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
		conns, err := q.GatewayConnections(ctx, id.Org, id.Gateway)
		if err != nil {
			return err
		}
		out.Connections = s.withoutConnectors(id.Gateway, conns)
		if out.KindConfigs, err = s.kindConfigs(ctx, tx, id.Org, out.Connections); err != nil {
			return err
		}
		if !s.hosted[id.Gateway] {
			if out.Connectors, err = q.GatewayConnectorSpecs(ctx, id.Org, id.Gateway); err != nil {
				return err
			}
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
		if out.GitHub, err = q.GatewayConnectionGitHub(ctx, id.Org, id.Gateway); err != nil {
			return err
		}
		out.Captures, err = q.GatewayCaptureProfiles(ctx, id.Org, id.Gateway)
		return err
	})
	return out, err
}
