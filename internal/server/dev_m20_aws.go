// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcawsecs "github.com/katocxl/pantherclaw/packages/pc-aws-ecs"
)

// devAWSECSConnectionName is the seeded agent-side ECS connection.
const devAWSECSConnectionName = "aws-ecs"

// seedAWSECSAgentConnection creates the development connection through which
// agents deploy with pc.aws.ecs (G0 M20 D286): targetURL is the ECS endpoint
// (pantherclaw-sim aws), its host the only one the credential is bound to,
// the base key is held by the gateway (a person seals it with pclaw seal),
// and the gateway is the provider of the deployment controller fact, which
// it reads before each deploy. DEVELOPMENT ONLY.
func seedAWSECSAgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string) (capp.Connection, error) {
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devAWSECSConnectionName, Kind: capp.KindHTTP, Package: pcawsecs.Name, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: devClass(targetURL), AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		CredentialHeader: creddomain.AWSSigV4Header, CredentialScheme: creddomain.AWSSigV4Scheme,
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: aws-ecs connection: %w", err)
	}
	if err := seedGatewayFactProvider(ctx, pool, org, gateway, c.ID, "awsecs.gateway"); err != nil {
		return capp.Connection{}, fmt.Errorf("dev: aws-ecs facts: %w", err)
	}
	return c, nil
}
