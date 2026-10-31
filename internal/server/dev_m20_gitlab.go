// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcgitlab "github.com/katocxl/pantherclaw/packages/pc-gitlab"
)

// devGitLabConnectionName is the seeded agent-side GitLab connection.
const devGitLabConnectionName = "gitlab"

// seedGitLabAgentConnection creates the development connection through
// which agents work with merge requests with pc.gitlab (G0 M20 D254):
// targetURL is the GitLab instance (pantherclaw-sim gitlab), its host the
// only one the token is bound to, the access token is held by the gateway
// (a person seals it with pclaw seal), and the gateway is the provider of
// the merge request facts, which it reads before each merge. DEVELOPMENT
// ONLY.
func seedGitLabAgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string) (capp.Connection, error) {
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devGitLabConnectionName, Kind: capp.KindHTTP, Package: pcgitlab.Name, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: devClass(targetURL), AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: gitlab connection: %w", err)
	}
	if err := seedGatewayFactProvider(ctx, pool, org, gateway, c.ID, "gitlab.gateway"); err != nil {
		return capp.Connection{}, fmt.Errorf("dev: gitlab facts: %w", err)
	}
	return c, nil
}
