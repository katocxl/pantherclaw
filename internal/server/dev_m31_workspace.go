// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcgmail "github.com/katocxl/pantherclaw/packages/pc-gmail"
	pcgoogleworkspace "github.com/katocxl/pantherclaw/packages/pc-google-workspace"
	pcm365 "github.com/katocxl/pantherclaw/packages/pc-m365"
)

// The seeded agent-side Google and Microsoft 365 connections (G0 M31 D956).
const (
	devGoogleWorkspaceConnectionName = "google-workspace"
	devM365ConnectionName            = "m365"
	devGmailConnectionName           = "gmail"
)

// seedGmailAgentConnection creates the development connection through which
// agents send and read Gmail with pc.gmail (G0 M31 D956): targetURL is the
// Google API base (pantherclaw-sim google), its host the only one the
// credential is bound to, and the service account key is held by the
// gateway, which mints a token for the sealed subject on every dispatch.
// DEVELOPMENT ONLY.
func seedGmailAgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string) (capp.Connection, error) {
	return seedBearerAgentConnection(ctx, cfg, pool, org, gateway, targetURL, devGmailConnectionName, pcgmail.Name)
}

// seedGoogleWorkspaceAgentConnection creates the development connection
// through which agents work in Google Drive and Calendar with
// pc.google-workspace (G0 M31 D956): targetURL is the Google API base
// (pantherclaw-sim google), its host the only one the credential is bound
// to, and the service account key is held by the gateway, which mints a
// token for every dispatch (a person seals the key file with pclaw seal).
// DEVELOPMENT ONLY.
func seedGoogleWorkspaceAgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string) (capp.Connection, error) {
	return seedBearerAgentConnection(ctx, cfg, pool, org, gateway, targetURL, devGoogleWorkspaceConnectionName, pcgoogleworkspace.Name)
}

// seedM365AgentConnection creates the development connection through which
// agents work in Microsoft 365 with pc.m365 (G0 M31 D956): targetURL is the
// Graph base (pantherclaw-sim m365), its host the only one the credential is
// bound to, and the app's client secret is held by the gateway, which mints
// an app-only token for every dispatch (a person seals it with pclaw seal
// --oauth-token-url). DEVELOPMENT ONLY.
func seedM365AgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string) (capp.Connection, error) {
	return seedBearerAgentConnection(ctx, cfg, pool, org, gateway, targetURL, devM365ConnectionName, pcm365.Name)
}

// seedBearerAgentConnection creates a held http connection whose credential
// the gateway places as a bearer token. DEVELOPMENT ONLY.
func seedBearerAgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL, name, pkg string) (capp.Connection, error) {
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: name, Kind: capp.KindHTTP, Package: pkg, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: devClass(targetURL), AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: %s connection: %w", name, err)
	}
	return c, nil
}
