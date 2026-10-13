// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"time"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// devGitHubConnectionName is the development GitHub connection: agents call
// the gateway at /github/repos/… and /mcp/github (G0 M8).
const devGitHubConnectionName = "github"

// githubOperations are the pc.github operations the seeded grant allows
// with --github-url: reading, branching, writing, opening and merging pull
// requests, and the deployment a merge can start (a consequence, never
// called directly).
var githubOperations = []string{
	"github.contents.read", "github.contents.write", "github.branch.create", "github.pull.read", "github.pull.create",
	"github.pull.merge", "github.deployment.trigger",
}

// seedGitHubConnection creates the development GitHub connection to
// targetURL (the GitHub simulator), held by the gateway: a person seals the
// GitHub App's key for it (pclaw seal --github-app), and the gateway mints
// a token per action (HR-203, HR-204). Its routes enforce. DEVELOPMENT
// ONLY.
func seedGitHubConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string) (capp.Connection, error) {
	class := capp.ClassPublic
	if u, err := url.Parse(targetURL); err == nil {
		if a, isIP := httpx.HostAddr(u.Hostname()); isIP && (a.IsPrivate() || a.IsLoopback()) {
			class = capp.ClassInternal
		}
	}
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devGitHubConnectionName, Kind: capp.KindHTTP, Package: pcgithub.Name, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: class, AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: github connection: %w", err)
	}
	return c, nil
}

// seedGitHubFacts registers the gateway serving the GitHub connection as the
// provider of every fact pc.github names (G0 M8 decision 5): the gateway
// reads them from GitHub before each decision. DEVELOPMENT ONLY.
func seedGitHubFacts(ctx context.Context, pool *db.Pool, org ids.OrgID, gateway, conn ids.UUID) error {
	named, err := packageFacts(pool)(ctx, org, gateway, conn)
	if err != nil {
		return fmt.Errorf("dev: github facts: %w", err)
	}
	var decls []fdomain.Declaration
	for _, name := range slices.Sorted(maps.Keys(named)) {
		for _, subject := range named[name] {
			decls = append(decls, fdomain.Declaration{Name: name, Type: fdomain.TypeObject, SubjectType: subject, MaxLag: time.Minute})
		}
	}
	p := fdomain.Provider{
		ID: ids.NewV7(), Org: org, Name: "github.gateway", GatewayID: gateway, ConnectionID: conn, State: fdomain.ProviderActive, Facts: decls,
	}
	ev := audit.Event{
		Name: "facts.provider_registered", Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "fact_provider", ID: p.ID.String()},
		Details: map[string]string{"gateway": gateway.String(), "connection": conn.String(), "facts": fmt.Sprint(len(decls))},
	}
	if err := (&factspg.Store{Pool: pool}).CreateProvider(ctx, org, p, "dev-seed", ev); err != nil {
		return fmt.Errorf("dev: github facts: %w", err)
	}
	return nil
}
