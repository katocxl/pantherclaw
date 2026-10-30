// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"time"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcjira "github.com/katocxl/pantherclaw/packages/pc-jira"
)

// devJiraConnectionName is the seeded agent-side Jira connection.
const devJiraConnectionName = "jira"

// seedJiraAgentConnection creates the development connection through which
// agents work in Jira with pc.jira (G0 M20 D254): targetURL is the Jira site
// (pantherclaw-sim jira), its host the only one the credential is bound to,
// the Basic credential is held by the gateway (a person seals base64 of
// email:api-token with pclaw seal), and the gateway is the provider of
// jira.project.external, which it reads before each write. DEVELOPMENT
// ONLY.
func seedJiraAgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string) (capp.Connection, error) {
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devJiraConnectionName, Kind: capp.KindHTTP, Package: pcjira.Name, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: devClass(targetURL), AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		CredentialHeader: "Authorization", CredentialScheme: "Basic",
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: jira connection: %w", err)
	}
	if err := seedGatewayFactProvider(ctx, pool, org, gateway, c.ID, "jira.gateway"); err != nil {
		return capp.Connection{}, fmt.Errorf("dev: jira facts: %w", err)
	}
	return c, nil
}

// devClass is a development target's destination class: internal for a
// private or loopback address, else public.
func devClass(targetURL string) string {
	if u, err := url.Parse(targetURL); err == nil {
		if a, isIP := httpx.HostAddr(u.Hostname()); isIP && (a.IsPrivate() || a.IsLoopback()) {
			return capp.ClassInternal
		}
	}
	return capp.ClassPublic
}

// seedGatewayFactProvider registers the gateway as the provider of every
// fact the connection's package names, for each target type that names it.
// DEVELOPMENT ONLY.
func seedGatewayFactProvider(ctx context.Context, pool *db.Pool, org ids.OrgID, gateway, conn ids.UUID, name string) error {
	named, err := packageFacts(pool)(ctx, org, gateway, conn)
	if err != nil {
		return err
	}
	var decls []fdomain.Declaration
	for _, fact := range slices.Sorted(maps.Keys(named)) {
		for _, subject := range named[fact] {
			decls = append(decls, fdomain.Declaration{Name: fact, Type: fdomain.TypeObject, SubjectType: subject, MaxLag: time.Minute})
		}
	}
	p := fdomain.Provider{
		ID: ids.NewV7(), Org: org, Name: name, GatewayID: gateway, ConnectionID: conn, State: fdomain.ProviderActive, Facts: decls,
	}
	ev := audit.Event{
		Name: "facts.provider_registered", Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "fact_provider", ID: p.ID.String()},
		Details: map[string]string{"gateway": gateway.String(), "connection": conn.String(), "facts": strconv.Itoa(len(decls))},
	}
	return (&factspg.Store{Pool: pool}).CreateProvider(ctx, org, p, "dev-seed", ev)
}
