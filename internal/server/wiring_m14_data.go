// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"net/http"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// wireM14Data registers the postgres kind's configuration store (G0 M14
// D15, D64, D84): with it, postgres connections can be created, and their
// gateways receive the endpoint and manifest a person confirmed. internal
// is refused on a connection a PantherClaw-hosted gateway serves (D98).
func wireM14Data(c *m14Core, m6 *m6Services) {
	if c == nil {
		return
	}
	c.kinds.Register(capp.KindPostgres, pgmanifest.Store{Hosted: pgHosted(m6)})
}

// pgHosted reports whether PantherClaw hosts a gateway: the configured
// list (gateways.pantherclaw_hosted), which may be empty (D121). Without
// the M6 services nothing says which gateways it hosts, and the nil it
// returns then refuses internal everywhere.
func pgHosted(m6 *m6Services) func(ids.UUID) bool {
	if m6 == nil || m6.gateways == nil {
		return nil
	}
	return m6.gateways.PantherClawHosted
}

// postgresManifests is the confirm page's service (D84).
func postgresManifests(d apiDeps) *pgmanifest.Service {
	svc := pgmanifest.New(d.pool)
	svc.Hosted = pgHosted(d.m6)
	return svc
}

// mountM14Data adds the postgres manifest confirm page (D84).
func mountM14Data(mux *http.ServeMux, d apiDeps) {
	if d.web != nil {
		svc := postgresManifests(d)
		d.web.MountPostgresManifests(mux, svc)
		probeM14("m14.postgres.manifests", svc)
	}
}
