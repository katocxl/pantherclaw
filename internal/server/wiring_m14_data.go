// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"net/http"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
)

// wireM14Data registers the postgres kind's configuration store (G0 M14
// D15, D64, D84): with it, postgres connections can be created, and their
// gateways receive the endpoint and manifest a person confirmed. internal
// is refused on a connection a PantherClaw-hosted gateway serves (D98).
func wireM14Data(c *m14Core, m6 *m6Services) {
	if c == nil {
		return
	}
	store := pgmanifest.Store{}
	if m6 != nil && m6.gateways != nil {
		store.Hosted = m6.gateways.PantherClawHosted
	}
	c.kinds.Register(capp.KindPostgres, store)
}

// mountM14Data adds the postgres manifest confirm page (D84).
func mountM14Data(mux *http.ServeMux, d apiDeps) {
	if d.web != nil {
		manifests := pgmanifest.New(d.pool)
		d.web.MountPostgresManifests(mux, manifests)
		probeM14("m14.postgres.manifests", manifests)
	}
}
