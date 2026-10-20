// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// m14Core is what the M14 streams' wiring builds on (G0 M14 D64): the
// stores of the postgres and a2a configurations, which the data and a2a
// wiring register (wiring_m14_data.go, wiring_m14_a2a.go).
type m14Core struct {
	kinds *ports.KindConfigs
}

// wireM14Core gives the connections and gateways services one registry of
// kind configuration stores. Until a stream registers a kind, connections
// of that kind are refused with KIND_NOT_IMPLEMENTED.
func wireM14Core(m6 *m6Services) *m14Core {
	c := &m14Core{kinds: &ports.KindConfigs{}}
	if m6 != nil {
		m6.connections.WithKindConfigs(c.kinds)
		m6.gateways.WithKindConfigs(c.kinds)
	}
	probeM14("m14.kinds", c.kinds)
	return c
}

// wireM14Process gives the process's one grants service (the automations
// core's, shared by the API, jobs and workers) the licence, in every
// role, so data scope in grants is gated by edition (G0 M14 D11).
func wireM14Process(core *automationsCore, bill *billing.Service) {
	if core != nil && core.grants != nil && bill != nil {
		core.grants.Editions = bill
	}
	if core != nil {
		probeM14("m14.grants.process", core.grants)
	}
}

// wireM14Grants gates data scope in issued and revised grants by the
// licence (G0 M14 D11); a nil edition source refuses them.
func wireM14Grants(grants *grantsapp.Service, d apiDeps) {
	if grants != nil && d.billing != nil {
		grants.Editions = d.billing
	}
	probeM14("m14.grants.api", grants)
}

func init() {
	// Publishing a data scope rule needs the Team edition (D11).
	policyGateExtensions = append(policyGateExtensions, func(d apiDeps, v *policyapp.Versions) {
		if d.billing != nil {
			v.Editions = d.billing
		}
		probeM14("m14.policy.versions", v)
	})
}
