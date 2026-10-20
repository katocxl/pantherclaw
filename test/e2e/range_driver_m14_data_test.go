// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// The range driver's Postgres part (G0 M14 D21, D46): RT-042..044 run on a
// stack with the D19 fixture database and the seeded connection
// "warehouse", read by a run whose grant limits it to customer 2's records
// and to public data.

// pgCapabilities are the Postgres capabilities this driver offers.
func pgCapabilities() map[app.Capability]bool {
	return map[app.Capability]bool{"pg.query": true, "pg.role_swap": true}
}

// needsPostgres reports whether a scenario runs on the fixture database.
func needsPostgres(sc domain.Scenario) bool {
	return requires(sc, "pg.query") || requires(sc, "pg.role_swap")
}

// pgRangeScope is the grant scope of the range's postgres run.
const pgRangeScope = `{"postgres.rows.read": {"records": {"key": "customer", "values": ["2"]}, "classes": {"ids": ["public"]}},
  "postgres.rows.aggregate": {"records": {"key": "customer", "values": ["2"]}, "classes": {"ids": ["public"]}}}`

// setupPostgres makes the fixture database answer the simulated-connection
// handshake (D110), since the range marks every connection simulated, and
// gives the scenario a run on the scoped grant.
func (d *rangeDriver) setupPostgres() {
	d.s.pg.tg.SimHandshake(d.t, d.s.pg.conn.String())
	d.s.scopedRun(d.t, pgRangeScope)
	d.defaultRun = d.s.run
}

// mutatePostgres changes the database the connection reads: write_grant
// lets the connection's role write a manifest table, as a careless DBA
// would, and the gateway gets a fresh credential version, so its next
// query opens a new pool and checks the role again (RT-044).
func (d *rangeDriver) mutatePostgres(change string, args jsontext.Value) (domain.Observation, error) {
	var a struct {
		WriteGrant bool `json:"write_grant"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return domain.Observation{}, err
	}
	if change != "fault" || !a.WriteGrant {
		return domain.Observation{}, fmt.Errorf("sim.mutate postgres %s %s", change, args)
	}
	tg := d.s.pg.tg
	tg.AdminExec(d.t, "GRANT INSERT, UPDATE ON shop.orders TO "+tg.ReadOnly)
	d.s.sealPostgres(d.t, tg.ReadOnlyPass)
	return domain.Observation{}, nil
}
