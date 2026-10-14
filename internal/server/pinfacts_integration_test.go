// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR160_AQuarantinedOrRetiredPinNamesNoFacts (#299 review follow-up):
// a gateway provider may report the facts of its connection's pinned
// package only while that version is active; once it is quarantined or
// retired it names none, so the gateway's reports are refused.
func TestHR160_AQuarantinedOrRetiredPinNamesNoFacts(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI, gatewayAt("127.0.0.1:8443"))
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{
		"dev", "seed", "--config", cfgPath, "--gateway-out", filepath.Join(dir, "gw.json"),
		"--github-url", "http://127.0.0.1:9",
	}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("dev seed = %d %s", code, errb.String())
	}
	m := seededOrg.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("dev seed output %q", out.String())
	}
	org, err := ids.Parse[ids.Org](m[1])
	if err != nil {
		t.Fatal(err)
	}
	pool := d.AppPool(t)
	ctx := context.Background()
	var gw, conn ids.UUID
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT gateway_id, id FROM pc.connections WHERE name = 'github'").Scan(&gw, &conn)
	}); err != nil {
		t.Fatal(err)
	}
	named := packageFacts(pool)
	if facts, err := named(ctx, org, gw, conn); err != nil || len(facts["github.pull.head"]) == 0 {
		t.Fatalf("an active pin: %v %v", facts, err)
	}
	for _, state := range []string{"QUARANTINED", "RETIRED"} {
		d.AdminExec(t, `UPDATE pc.package_versions v SET state = $2 FROM pc.tool_packages p
			WHERE v.org_id = $1 AND p.org_id = v.org_id AND p.id = v.package_id AND p.name = 'pc.github'`, org, state)
		if _, err := named(ctx, org, gw, conn); !errors.Is(err, factsapp.ErrConnectionUnknown) {
			t.Errorf("a %s pin: %v", state, err)
		}
	}
}
