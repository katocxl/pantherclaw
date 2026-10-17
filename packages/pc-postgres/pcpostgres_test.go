// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcpostgres_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
)

// TestPackage_Loads: the embedded package decodes and validates, every
// definition is a scoped read with a SQL dispatch, and each has an MCP
// tool and an HTTP route (D17).
func TestPackage_Loads(t *testing.T) {
	p, err := manifest.Decode(pcpostgres.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pcpostgres.Name || p.Version != pcpostgres.Version {
		t.Fatalf("package %s %s", p.Name, p.Version)
	}
	ops := map[string]string{"postgres.rows.read": "rows", "postgres.rows.aggregate": "aggregate", "postgres.tables.read": "tables"}
	for i := range p.Definitions {
		d := &p.Definitions[i]
		want, ok := ops[d.Operation]
		if !ok || d.Access != domain.AccessRead || d.Dispatch == nil || d.Dispatch.SQL == nil || d.Dispatch.SQL.Operation != want ||
			d.Response == nil || len(d.Scoping) == 0 {
			t.Errorf("%s: %+v", d.Operation, d)
		}
		delete(ops, d.Operation)
		channels := map[domain.Channel]bool{}
		for _, m := range d.Mappings {
			channels[m.Channel] = true
		}
		if !channels[domain.ChannelMCP] || !channels[domain.ChannelHTTP] {
			t.Errorf("%s: channels %v", d.Operation, channels)
		}
	}
	if len(ops) != 0 {
		t.Errorf("missing %v", ops)
	}
}
