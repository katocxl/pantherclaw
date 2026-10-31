// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestD240_AnOmittedSchemaIsFlaggedUntilItArrives: a schema a full report left
// out raises schema_unavailable, which clears when a report brings it. The
// item stays NEW all along: a flag approves nothing.
// Covers: F868, F869
func TestD240_AnOmittedSchemaIsFlaggedUntilItArrives(t *testing.T) {
	e := newEnv(t)
	e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	c := e.upstreamConn(t, "upstream")
	ctx := context.Background()
	in := app.InventoryEntry{Kind: app.InventoryTool, Name: "long", Digest: digest("aa"), Description: "Reads.", InputSchemaDigest: digest("a0"), SchemaOmitted: true}
	if _, err := e.svc.ReportInventory(ctx, e.org, e.gateway, app.InventoryReport{Connection: c.ID, Entries: []app.InventoryEntry{in}}); err != nil {
		t.Fatal(err)
	}
	id := e.itemID(t, c.ID, "long")
	if got := e.flagsOn(t, id, "OPEN"); !slices.Contains(got, "schema_unavailable") {
		t.Fatalf("flags %v", got)
	}
	in.SchemaOmitted, in.InputSchema = false, cleanSchema
	if _, err := e.svc.ReportInventory(ctx, e.org, e.gateway, app.InventoryReport{Connection: c.ID, Entries: []app.InventoryEntry{in}}); err != nil {
		t.Fatal(err)
	}
	if got := e.flagsOn(t, id, "OPEN"); slices.Contains(got, "schema_unavailable") {
		t.Errorf("flags %v", got)
	}
	row, err := e.svc.GetInventoryItem(e.admin, id)
	if err != nil || row.State != "NEW" || row.InputSchema != cleanSchema {
		t.Fatalf("%+v %v", row, err)
	}
}

// TestD240_OmissionHasAShape: only a tool can have a schema omitted, with its
// digest and without its text.
// Covers: HR-418, F868
func TestD240_OmissionHasAShape(t *testing.T) {
	e := newEnv(t)
	e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	c := e.upstreamConn(t, "upstream")
	for name, in := range map[string]app.InventoryEntry{
		"no digest":  {Kind: app.InventoryTool, Name: "a", Digest: digest("aa"), SchemaOmitted: true},
		"with text":  {Kind: app.InventoryTool, Name: "a", Digest: digest("aa"), SchemaOmitted: true, InputSchema: cleanSchema, InputSchemaDigest: digest("a0")},
		"a resource": {Kind: app.InventoryResource, Name: "file:///a", Digest: digest("aa"), SchemaOmitted: true, InputSchemaDigest: digest("a0")},
	} {
		if _, err := e.svc.ReportInventory(context.Background(), e.org, e.gateway, app.InventoryReport{Connection: c.ID, Entries: []app.InventoryEntry{in}}); !errors.Is(err, app.ErrInventory) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestD241_TheOneReadWithTheSchema: an item reads back whole by id, and an
// unknown id is not found.
// Covers: F868
func TestD241_TheOneReadWithTheSchema(t *testing.T) {
	e := newEnv(t)
	e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	c := e.upstreamConn(t, "upstream")
	in := app.InventoryEntry{Kind: app.InventoryTool, Name: "whole", Digest: digest("aa"), Description: "Reads.", InputSchema: cleanSchema, InputSchemaDigest: digest("a0"), ListedExtra: `{"title":"T"}`}
	if _, err := e.svc.ReportInventory(context.Background(), e.org, e.gateway, app.InventoryReport{Connection: c.ID, Entries: []app.InventoryEntry{in}}); err != nil {
		t.Fatal(err)
	}
	row, err := e.svc.GetInventoryItem(e.admin, e.itemID(t, c.ID, "whole"))
	if err != nil || row.InputSchema != cleanSchema || row.ListedExtra != in.ListedExtra {
		t.Fatalf("%+v %v", row, err)
	}
	if _, err := e.svc.GetInventoryItem(e.admin, ids.NewV7()); !errors.Is(err, app.ErrInventoryNotFound) {
		t.Fatalf("%v", err)
	}
}
