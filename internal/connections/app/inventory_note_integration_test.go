// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR582_ANoteChangesNothing: what an operator reports from `pclaw mcp
// inspect --submit` lands on the item as their word, with their name, and the
// item's state and flags stay as they are.
// Covers: F871, F869
func TestHR582_ANoteChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	c := e.upstreamConn(t, "upstream")
	entry := app.InventoryEntry{Kind: app.InventoryTool, Name: "bad", Digest: digest("aa"), Description: "x <!-- y -->"}
	if _, err := e.svc.ReportInventory(context.Background(), e.org, e.gateway, app.InventoryReport{Connection: c.ID, Entries: []app.InventoryEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	id := e.itemID(t, c.ID, "bad")
	flags := e.flagsOn(t, id, "OPEN")
	if len(flags) == 0 {
		t.Fatal("no flags to keep")
	}
	row, err := e.svc.AddInventoryNote(e.admin, id, "pclaw mcp inspect: Result: no known flags")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "NEW" || row.OperatorNote == "" || row.OperatorNoteBy == nil || row.OperatorNoteAt == nil {
		t.Fatalf("%+v", row)
	}
	if got := e.flagsOn(t, id, "OPEN"); len(got) != len(flags) {
		t.Errorf("flags %v, were %v", got, flags)
	}
	for name, note := range map[string]string{"empty": "", "long": strings.Repeat("x", app.MaxInventoryNote+1), "not UTF-8": "\xff"} {
		if _, err := e.svc.AddInventoryNote(e.admin, id, note); !errors.Is(err, app.ErrInventoryNote) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.AddInventoryNote(e.admin, ids.NewV7(), "x"); !errors.Is(err, app.ErrInventoryNotFound) {
		t.Errorf("no such item: %v", err)
	}
}
