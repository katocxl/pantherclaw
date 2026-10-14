// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"strings"
	"testing"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR222_NoticesFromSimulatedActivityAreLabeled (D6): a notice marked
// simulated, or about a simulated connection, starts its title with
// [SIMULATED]; one about a real connection does not.
func TestHR222_NoticesFromSimulatedActivityAreLabeled(t *testing.T) {
	e := newEnv(t)
	gw, sim, real := ids.NewV7(), ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", e.org, gw)
	for id, simulated := range map[ids.UUID]bool{sim: true, real: false} {
		e.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
			created_by, updated_by, simulated) VALUES ($1, $2, $3, 'http', $4, 'pc.mock-payments', 'http://127.0.0.1:9000',
			'none', 'enforce', 'test', 'test', $5)`, e.org, id, "c-"+id.String()[24:], gw, simulated)
	}
	title := func(dedupe string) string {
		var s string
		if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT title FROM pc.notifications WHERE dedupe_key = $1", dedupe).Scan(&s)
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	params := map[string]string{"connection": "x", "count": "1"}
	e.enqueue(t, napp.Message{Type: "security.effect_without_receipt", Params: params, DedupeKey: "marked", Simulated: true})
	e.enqueue(t, napp.Message{
		Type: "security.effect_without_receipt", Params: params, DedupeKey: "sim-subject",
		Subject: &napp.Subject{Type: "connection", ID: sim},
	})
	e.enqueue(t, napp.Message{
		Type: "security.effect_without_receipt", Params: params, DedupeKey: "real-subject",
		Subject: &napp.Subject{Type: "connection", ID: real},
	})
	e.enqueue(t, napp.Message{Type: "security.effect_without_receipt", Params: params, DedupeKey: "plain"})
	for key, want := range map[string]bool{"marked": true, "sim-subject": true, "real-subject": false, "plain": false} {
		if got := strings.HasPrefix(title(key), domain.SimulatedPrefix); got != want {
			t.Errorf("%s: title %q, prefixed=%v, want %v", key, title(key), got, want)
		}
	}
}

func TestSimulatedTitleStaysWithinTheTitleLimit(t *testing.T) {
	long := strings.Repeat("é", domain.MaxTitle)
	if got := []rune(domain.SimulatedTitle(long)); len(got) != domain.MaxTitle || !strings.HasPrefix(string(got), domain.SimulatedPrefix) {
		t.Fatalf("title of %d characters", len(got))
	}
}
