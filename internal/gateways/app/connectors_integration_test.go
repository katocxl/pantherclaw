// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// TestHR084_APantherClawHostedGatewayGetsNoConnector: a customer-hosted
// gateway's configuration carries its connector connections with their
// current specs; a PantherClaw-hosted gateway's carries none, whatever the
// database holds (G0 M9 decision 7).
func TestHR084_APantherClawHostedGatewayGetsNoConnector(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, customer := e.enroll(t, "customer")
	_, hosted := e.enroll(t, "hosted")
	e.svc.WithPantherClawHosted([]ids.UUID{hosted.Gateway})
	connector := func(gw ids.UUID) ids.UUID {
		id := ids.NewV7()
		e.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, access_mode, created_by, updated_by)
			VALUES ($1, $2, $3, 'mcp_container', $4, $5, 'none', 'test', 'test')`, e.org, id, "c-"+id.String()[28:], gw, mockpayments.Name)
		for rev := 1; rev <= 2; rev++ {
			e.exec(t, `INSERT INTO pc.connector_specs (org_id, connection_id, revision, image, command, memory_mib, milli_cpus, pids, created_by)
				VALUES ($1, $2, $3, $4, ARRAY['/server', $5], 512, 1000, 256, 'test')`, e.org, id, rev,
				"sha256:"+"ab"+"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", "--rev"+string(rune('0'+rev)))
		}
		e.exec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE id = $1", gw)
		return id
	}
	mine, theirs := connector(customer.Gateway), connector(hosted.Gateway)
	ctx := context.Background()

	cfg, err := e.svc.Configuration(ctx, customer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Connections) != 1 || cfg.Connections[0].ID != mine || len(cfg.Connectors) != 1 || cfg.Connectors[0].ConnectionID != mine ||
		cfg.Connectors[0].Revision != 2 || cfg.Connectors[0].Command[1] != "--rev2" {
		t.Fatalf("customer-hosted: %d connections, connectors %+v", len(cfg.Connections), cfg.Connectors)
	}
	cfg, err = e.svc.Configuration(ctx, hosted, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cfg.Connections {
		if c.ID == theirs {
			t.Fatal("a PantherClaw-hosted gateway got a connector connection")
		}
	}
	if len(cfg.Connectors) != 0 || !e.svc.PantherClawHosted(hosted.Gateway) || e.svc.PantherClawHosted(customer.Gateway) {
		t.Fatalf("PantherClaw-hosted: connectors %+v", cfg.Connectors)
	}
}
