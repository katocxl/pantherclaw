// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateways/app"
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

// TestHR084_AGatewayReportsOnlyItsOwnConnectorsRuns: a gateway reports the
// runs of its own connector connections, which move only forward and run
// a spec revision of their connection; another gateway's connector, a
// connection that is not a connector, or any on a PantherClaw-hosted
// gateway is not found, and a run id cannot be reused for another
// connection (G0 M9 track C, 00094).
func TestHR084_AGatewayReportsOnlyItsOwnConnectorsRuns(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, mine := e.enroll(t, "mine")
	_, theirs := e.enroll(t, "theirs")
	ctx := context.Background()
	connector := func(gw ids.UUID) ids.UUID {
		id := ids.NewV7()
		e.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, access_mode, created_by, updated_by)
			VALUES ($1, $2, $3, 'mcp_container', $4, $5, 'none', 'test', 'test')`, e.org, id, "c-"+id.String()[28:], gw, mockpayments.Name)
		e.exec(t, `INSERT INTO pc.connector_specs (org_id, connection_id, revision, image, command, memory_mib, milli_cpus, pids, created_by)
			VALUES ($1, $2, 1, $3, ARRAY['/server'], 512, 1000, 256, 'test')`, e.org, id,
			"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		return id
	}
	own, other := connector(mine.Gateway), connector(theirs.Gateway)
	run := func(instance, conn ids.UUID, rev int32, state string) error {
		_, err := e.svc.ReportConnectorState(ctx, mine, app.ConnectorRun{
			Instance: instance, Connection: conn, SpecRevision: rev, State: state, Container: "pc-conn-0123456789abcdef",
			EngineVersion: "29.8.2", APIVersion: "1.56", Runtime: "runc",
		})
		return err
	}
	first := ids.NewV7()
	for _, state := range []string{"STARTING", "RUNNING", "STOPPED"} {
		if err := run(first, own, 1, state); err != nil {
			t.Fatalf("%s: %v", state, err)
		}
	}
	if err := run(first, own, 1, "RUNNING"); !errors.Is(err, app.ErrConnectorRun) {
		t.Fatalf("a stopped run started again: %v", err)
	}
	if err := run(ids.NewV7(), own, 7, "STARTING"); !errors.Is(err, app.ErrConnectorRun) {
		t.Fatalf("a run of an unknown spec revision: %v", err)
	}
	if err := run(ids.NewV7(), other, 1, "STARTING"); !errors.Is(err, app.ErrConnectorNotFound) {
		t.Fatalf("another gateway's connector: %v", err)
	}
	second := ids.NewV7()
	if err := run(second, own, 1, "STARTING"); err != nil {
		t.Fatal(err)
	}
	if err := run(second, connector(mine.Gateway), 1, "RUNNING"); !errors.Is(err, app.ErrConnectorRun) {
		t.Fatalf("a run id reused for another connection: %v", err)
	}
	e.exec(t, `INSERT INTO pc.connector_specs (org_id, connection_id, revision, image, command, memory_mib, milli_cpus, pids, created_by)
		VALUES ($1, $2, 2, $3, ARRAY['/server'], 512, 1000, 256, 'test')`, e.org, own,
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := run(second, own, 2, "RUNNING"); !errors.Is(err, app.ErrConnectorRun) {
		t.Fatalf("a run moved to another spec revision: %v", err)
	}
	// The gateway crashes with second open; its next run closes it.
	if err := run(ids.NewV7(), own, 2, "STARTING"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.connector_instances WHERE org_id = $1 AND id = $2 AND state = 'STOPPED'
		AND last_error_class = 'superseded' AND stopped_at IS NOT NULL`, e.org, second); n != 1 {
		t.Fatal("a run a crashed gateway left open was not closed")
	}
	if err := run(second, own, 1, "RUNNING"); !errors.Is(err, app.ErrConnectorRun) {
		t.Fatalf("a superseded run reported running: %v", err)
	}
	e.svc.WithPantherClawHosted([]ids.UUID{mine.Gateway})
	if err := run(ids.NewV7(), own, 1, "STARTING"); !errors.Is(err, app.ErrConnectorNotFound) {
		t.Fatalf("a PantherClaw-hosted gateway's connector run: %v", err)
	}
}
