// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR200_ToolObservationsAreRecordedOnlyThroughTheReportingGateway: an
// observation a gateway reports is kept with the run, instance, tool and
// input digest, never the input; one for a connection the gateway does not
// serve, or of another org, is not recorded.
func TestHR200_ToolObservationsAreRecordedOnlyThroughTheReportingGateway(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	agent, run := e.agentRun(t, "coder")
	instance := ids.NewV7()
	e.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, e.org, instance, agent, instance.String()[:36]+"0000000")
	digest := bytes.Repeat([]byte{9}, 32)
	o := app.ToolObservation{Run: run, Instance: instance, Connection: c.ID, Tool: "Read", InputSHA256: digest}
	id, err := e.svc.RecordToolObservation(t.Context(), e.org, e.gateway, o)
	if err != nil || id.IsZero() {
		t.Fatalf("record: %v", err)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.tool_observations WHERE id = $1 AND tool = 'Read' AND channel = 'sdk'
		AND input_sha256 = $2 AND instance_id = $3`, id, digest, instance); n != 1 {
		t.Fatalf("recorded %d rows", n)
	}
	if _, err := e.svc.RecordToolObservation(t.Context(), e.org, ids.NewV7(), o); !is(err, app.ErrNotServed) {
		t.Errorf("another gateway: %v", err)
	}
	other := e.withOrg(t)
	if _, err := e.svc.RecordToolObservation(t.Context(), other.org, other.gateway, o); !is(err, app.ErrNotServed) {
		t.Errorf("another org: %v", err)
	}
}
