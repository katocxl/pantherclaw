// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// agentRun adds an agent named name with a run, and returns the run.
func (e *env) agentRun(t *testing.T, name string) (agent, run ids.UUID) {
	t.Helper()
	envID, user := ids.NewV7(), ids.NewV7()
	agent, run = ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, $3, 'Dev', 'DEVELOPMENT')", e.org, envID, "dev-"+name)
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, user, name+"-owner")
	e.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, $3, 'DISCOVERED', 'test')", e.org, agent, name)
	e.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, e.org, run, agent, envID, user)
	return agent, run
}

// outcome records a dispatched action of run through conn, created ago
// before now, with outcome.
func (e *env) outcome(t *testing.T, conn, run ids.UUID, outcome, ago string) {
	t.Helper()
	txn, permit := ids.NewV7(), ids.NewV7()
	e.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, mode, connection_id, created_at) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'ALLOWED', 'gw',
		'enforce', $6, now() - $7::interval)`, e.org, txn, run, ids.NewV7(), make([]byte, 32), conn, ago)
	e.exec(t, `INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, state, expires_at, dispatching_at, finished_at,
		mode, connection_id) VALUES ($1, $2, $3, $4, 1, 'DISPATCHED', now() + interval '5 seconds', now(), now(), 'enforce', $5)`,
		e.org, permit, txn, e.gateway, conn)
	e.exec(t, `INSERT INTO pc.execution_attempts (org_id, id, permit_id, transaction_id, outcome, recorded_at)
		VALUES ($1, $2, $3, $4, $5, now() - $6::interval)`, e.org, ids.NewV7(), permit, txn, outcome, ago)
}

// TestF358_ConnectionHealthShowsWhatAPersonNeeds: health shows the
// connection, its circuits, the permissions its credential is used for,
// its tests, the failed and UNKNOWN outcomes of the last 24 hours with the
// latest failure and success, and the agents that used it in the last 30
// days, latest first. A reader without agent.read sees that agents are
// hidden instead; another org's connection is NotFound.
func TestF358_ConnectionHealthShowsWhatAPersonNeeds(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	other := e.payments(t, "other")
	coder, run := e.agentRun(t, "coder")
	_, old := e.agentRun(t, "retired-bot")
	e.outcome(t, c.ID, run, "accepted", "1 hour")
	e.outcome(t, c.ID, run, "failed", "2 hours")
	e.outcome(t, c.ID, run, "unknown", "3 hours")
	e.outcome(t, c.ID, run, "failed", "2 days") // outside the delivery window
	e.outcome(t, c.ID, old, "accepted", "40 days")
	e.outcome(t, other.ID, run, "failed", "1 hour")
	if _, err := e.svc.OpenCircuit(e.admin, e.org, e.gateway, c.ID, 6, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Test(e.admin, c.ID, ""); err != nil {
		t.Fatal(err)
	}

	h, err := e.svc.Health(e.caller(td.KindUser, td.RoleGatewayAdmin), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	d := h.Deliveries
	if h.Connection.ID != c.ID || h.Connection.State != app.StateQuarantined || len(h.Circuits) != 1 || !h.Circuits[0].Open ||
		h.Circuits[0].Unknown != 6 || len(h.Permissions) != 2 || h.LastTest == nil || h.LastTest.Result != app.TestFailed ||
		h.LastPassedTest != nil || d.Failed != 1 || d.Unknown != 1 || d.LastFailure.IsZero() || d.LastSuccess.IsZero() ||
		!d.LastSuccess.After(d.LastFailure) {
		t.Fatalf("health %+v", h)
	}
	if h.AgentsHidden || len(h.Agents) != 1 || h.Agents[0].Agent != coder || h.Agents[0].Name != "coder" {
		t.Fatalf("dependent agents %+v hidden %v", h.Agents, h.AgentsHidden)
	}

	quiet := e.payments(t, "quiet")
	if h, err := e.svc.Health(e.admin, quiet.ID); err != nil || h.Deliveries.Failed != 0 || !h.Deliveries.LastFailure.IsZero() ||
		!h.Deliveries.LastSuccess.IsZero() || h.LastTest != nil || len(h.Agents) != 0 || len(h.Circuits) != 0 {
		t.Fatalf("a connection nothing used: %+v %v", h, err)
	}
	if h, err := e.svc.Health(e.caller(td.KindUser, td.RoleEmergency), c.ID); err != nil || !h.AgentsHidden || len(h.Agents) != 0 {
		t.Fatalf("without agent.read: %+v %v", h.Agents, err)
	}
	if _, err := e.svc.Health(e.caller(td.KindUser, td.RoleFactProvider), c.ID); !denied(err) {
		t.Errorf("without connection.read: %v", err)
	}
	theirs := e.withOrg(t).payments(t, "payments")
	if _, err := e.svc.Health(e.admin, theirs.ID); !is(err, app.ErrNotFound) {
		t.Errorf("another org's: %v", err)
	}
}
