// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	bapp "github.com/katocxl/pantherclaw/internal/behavior/app"
	"github.com/katocxl/pantherclaw/internal/behavior/simhistory"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// TestE2E_M27_SimulatedIncidentDetectedExplainedContained is M27's exit
// journey (G0 M27 D502, D514). A range agent gets a fortnight of labelled,
// generated history; the rollup builds its SIMULATED profile, and when the
// agent then uses a tool it never used, behaviour analytics raise a test
// alert: labelled inference, UNVALIDATED, at most ALERT, never a CONFIRMED
// alert. The stack's server shows the alert and explains it with the
// agent's profile, and a person contains the run. Nothing contained it
// automatically.
// Covers: F930, F931, F932, F933, F935
func TestE2E_M27_SimulatedIncidentDetectedExplainedContained(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", billing: true, people: &p})
	activePlan(t, s.pool, s.org)
	ctx := context.Background()

	// The behaviour procedures are mounted and refuse an anonymous caller.
	for _, path := range []string{
		"/pantherclaw.v1.BehaviorService/GetAgentProfile",
		"/pantherclaw.v1.BehaviorService/GetBehaviorContext",
	} {
		r, err := http.NewRequest(http.MethodPost, s.apiURL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}

	// A security admin signs in.
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", org); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	admin := people.user(t, "m27-admin", "m27-admin@example.test")
	admin.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	adminID := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'm27-admin'")
	if code, o, e := admin.pclaw(t, "role", "bind", "--role", "security_admin", "--user", adminID); code != 0 {
		t.Fatalf("role bind: %d %s %s", code, o, e)
	}
	admin.login(t, org, "")
	rc := connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, admin)},
	}, s.apiURL))
	behavior := pantherclawv1connect.NewBehaviorServiceClient(rc)
	incidents := pantherclawv1connect.NewIncidentServiceClient(rc)
	response := pantherclawv1connect.NewResponseServiceClient(rc)

	// A range agent and its simulated run, beside the seeded real one.
	agent, run := ids.NewV7(), ids.NewV7()
	inOrg := func(sql string, args ...any) {
		t.Helper()
		if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	inOrg(`INSERT INTO pc.agents (org_id, id, name, state, created_by, range_agent) VALUES ($1, $2, 'm27-range', 'DISCOVERED', 'test', true)`, s.org, agent)
	inOrg(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at, simulated)
		SELECT org_id, $2, $3, environment_id, launcher_user_id, principal_user_id, principal_source, now() + interval '1 hour', true
		FROM pc.runs WHERE org_id = $1 AND id = $4`, s.org, run, agent, s.run)

	// Before any rollup the profile is NOT_COLLECTED, never zero.
	prof, err := behavior.GetAgentProfile(ctx, &pantherclawv1.GetAgentProfileRequest{
		AgentId: agent.String(), Origin: pantherclawv1.BehaviorOrigin_BEHAVIOR_ORIGIN_SIMULATED,
	})
	if err != nil || prof.GetProfile().GetState() != pantherclawv1.BehaviorProfileState_BEHAVIOR_PROFILE_STATE_NOT_COLLECTED {
		t.Fatalf("before the rollup: %+v %v", prof, err)
	}

	// Labelled generated history, then the rollup starts collection.
	if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := simhistory.Store(ctx, tx, simhistory.Spec{
			Agent: agent, DestClass: "INTERNAL", Operations: []string{"repo.read", "repo.write"},
			Days: 14, RunsPerDay: 3, Hour: time.Now().UTC().Hour(), End: time.Now(), Seed: 935,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	roll := &bapp.Rollup{Pool: s.pool, Ents: ents{billing.Business}, Raiser: &alerts.Raiser{}, Failures: &failures.Sink{}, Settle: time.Nanosecond}
	if res, err := roll.Run(ctx, s.org); err != nil || res.Signals != 0 {
		t.Fatalf("first rollup: %+v %v", res, err)
	}

	// The incident: the agent uses a tool it never used.
	inOrg(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, mode, simulated)
		VALUES ($1, $2, $3, $4, $5, 'secrets.dump', 'ALLOW', 'R', 'gw', 'enforce', true)`, s.org, ids.NewV7(), run, ids.NewV7(), make([]byte, 32))
	if res, err := roll.Run(ctx, s.org); err != nil || res.Signals == 0 {
		t.Fatalf("second rollup: %+v %v", res, err)
	}

	// Detected: the server lists the alert, a labelled test inference.
	listed, err := incidents.ListAlerts(ctx, &pantherclawv1.ListAlertsRequest{RuleId: "pc.drift.behavior.new_tool"})
	if err != nil || len(listed.GetAlerts()) != 1 {
		t.Fatalf("alerts: %+v %v", listed, err)
	}
	alert := listed.GetAlerts()[0]
	if alert.GetBasis() != "INFERRED" || !alert.GetTest() || alert.GetAttention() == "INCIDENT" || alert.GetAttention() == "PAGE" ||
		alert.GetIncidentId() != "" || !strings.HasPrefix(alert.GetTitle(), "SIMULATED: ") ||
		!strings.Contains(alert.GetSummary(), "unvalidated") ||
		!slices.ContainsFunc(alert.GetSubjects(), func(x *pantherclawv1.ReflexSubject) bool {
			return x.GetType() == "agent" && x.GetId() == agent.String()
		}) {
		t.Fatalf("alert %+v", alert)
	}

	// Explained: the profile says what the agent usually does, and that it
	// is inference on unvalidated thresholds.
	prof, err = behavior.GetAgentProfile(ctx, &pantherclawv1.GetAgentProfileRequest{
		AgentId: agent.String(), Origin: pantherclawv1.BehaviorOrigin_BEHAVIOR_ORIGIN_SIMULATED,
	})
	if err != nil {
		t.Fatal(err)
	}
	pr := prof.GetProfile()
	if pr.GetState() != pantherclawv1.BehaviorProfileState_BEHAVIOR_PROFILE_STATE_COLLECTED || pr.GetBasis() != "INFERRED" ||
		pr.GetDefinitionStatus() != "UNVALIDATED" || pr.GetLabel() == "" || pr.GetActiveDays() < 14 ||
		!slices.ContainsFunc(pr.GetTools(), func(x *pantherclawv1.BehaviorTool) bool { return x.GetOperation() == "repo.read" }) {
		t.Fatalf("profile %+v", pr)
	}
	// A real profile of a range agent is never built from simulated work.
	real, err := behavior.GetAgentProfile(ctx, &pantherclawv1.GetAgentProfileRequest{
		AgentId: agent.String(), Origin: pantherclawv1.BehaviorOrigin_BEHAVIOR_ORIGIN_REAL,
	})
	if err != nil || real.GetProfile().GetState() != pantherclawv1.BehaviorProfileState_BEHAVIOR_PROFILE_STATE_NOT_COLLECTED {
		t.Fatalf("real profile of a range agent: %+v %v", real, err)
	}

	// Nothing contained it automatically; a person contains the run.
	if n := s.row(t, "SELECT count(*)::text FROM pc.response_actions WHERE org_id = $1", s.org.String()); n != "0" {
		t.Fatalf("%s response actions before the person", n)
	}
	contained, err := response.Contain(ctx, &pantherclawv1.ContainRequest{
		Scope: &pantherclawv1.ResponseSubject{Type: "run", Id: run.String()}, Control: "DENY_ALL",
		Reason: "simulated incident: a tool the agent never used",
	})
	if err != nil || contained.GetActionId() == "" {
		t.Fatalf("Contain: %+v %v", contained, err)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.response_actions WHERE org_id = $1 AND scope_id = $2 AND source = 'PERSON'",
		s.org.String(), run.String()); n != "1" {
		t.Fatalf("person's containment rows = %s", n)
	}
}
