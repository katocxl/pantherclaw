// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	bapp "github.com/katocxl/pantherclaw/internal/behavior/app"
	"github.com/katocxl/pantherclaw/internal/behavior/simhistory"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// TestE2E_M27_SimulatedIncidentDetectedExplainedContained is M27's exit
// journey (G0 M27 D502, D514). A range agent gets a fortnight of labelled,
// generated history; the rollup builds its SIMULATED profile, and when the
// agent then uses a tool it never used, behavior analytics raise a test
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

	// The behavior procedures are mounted and refuse an anonymous caller.
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

	// An inferred alert never contains automatically, even under a containing
	// automation: a CRITICAL, non-test INFERRED alert on the real agent's run
	// starts scoped_incident_containment, whose contain step skips
	// UNCONFIRMED_SIGNAL (D514, D526 P3).
	realRun := m27InferredAlertSkipsContain(t, s, mustUUID(t, adminID))
	if n := s.row(t, "SELECT count(*)::text FROM pc.response_actions WHERE org_id = $1", s.org.String()); n != "0" {
		t.Fatalf("%s response actions before the person", n)
	}

	// A person contains the run the inferred alert names.
	listed, err = incidents.ListAlerts(ctx, &pantherclawv1.ListAlertsRequest{RuleId: m27Rule})
	if err != nil || len(listed.GetAlerts()) != 1 || listed.GetAlerts()[0].GetBasis() != "INFERRED" || listed.GetAlerts()[0].GetTest() {
		t.Fatalf("the inferred alert: %+v %v", listed, err)
	}
	var subject string
	for _, x := range listed.GetAlerts()[0].GetSubjects() {
		if x.GetType() == "run" {
			subject = x.GetId()
		}
	}
	if subject != realRun.String() {
		t.Fatalf("the alert's run %q, want %s", subject, realRun)
	}
	contained, err := response.Contain(ctx, &pantherclawv1.ContainRequest{
		Scope: &pantherclawv1.ResponseSubject{Type: "run", Id: subject}, Control: "DENY_ALL",
		Reason: "inferred alert: a person looked and contains the run",
	})
	if err != nil || contained.GetActionId() == "" {
		t.Fatalf("Contain: %+v %v", contained, err)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.response_actions WHERE org_id = $1 AND scope_id = $2 AND source = 'PERSON'",
		s.org.String(), subject); n != "1" {
		t.Fatalf("person's containment rows = %s", n)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.response_actions WHERE org_id = $1 AND source <> 'PERSON'", s.org.String()); n != "0" {
		t.Fatalf("%s containments by something other than a person", n)
	}
}

// m27Rule is the inferred alert's rule: a custom rule, which M27 caps at
// INFERRED (D526 P6).
const m27Rule = "org.m27_watch"

// m27InferredAlertSkipsContain installs scoped_incident_containment, LIVE,
// and runs its trigger and engine in the test on the stack's database, as
// M11's exit journey does: the server's feed job is held off the org and each
// execution is parked between the test's own advances. It raises a CRITICAL,
// non-test INFERRED alert on the seeded real agent's run, and requires the
// contain step to skip UNCONFIRMED_SIGNAL. It returns that run.
func m27InferredAlertSkipsContain(t *testing.T, s *stack, owner ids.UUID) ids.UUID {
	t.Helper()
	ctx := context.Background()
	// The generic and security kinds; contain's dependencies are not wired,
	// so a contain that ran would fail rather than skip.
	reg := steps.Generic(steps.Deps{})
	maps.Copy(reg, securitysteps.All(securitysteps.Deps{}))
	e, err := pgengine.New(s.pool, reg, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	trig := triggers.New(triggers.Deps{
		Pool: s.pool, Starter: parkingStarter{e: e}, Editions: ents{billing.Business}, Failures: &failures.Sink{},
		Raiser: &alerts.Raiser{},
	})
	holdFeed(t, s)
	feedAll := func() {
		t.Helper()
		for range 100 {
			if _, err := ledger.ChainAll(ctx, s.pool, s.org, 1000); err != nil {
				t.Fatal(err)
			}
			res, err := trig.ProcessFeed(ctx, s.org)
			if err != nil {
				t.Fatal(err)
			}
			if res.To == 0 {
				return
			}
		}
	}
	feedAll() // what happened before the automation existed starts nothing

	def, _, err := templates.Render("scoped_incident_containment", map[string]string{
		"review_by": time.Now().AddDate(0, 0, 30).Format(time.DateOnly),
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &triggerstest.Fixture{Pool: s.pool, Org: s.org, User: owner}
	auto := m21Enabled(t, f, "m27-containment", string(def))

	// The seeded run is a real agent's (not a range agent's).
	realRun := mustUUID(t, s.run)
	agent := s.row(t, "SELECT r.agent_id::text FROM pc.runs r JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id WHERE r.id = $1 AND NOT r.simulated AND NOT a.range_agent", s.run)
	digest := sha256.Sum256([]byte(m27Rule))
	if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := (&alerts.Raiser{}).Raise(ctx, tx.Pgx(), reflexdomain.Signal{
			Org: s.org, Source: reflexdomain.SourceDetection, RuleID: m27Rule, RuleVersion: "1",
			RuleDigest: "sha256:" + hex.EncodeToString(digest[:]), Title: "Agent read every secret",
			Summary:  "A custom rule saw the agent read every secret it can reach. Inference: a person decides.",
			Severity: reflexdomain.SeverityCritical, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisInferred,
			Subjects: []reflexdomain.Subject{
				{Type: reflexdomain.SubjectAgent, ID: agent}, {Type: reflexdomain.SubjectRun, ID: realRun.String()},
			},
			DedupeKey: "m27-exit", OccurredAt: time.Now(),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var execution string
	eventually(t, 30*time.Second, "the inferred alert to start the automation", func() (bool, error) {
		feedAll()
		execution = s.row(t, "SELECT coalesce((SELECT id::text FROM pc.automation_executions WHERE automation_id = $1 LIMIT 1), '')", auto.ID.String())
		return execution != "", nil
	})
	if basis := s.row(t, `SELECT coalesce(authenticity_detail ->> 'basis', '') || '/' || coalesce(authenticity_detail ->> 'confirmed', '') FROM pc.automation_triggers
		WHERE automation_id = $1`, auto.ID.String()); basis != "INFERRED/false" && basis != "INFERRED/" {
		t.Fatalf("the trigger's basis: %s", basis)
	}
	const contain = `SELECT coalesce((SELECT state || '/' || coalesce(reason, '') FROM pc.automation_step_attempts
		WHERE execution_id = $1 AND step_id = 'contain' ORDER BY attempt DESC LIMIT 1), '')`
	for range 6 {
		s.exec(t, "UPDATE pc.automation_executions SET wake_at = now() - interval '1 second' WHERE id = $1 AND wake_at IS NOT NULL", execution)
		s.exec(t, "UPDATE pc.automation_step_attempts SET wake_at = now() - interval '1 second' WHERE execution_id = $1 AND wake_at IS NOT NULL", execution)
		if err := e.Advance(ctx, s.org, mustUUID(t, execution)); err != nil {
			t.Fatal(err)
		}
		s.exec(t, `UPDATE pc.automation_executions SET wake_at = now() + interval '1 hour'
			WHERE id = $1 AND state IN ('PENDING', 'RUNNING', 'WAITING', 'NEEDS_RECONCILIATION')`, execution)
		if s.row(t, contain, execution) != "" {
			break
		}
	}
	if got := s.row(t, contain, execution); got != "SKIPPED/UNCONFIRMED_SIGNAL" {
		t.Fatalf("the contain step: %q", got)
	}
	return realRun
}

// holdFeed keeps the server's feed job away from the org for the rest of
// the test, as autoStack.holdServerFeed does: a job scheduled past the end
// of the test holds the org's unique slot.
func holdFeed(t *testing.T, s *stack) {
	t.Helper()
	client, err := jobs.NewClient(s.pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	args := triggers.OrgArgs{Org: s.org, Task: triggers.TaskFeed}
	eventually(t, 30*time.Second, "the server's feed job to finish", func() (bool, error) {
		res, err := client.Insert(context.Background(), args, &river.InsertOpts{ScheduledAt: time.Now().Add(time.Hour)})
		if err != nil {
			return false, err
		}
		return !res.UniqueSkippedAsDuplicate, nil
	})
}
