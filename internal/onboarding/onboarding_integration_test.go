// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package onboarding_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/onboarding"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type fixture struct {
	d    *dbtest.DB
	pool *db.Pool
	n    int
}

func (f *fixture) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// world is one org with a user (developer), an environment and a gateway.
type world struct {
	org  ids.OrgID
	user ids.UUID
	env  ids.UUID
}

func (f *fixture) world(t *testing.T) world {
	t.Helper()
	w := world{org: ids.New[ids.Org](), user: ids.NewV7(), env: ids.NewV7()}
	f.exec(t, w.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", w.org)
	f.exec(t, w.org, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://idp.test', $3, 'u@example.test')`, w.org, w.user, w.user.String())
	f.exec(t, w.org, `INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'prod', 'Prod', 'PRODUCTION')`, w.org, w.env)
	return w
}

func (w world) ctx() context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.user}, Bindings: []td.Binding{
			{Role: td.RoleDeveloper, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}},
		}},
		Credential: tapp.CredBrowserSession,
	})
}

// agent adds an agent (a range agent when simulated) with an admitted
// instance, a run and one transaction per decision; it returns the agent.
func (f *fixture) agent(t *testing.T, w world, simulated bool, decisions ...string) ids.UUID {
	t.Helper()
	f.n++
	agent, inst, run := ids.NewV7(), ids.NewV7(), ids.NewV7()
	f.exec(t, w.org, `INSERT INTO pc.agents (org_id, id, name, state, created_by, range_agent) VALUES ($1, $2, $3, 'DISCOVERED', 'test', $4)`,
		w.org, agent, fmt.Sprintf("agent-%d", f.n), simulated)
	jkt := strings.Repeat("A", 42) + string(rune('a'+f.n))
	f.exec(t, w.org, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via, decided_at)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery', now())`, w.org, inst, agent, jkt)
	f.exec(t, w.org, `INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, principal_source, expires_at, simulated,
		launcher_user_id, principal_user_id)
		VALUES ($1, $2, $3, $4, $5, 'launcher', now() + interval '1 hour', $6, $7, $7)`, w.org, run, agent, inst, w.env, simulated, w.user)
	for i, d := range decisions {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", run, i)))
		f.exec(t, w.org, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, simulated) VALUES ($1, $2, $3, $4, $5, 'test.op', $6, 'TEST', 'gw', $7)`,
			w.org, ids.NewV7(), run, ids.NewV7(), h[:], d, simulated)
	}
	f.exec(t, w.org, `INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor, reason) VALUES ($1, $2, $3, 'agent.suspended', 'test', 'test')`,
		w.org, ids.NewV7(), agent)
	f.exec(t, w.org, `INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor, reason) VALUES ($1, $2, $3, 'agent.restored', 'test', 'test')`,
		w.org, ids.NewV7(), agent)
	return agent
}

func progress(t *testing.T, s *onboarding.Service, w world) map[onboarding.StepID]onboarding.Step {
	t.Helper()
	p, err := s.GetProgress(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != len(onboarding.Order) {
		t.Fatalf("%d steps", len(p.Steps))
	}
	out := map[onboarding.StepID]onboarding.Step{}
	for _, st := range p.Steps {
		out[st.ID] = st
	}
	return out
}

// TestHR364_SimulatedRecordsNeverCompleteAStep: range agents, simulated
// runs and transactions leave every agent step to do.
func TestHR364_SimulatedRecordsNeverCompleteAStep(t *testing.T) {
	f := &fixture{d: dbtest.New(t)}
	f.pool = f.d.AppPool(t)
	s := onboarding.New(f.pool)
	w := f.world(t)
	f.agent(t, w, true, "ALLOW", "DENY", "REQUIRE_APPROVAL")
	for id, st := range progress(t, s, w) {
		if st.Done() {
			t.Errorf("%s done by simulated records: %+v", id, st.Evidence)
		}
	}
	agent := f.agent(t, w, false, "ALLOW", "DENY", "REQUIRE_APPROVAL")
	got := progress(t, s, w)
	for id, kinds := range map[onboarding.StepID][]string{
		onboarding.StepAgentEnrolled: {"agent"}, onboarding.StepFirstDecision: {"decision"},
		onboarding.StepTestAllowed: {"transaction"}, onboarding.StepTestDenied: {"transaction"},
		onboarding.StepTestHeld: {"transaction"}, onboarding.StepSuspensionTested: {"suspension"},
	} {
		st := got[id]
		if !st.Done() || len(st.Evidence) != len(kinds) || st.Evidence[0].Kind != kinds[0] {
			t.Errorf("%s = %+v, want done with %v", id, st, kinds)
		}
	}
	if got[onboarding.StepAgentEnrolled].Evidence[0].ID != agent {
		t.Error("agent step names another agent")
	}
	for _, id := range []onboarding.StepID{onboarding.StepSecurityKey, onboarding.StepInviteTeam, onboarding.StepGatewayEnrolled, onboarding.StepApprovalDecided} {
		if got[id].Done() {
			t.Errorf("%s done without its record", id)
		}
	}
}

// TestHR363_OnboardingEvidenceComesOnlyFromTheCallersOrg.
func TestHR363_OnboardingEvidenceComesOnlyFromTheCallersOrg(t *testing.T) {
	f := &fixture{d: dbtest.New(t)}
	f.pool = f.d.AppPool(t)
	s := onboarding.New(f.pool)
	mine, theirs := f.world(t), f.world(t)
	f.agent(t, theirs, false, "ALLOW", "DENY", "REQUIRE_APPROVAL")
	f.exec(t, theirs.org, `INSERT INTO pc.invitations (org_id, id, email, roles, token_hash, created_by, expires_at)
		VALUES ($1, $2, 'x@example.test', '{}', $3, 'test', now() + interval '1 day')`, theirs.org, ids.NewV7(), make([]byte, 32))
	p, err := s.GetProgress(mine.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if p.Complete {
		t.Error("complete from another org's records")
	}
	for _, st := range p.Steps {
		if st.Done() {
			t.Errorf("%s done from another org's records", st.ID)
		}
	}
	if got := progress(t, s, theirs); !got[onboarding.StepInviteTeam].Done() {
		t.Error("the other org's own invitation does not count for it")
	}
}

// TestHR362_OnboardingProgressIsComputedNeverSetByAClient: the API has no
// procedure that records progress, and reading it needs onboarding.read.
func TestHR362_OnboardingProgressIsComputedNeverSetByAClient(t *testing.T) {
	declared, err := protoperms.Declared(filepath.Join("..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	for proc := range declared {
		if strings.Contains(proc, ".OnboardingService/") && !strings.HasSuffix(proc, "/GetProgress") {
			t.Errorf("OnboardingService serves %s", proc)
		}
	}
	f := &fixture{d: dbtest.New(t)}
	f.pool = f.d.AppPool(t)
	w := f.world(t)
	viewer := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.user}, Bindings: []td.Binding{
			{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}},
		}},
	})
	if _, err := onboarding.New(f.pool).GetProgress(viewer); err == nil {
		t.Error("a viewer read onboarding progress")
	}
	if _, err := onboarding.New(f.pool).GetProgress(context.Background()); err == nil {
		t.Error("progress without a caller")
	}
}

// TestHR362_OnboardingCompletesWithoutTheFollowUpSteps (D79): a person
// alone in a new org completes onboarding without inviting anyone or
// deciding an approval; those steps stay reported.
func TestHR362_OnboardingCompletesWithoutTheFollowUpSteps(t *testing.T) {
	f := &fixture{d: dbtest.New(t)}
	f.pool = f.d.AppPool(t)
	s := onboarding.New(f.pool)
	w := f.world(t)
	f.agent(t, w, false, "ALLOW", "DENY", "REQUIRE_APPROVAL")
	p, err := s.GetProgress(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if p.Complete {
		t.Fatal("complete without a security key and a gateway")
	}
	f.exec(t, w.org, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		w.org, ids.NewV7(), w.user, []byte("cred-onboarding-0123456789"), []byte("public-key-onboarding-0123456789abcdefghijklmnop"))
	gw := ids.NewV7()
	f.exec(t, w.org, `INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'gw', 'test')`, w.org, gw)
	f.exec(t, w.org, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before, not_after)
		VALUES ($1, $2, $3, '\x01', $4, 'ENROLL', now(), now() + interval '1 hour')`, w.org, ids.NewV7(), gw, strings.Repeat("k", 43))
	got := progress(t, s, w)
	p, err = s.GetProgress(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if !p.Complete {
		t.Errorf("not complete: %+v", got)
	}
	if got[onboarding.StepInviteTeam].Done() || got[onboarding.StepApprovalDecided].Done() {
		t.Error("follow-up steps done without their records")
	}
	if !got[onboarding.StepSecurityKey].Done() || got[onboarding.StepSecurityKey].Evidence[0].Kind != onboarding.KindSecurityKey {
		t.Errorf("security key step = %+v", got[onboarding.StepSecurityKey])
	}
	if len(got[onboarding.StepTestHeld].Evidence) == 0 {
		t.Error("TEST_HELD has no evidence once the hold is recorded")
	}
}
