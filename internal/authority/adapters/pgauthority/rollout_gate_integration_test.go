// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factpg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Rollouts through the real publish gate and change requests (D6, D11,
// D12). Validation and the scenario tests stand in as passing ports (S1a's
// are tested on their own); the gate, the classification, the change
// requests and their confirmations are the real ones.

var gateDigests = [32]byte{7}

type passingPorts struct{}

func (passingPorts) Validate(context.Context, ids.OrgID, *pdomain.Bundle) (pdomain.ValidationResult, error) {
	return pdomain.ValidationResult{Passed: true, DefinitionsDigest: gateDigests, CatalogDigest: gateDigests}, nil
}

func (passingPorts) Run(context.Context, ids.OrgID, *pdomain.Bundle) (pdomain.TestResult, error) {
	return pdomain.TestResult{Passed: true, DefinitionsDigest: gateDigests, CatalogDigest: gateDigests}, nil
}

type gatedRollouts struct {
	*rolloutWorld
	versions *papp.Versions
	digests  [32]byte
	// pat is a person holding policy.publish, signed in on the page with a
	// security key.
	pat gatePerson
}

type gatePerson struct {
	id, key, session ids.UUID
	ctx              context.Context
}

func (w *world) gatedRollouts() *gatedRollouts {
	w.t.Helper()
	if w.auth.Inputs == nil {
		w.keepInputs()
	}
	g := &gatedRollouts{rolloutWorld: w.rollouts(billing.Team), digests: gateDigests}
	facts := &factpg.Store{Pool: w.pool}
	g.versions = &papp.Versions{
		Store: &polpg.Store{Pool: w.pool}, Facts: facts, Subjects: facts, Definitions: &defpg.Store{Pool: w.pool},
		Authz: grantsapp.SubjectAuthorizer{}, Limits: celenv.DefaultLimits, Validator: passingPorts{}, Tests: passingPorts{},
	}
	g.versions.Changes = papp.NewChanges(w.pool, nil, "https://pc.example.test",
		func(context.Context, ids.OrgID) ([32]byte, [32]byte, error) { return g.digests, g.digests, nil })
	g.versions.Changes.Register(papp.ChangePublish, g.versions.ApplyPublish)
	g.svc.Gate = rollout.Connect(g.versions, g.svc)
	g.pat = g.person("pat", tdomain.RolePolicyPublisher)
	g.publisher = g.pat.ctx
	return g
}

// person adds a user with a security key and a browser session, bound at
// the org to roles.
func (g *gatedRollouts) person(name string, roles ...tdomain.RoleName) gatePerson {
	g.t.Helper()
	p := gatePerson{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	exec(g.t, g.pool, g.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", g.org, p.id, name)
	exec(g.t, g.pool, g.org, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		g.org, p.key, p.id, secret[:16], secret)
	exec(g.t, g.pool, g.org, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, g.org, p.session, p.id, secret)
	var bs []tdomain.Binding
	for _, r := range roles {
		exec(g.t, g.pool, g.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			g.org, ids.NewV7(), string(r), p.id)
		bs = append(bs, tdomain.Binding{Role: r, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: g.org.UUID()}})
	}
	p.ctx = tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    tdomain.Subject{Org: g.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: p.id}, Bindings: bs},
		Credential: tapp.CredBrowserSession, Session: p.session,
	})
	return p
}

// confirm is p's confirmation of a change request with a BINDING ceremony
// over its binding, as the policy changes page makes it.
func (g *gatedRollouts) confirm(p gatePerson, id ids.UUID) (papp.ChangeRequest, error) {
	g.t.Helper()
	req, err := g.versions.Changes.Get(p.ctx, id)
	if err != nil {
		g.t.Fatal(err)
	}
	cer := ids.NewV7()
	exec(g.t, g.pool, g.org, `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, policy_change_request_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, g.org, cer, p.session, p.id, req.Binding[:], id)
	return g.versions.Changes.Confirm(p.ctx, id, papp.Assertion{Ceremony: cer, Credential: p.key})
}

// shadowOf stores base as the published version and next as a draft, and
// starts a SHADOW rollout of next with the cohort "pilot" holding the
// world's agent.
func (g *gatedRollouts) shadowOf(base, next []pdomain.Rule) rollout.Rollout {
	g.t.Helper()
	g.publishPolicy(1, false, base...)
	draft := g.publishPolicy(2, true, next...)
	if _, err := g.svc.CreateCohort(g.publisher, "pilot"); err != nil {
		g.t.Fatal(err)
	}
	if _, err := g.svc.ChangeCohort(g.publisher, "pilot", []ids.UUID{g.agent}, false); err != nil {
		g.t.Fatal(err)
	}
	r, err := g.svc.StartRollout(g.publisher, draft, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	return r
}

// TestHR234_ALooseningPilotEntersOnlyOnceConfirmed: a pilot of a version
// that drops a hold of the published one is a ROLLOUT change request; the
// rollout stays in SHADOW and the agent keeps the published version until
// a person holding policy.publish confirms it with a security key, and
// then the pilot's version decides for the cohort's agent.
func TestHR234_ALooseningPilotEntersOnlyOnceConfirmed(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2")
	g := w.gatedRollouts()
	r := g.shadowOf([]pdomain.Rule{pgCapOver1000, pgHoldOver50}, []pdomain.Rule{pgCapOver1000})
	got, cr, err := g.svc.StartPilot(g.publisher, r.ID, []string{"pilot"})
	if err != nil || cr == nil || got.Stage != rollout.StageShadow {
		t.Fatalf("a loosening pilot: %+v %v %v", got.Stage, cr, err)
	}
	req, err := g.versions.Changes.Get(g.publisher, cr.ID)
	if err != nil || req.Kind != papp.ChangeRollout || req.Subject != r.ID || req.State != papp.ChangePending || req.Required != 1 {
		t.Fatalf("change request: %+v %v", req, err)
	}
	run := w.run(w.grant("500").ID, ids.UUID{})
	if res := w.authorize(w.request(run, ids.NewV7(), "ch_1", "70.00")); res.Decision != adomain.RequireApproval {
		t.Fatalf("before the confirmation: %s", res.Decision)
	}
	if done, err := g.confirm(g.pat, cr.ID); err != nil || done.State != papp.ChangeApproved {
		t.Fatalf("confirm: %+v %v", done.State, err)
	}
	if got, err := g.svc.GetRollout(g.publisher, r.ID); err != nil || got.Stage != rollout.StagePilot || got.Targets[rollout.TargetConfigured] != 1 {
		t.Fatalf("after the confirmation: %+v %v", got, err)
	}
	if res := w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00")); res.Decision != adomain.Allow {
		t.Fatalf("in the pilot: %s", res.Decision)
	}
}

// TestHR234_ARolloutChangeRequestIsVoidedWhenItsBaseChanged: another
// version published after the pilot was requested voids the request on
// confirmation (BASE_CHANGED), and the rollout stays in SHADOW.
func TestHR234_ARolloutChangeRequestIsVoidedWhenItsBaseChanged(t *testing.T) {
	w := newWorld(t)
	g := w.gatedRollouts()
	r := g.shadowOf([]pdomain.Rule{pgCapOver1000, pgHoldOver50}, []pdomain.Rule{pgCapOver1000})
	_, cr, err := g.svc.StartPilot(g.publisher, r.ID, []string{"pilot"})
	if err != nil || cr == nil {
		t.Fatalf("pilot: %v %v", cr, err)
	}
	w.publishPolicy(3, false, pgCapOver1000, pgHoldOver50, pgForbidOver20)
	if _, err := g.confirm(g.pat, cr.ID); !errors.Is(err, papp.ErrChangeVoided) {
		t.Fatalf("confirm after the base changed: %v", err)
	}
	req, _ := g.versions.Changes.Get(g.publisher, cr.ID)
	if req.State != papp.ChangeVoided || req.DecidedReason != papp.VoidBaseChanged {
		t.Fatalf("request: %s %s", req.State, req.DecidedReason)
	}
	if got, _ := g.svc.GetRollout(g.publisher, r.ID); got.Stage != rollout.StageShadow {
		t.Fatalf("stage: %s", got.Stage)
	}
}

// TestHR234_ATighteningPilotStartsAndCompletesThroughTheGate: a version that
// only adds a hold starts its pilot at once; completing it publishes the
// version through the gate, and the publishing transaction completes the
// rollout and makes every agent a target. A version published without a
// rollout records a COMPLETE one in every edition.
func TestHR234_ATighteningPilotStartsAndCompletesThroughTheGate(t *testing.T) {
	w := newWorld(t)
	g := w.gatedRollouts()
	r := g.shadowOf([]pdomain.Rule{pgCapOver1000}, []pdomain.Rule{pgCapOver1000, pgHoldOver50})
	got, cr, err := g.svc.StartPilot(g.publisher, r.ID, []string{"pilot"})
	if err != nil || cr != nil || got.Stage != rollout.StagePilot {
		t.Fatalf("a tightening pilot: %+v %v %v", got.Stage, cr, err)
	}
	got, cr, err = g.svc.CompleteRollout(g.publisher, r.ID)
	if err != nil || cr != nil || got.Stage != rollout.StageComplete || got.Targets[rollout.TargetConfigured] != 1 {
		t.Fatalf("complete: %+v %v %v", got, cr, err)
	}
	pub, err := g.versions.Store.PublishedVersion(context.Background(), w.org)
	if err != nil || pub == nil || pub.ID != r.VersionID {
		t.Fatalf("published: %+v %v", pub, err)
	}
	v3 := w.publishPolicy(3, true, pgCapOver1000, pgHoldOver50, pgForbidOver20)
	if out, err := g.versions.Publish(g.pat.ctx, v3); err != nil || out.ChangeRequest != nil {
		t.Fatalf("publish: %+v %v", out.ChangeRequest, err)
	}
	all, err := g.svc.ListRollouts(g.publisher, 10)
	if err != nil || len(all) != 2 || all[0].VersionID != v3 || all[0].Stage != rollout.StageComplete ||
		all[0].BaseVersionID == nil || *all[0].BaseVersionID != r.VersionID {
		t.Fatalf("rollouts: %+v %v", all, err)
	}
}

// TestHR234_ALooseningCompletionWaitsForItsPublishRequest: completing a
// rollout whose version loosens the published one creates the PUBLISH
// change request; the rollout completes in the transaction that approves
// it.
func TestHR234_ALooseningCompletionWaitsForItsPublishRequest(t *testing.T) {
	w := newWorld(t)
	g := w.gatedRollouts()
	r := g.shadowOf([]pdomain.Rule{pgCapOver1000, pgHoldOver50}, []pdomain.Rule{pgCapOver1000})
	got, cr, err := g.svc.CompleteRollout(g.publisher, r.ID)
	if err != nil || cr == nil || got.Stage != rollout.StageShadow {
		t.Fatalf("a loosening completion: %+v %v %v", got.Stage, cr, err)
	}
	if done, err := g.confirm(g.pat, cr.ID); err != nil || done.State != papp.ChangeApproved {
		t.Fatalf("confirm: %+v %v", done.State, err)
	}
	if got, err := g.svc.GetRollout(g.publisher, r.ID); err != nil || got.Stage != rollout.StageComplete {
		t.Fatalf("after the confirmation: %+v %v", got.Stage, err)
	}
}
