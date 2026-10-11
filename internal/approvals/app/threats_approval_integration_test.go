// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// apaRole binds role to user at org scope, created by grantor age ago (a
// Postgres interval).
func apaRole(f *fx, user ids.UUID, role string, grantor ids.UUID, age string) {
	f.t.Helper()
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
		VALUES ($1, $2, $3, $4, 'ORG', $5, now() - $6::interval)`, f.org, ids.NewV7(), role, user, "user:"+grantor.String(), age)
}

// apaKey registers another security key for user, created age ago, and
// returns its id.
func apaKey(f *fx, user ids.UUID, age string) ids.UUID {
	f.t.Helper()
	id := ids.NewV7()
	f.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'another key',
		now() - $6::interval)`, f.org, id, user, id[:], append(id[:], id[:]...), age)
	return id
}

// apaNewcomer is a person whose account and key are from today and whom
// grantor made an Approver today, signed in with a browser.
func apaNewcomer(f *fx, grantor ids.UUID) person {
	f.t.Helper()
	p := person{id: ids.NewV7(), browser: ids.NewV7()}
	f.exec(`INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)`, f.org, p.id, p.id.String())
	f.exec(`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, f.org, p.browser, p.id, append(p.id[:], p.id[:]...))
	p.cred = apaKey(f, p.id, "0 seconds")
	apaRole(f, p.id, "approver", grantor, "0 seconds")
	return p
}

// apaApprove is p approving request on the page with key, through the
// ceremony given (a refused attempt leaves its ceremony unused).
func apaApprove(f *fx, p person, request, ceremony, key ids.UUID) (approvals.Request, error) {
	return f.svc.Approve(context.Background(), f.org, approvals.Responder{User: p.id, Browser: p.browser}, request,
		approvals.Assertion{Ceremony: ceremony, Credential: key, AuthenticatorData: make([]byte, 37), ClientDataJSON: []byte(`{}`), Signature: []byte{1}})
}

// TestT002_TheAgentAndItsDeveloperCannotApproveTheHold: T-002 — the held
// agent tries to get its own refund approved: with its PantherClaw API key,
// with its developer's credentials on an API key, with an approver's CLI
// login, and through alice, its developer, who launched the run, is its
// principal and holds the Approver role. Every route is refused, nothing
// is recorded, and the agent's wait handle stays PENDING until an
// independent approver decides. The rules are TestHR032_* and TestHR036_*;
// connections to PantherClaw itself are refused by TestHR077_*.
func TestT002_TheAgentAndItsDeveloperCannotApproveTheHold(t *testing.T) {
	f := newFx(t, 1)
	apaRole(f, f.alice.id, "approver", f.bob.id, "30 days")
	inst := f.bound()
	req := f.request(1)
	ctx := context.Background()
	agentKey := tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()}},
		Credential: tenancy.CredAPIKey,
	}
	developerKey := tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.alice.id}},
		Credential: tenancy.CredAPIKey, Session: f.alice.cli,
	}
	narrower := []byte(`{"amount":{"value":"40.00","currency":"USD"},"reason":"duplicate"}`)
	for _, c := range []struct {
		name string
		try  func() error
		want error
	}{
		{"the agent's API key as a responder", func() error { _, err := approvals.ResponderFrom(agentKey); return err }, approvals.ErrHumanSession},
		{"the agent declining with its API key", func() error {
			_, err := f.svc.Decline(tenancy.WithCaller(ctx, agentKey), req, "OTHER", "", "")
			return err
		}, approvals.ErrHumanSession},
		{"the agent proposing its own narrower action", func() error {
			_, err := f.svc.ProposeNarrower(tenancy.WithCaller(ctx, agentKey), req, narrower, "", false)
			return err
		}, approvals.ErrHumanSession},
		{"the developer's identity on an API key", func() error { _, err := approvals.ResponderFrom(developerKey); return err }, approvals.ErrHumanSession},
		{"an approver's CLI login approving", func() error {
			_, err := f.svc.Approve(ctx, f.org, approvals.Responder{User: f.bob.id, CLI: f.bob.cli}, req, approvals.Assertion{Credential: f.bob.cred})
			return err
		}, approvals.ErrHumanSession},
		{"an approver's CLI login asking for the binding", func() error {
			_, err := f.svc.BeginApproval(ctx, f.org, approvals.Responder{User: f.bob.id, CLI: f.bob.cli}, req)
			return err
		}, approvals.ErrHumanSession},
		{"the developer asking for the binding on the page", func() error {
			_, err := f.svc.BeginApproval(ctx, f.org, approvals.Responder{User: f.alice.id, Browser: f.alice.browser}, req)
			return err
		}, approvals.ErrNotEligible},
		{"the developer approving with her own key", func() error { _, err := f.approve(f.alice, req); return err }, approvals.ErrNotEligible},
		{"the developer proposing a narrower action", func() error {
			_, err := f.svc.ProposeNarrower(f.as(f.alice), req, narrower, "", false)
			return err
		}, approvals.ErrNotEligible},
	} {
		if err := c.try(); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if s := f.str("SELECT count(*)::text FROM pc.approval_responses WHERE request_id = $1", req); s != "0" {
		t.Fatalf("%s responses recorded", s)
	}
	if s := f.str("SELECT r.state || '/' || e.state FROM pc.approval_requests r JOIN pc.waitlist_entries e ON e.subject_id = r.id WHERE r.id = $1", req); s != "PENDING/OPEN" {
		t.Fatalf("request/entry %s", s)
	}
	waits := approvals.NewWaits(f.p, 0, 0, nil)
	if v, err := waits.Read(ctx, f.org, inst, f.run, f.txn); err != nil || v.State != apdomain.WaitPending {
		t.Fatalf("the agent's handle after the attempts: %+v, %v", v, err)
	}
	if r, err := f.approve(f.bob, req); err != nil || r.State != "APPROVED" {
		t.Fatalf("an independent approver: %s, %v", r.State, err)
	}
	if v, err := waits.Read(ctx, f.org, inst, f.run, f.txn); err != nil || v.State != apdomain.WaitReady {
		t.Fatalf("the agent's handle after bob approved: %+v, %v", v, err)
	}
}

// TestT027_ASockPuppetNeverCountsAsTheSecondApprover: T-027 — a refund
// needs two approvers and bob has approved. The second approval is then
// attempted by bob again with a second key, by dave with bob's key or with
// a key added today, by erin, an org administrator, before and after she
// grants herself the Approver role, and by mallory, an account erin
// created and made an Approver today. None counts: the request stays
// PENDING with bob's response alone and no admin notice, until dave
// approves with his own month-old key. The rules are TestHR035_* (the
// domain, the schema and TestHR035_TwoPeopleWithTwoKeys); their re-check
// at use is TestHR170_ConsumptionChecksEligibilityAgain.
func TestT027_ASockPuppetNeverCountsAsTheSecondApprover(t *testing.T) {
	f := newFx(t, 2)
	req := f.request(2)
	if r, err := f.approve(f.bob, req); err != nil || r.State != "PENDING" {
		t.Fatalf("bob's approval: %s, %v", r.State, err)
	}
	erin := f.person("erin", false)
	apaRole(f, erin.id, "org_admin", f.alice.id, "30 days")
	mallory := apaNewcomer(f, erin.id)
	bobSecond, daveToday := apaKey(f, f.bob.id, "30 days"), apaKey(f, f.dave.id, "0 seconds")
	dave, erinC := f.ceremony(f.dave, req), f.ceremony(erin, req)
	if _, err := f.svc.BeginApproval(context.Background(), f.org, approvals.Responder{User: f.bob.id, Browser: f.bob.browser}, req); !errors.Is(err, approvals.ErrNotEligible) {
		t.Fatalf("bob asking for the binding again: %v", err)
	}
	if _, err := apaApprove(f, f.bob, req, f.ceremony(f.bob, req), bobSecond); !db.IsUniqueViolation(err) {
		t.Fatalf("bob approving again with his second key: %v, want the one-response-per-person refusal", err)
	}
	for _, c := range []struct {
		name     string
		who      person
		ceremony ids.UUID
		key      ids.UUID
		before   func()
	}{
		{"dave with bob's key", f.dave, dave, f.bob.cred, nil},
		{"dave with a key added today", f.dave, dave, daveToday, nil},
		{"an org administrator", erin, erinC, erin.cred, nil},
		{"the administrator after granting herself the role", erin, erinC, erin.cred, func() { apaRole(f, erin.id, "approver", erin.id, "0 seconds") }},
		{"an account made an Approver today", mallory, f.ceremony(mallory, req), mallory.cred, nil},
	} {
		if c.before != nil {
			c.before()
		}
		if _, err := apaApprove(f, c.who, req, c.ceremony, c.key); !errors.Is(err, approvals.ErrNotEligible) {
			t.Errorf("%s: %v, want not eligible", c.name, err)
		}
	}
	if s := f.str("SELECT state || '/' || (SELECT count(*) FROM pc.approval_responses WHERE request_id = $1) FROM pc.approval_requests WHERE id = $1", req); s != "PENDING/1" {
		t.Fatalf("request/responses %s, want PENDING with bob's response alone", s)
	}
	if s := f.str("SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.approval.multi_person_completed'"); s != "0" {
		t.Fatalf("%s multi-person notices before a second real approver", s)
	}
	if r, err := apaApprove(f, f.dave, req, dave, f.dave.cred); err != nil || r.State != "APPROVED" {
		t.Fatalf("dave with his own key: %s, %v", r.State, err)
	}
}
