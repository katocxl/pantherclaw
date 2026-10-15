// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exceptions_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// publisher is a person holding policy.publish with a security key, signed
// in on the policy changes page.
type publisher struct {
	id, key, session ids.UUID
	ctx              context.Context
}

func (f *fixture) publisher(t *testing.T, name string) publisher {
	t.Helper()
	p := publisher{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", f.org, p.id, name)
	f.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, p.key, p.id, secret[:16], secret)
	f.exec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, f.org, p.session, p.id, secret)
	f.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		f.org, ids.NewV7(), string(td.RolePolicyPublisher), p.id)
	sub := td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id}, Bindings: []td.Binding{
		{Role: td.RolePolicyPublisher, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}},
	}}
	p.ctx = tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: sub, Credential: tenancy.CredBrowserSession, Session: p.session})
	return p
}

// sign is p's BINDING ceremony over the request's binding, as the page
// hands it to the use case after the key answered.
func (f *fixture) sign(t *testing.T, p publisher, req papp.ChangeRequest) papp.Assertion {
	t.Helper()
	cer := ids.NewV7()
	f.exec(t, `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, policy_change_request_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, f.org, cer, p.session, p.id, req.Binding[:], req.ID)
	return papp.Assertion{Ceremony: cer, Credential: p.key}
}

// realChanges wires the fixture's service to the gate's change requests,
// with the EXCEPTION apply callback registered.
func (f *fixture) realChanges() *papp.Changes {
	c := papp.NewChanges(f.p, nil, "https://pc.test", func(context.Context, ids.OrgID) ([32]byte, [32]byte, error) {
		return [32]byte{1}, [32]byte{2}, nil
	})
	c.Register(papp.ChangeException, f.svc.Apply)
	f.svc.Changes = c
	return c
}

// TestT102_ExceptionIsApprovedLikeALoosening (F2, HR-231): an exception
// request becomes an EXCEPTION change request that two distinct
// publishers confirm with their keys; only the last confirmation
// activates it. A request whose rule changed meanwhile is voided
// BASE_CHANGED and its exception never applies; the sweep declines it.
func TestT102_ExceptionIsApprovedLikeALoosening(t *testing.T) {
	f := newFixture(t)
	changes := f.realChanges()
	bob, carol := f.publisher(t, "bob-publisher"), f.publisher(t, "carol-publisher")
	author := f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor)
	x, cr, err := f.svc.RequestException(author, f.request())
	if err != nil {
		t.Fatal(err)
	}
	req, err := changes.Get(bob.ctx, cr.ID)
	if err != nil || req.Kind != papp.ChangeException || req.Subject != x.ID || req.Base != f.published || req.Required != 2 {
		t.Fatalf("change request %+v (%v)", req, err)
	}
	got, err := changes.Confirm(bob.ctx, req.ID, f.sign(t, bob, req))
	if err != nil || got.State != papp.ChangePending || len(f.active(t)) != 0 {
		t.Fatalf("after one confirmation: %+v (%v), active %+v", got, err, f.active(t))
	}
	got, err = changes.Confirm(carol.ctx, req.ID, f.sign(t, carol, req))
	if err != nil || got.State != papp.ChangeApproved {
		t.Fatalf("after two confirmations: %+v (%v)", got, err)
	}
	if a := f.active(t); len(a) != 1 || a[0].ID != x.ID.String() {
		t.Fatalf("active %+v", a)
	}

	// The rule changes before the second request is confirmed.
	y, cr, err := f.svc.RequestException(author, f.request())
	if err != nil {
		t.Fatal(err)
	}
	rs := rules()
	rs[0].When = "false"
	f.republish(t, rs)
	req, err = changes.Get(bob.ctx, cr.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changes.Confirm(bob.ctx, req.ID, f.sign(t, bob, req)); err != nil {
		t.Fatal(err)
	}
	got, err = changes.Confirm(carol.ctx, req.ID, f.sign(t, carol, req))
	if !errors.Is(err, papp.ErrChangeVoided) || got.State != papp.ChangeVoided || got.DecidedReason != papp.VoidBaseChanged {
		t.Fatalf("a changed rule: %+v (%v)", got, err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.policy_exceptions WHERE id = $1 AND state = 'PENDING'`, y.ID); n != 1 {
		t.Fatal("the voided request's exception changed state")
	}
	f.d.AdminExec(t, `ALTER TABLE pc.policy_exceptions DISABLE TRIGGER policy_exceptions_transition`)
	f.d.AdminExec(t, `UPDATE pc.policy_exceptions SET created_at = now() - interval '10 minutes' WHERE id = $1`, y.ID)
	f.d.AdminExec(t, `ALTER TABLE pc.policy_exceptions ENABLE TRIGGER policy_exceptions_transition`)
	if _, err := f.svc.Sweep(context.Background(), f.org); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.policy_exceptions WHERE id = $1 AND state = 'DECLINED'`, y.ID); n != 1 {
		t.Fatal("the sweep did not decline the exception of a voided request")
	}
}

// TestT102_AFailedChangeRequestClosesTheException: when its change request
// cannot be created, the exception is declined at once, so it can never be
// approved later.
func TestT102_AFailedChangeRequestClosesTheException(t *testing.T) {
	f := newFixture(t)
	f.c.fail = papp.ErrChangePending
	x, _, err := f.svc.RequestException(f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor), f.request())
	if !errors.Is(err, papp.ErrChangePending) {
		t.Fatalf("request: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.policy_exceptions WHERE id = $1 AND state = 'DECLINED'`, x.ID); n != 1 {
		t.Fatal("the exception was left pending")
	}
	if _, err := f.activate(t, x.ID); !errors.Is(err, exceptions.ErrNotPending) {
		t.Fatalf("activated: %v", err)
	}
}
