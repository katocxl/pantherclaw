// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package signals

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeCases opens cases and remembers their seeds.
type fakeCases struct{ seeds []reflexdomain.CaseSeed }

func (c *fakeCases) Open(_ context.Context, _ pgx.Tx, seed reflexdomain.CaseSeed) (ids.UUID, error) {
	c.seeds = append(c.seeds, seed)
	return ids.NewV7(), nil
}

// fakeContainer records containment requests; fail makes them fail.
type fakeContainer struct {
	got  []reflexdomain.ContainRequest
	fail error
}

func (c *fakeContainer) Contain(_ context.Context, _ pgx.Tx, r reflexdomain.ContainRequest) (reflexdomain.ContainResult, error) {
	if c.fail != nil {
		return reflexdomain.ContainResult{}, c.fail
	}
	c.got = append(c.got, r)
	return reflexdomain.ContainResult{ActionID: ids.NewV7(), Status: "REQUESTED"}, nil
}

// person is a user with a security key and a browser session.
type person struct{ id, key, session ids.UUID }

func (f *rxFixture) person(t *testing.T, name string, n byte) person {
	t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://login.example.com', $3)", f.org, p.id, name)
	f.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, p.key, p.id, bytes.Repeat([]byte{n}, 16), bytes.Repeat([]byte{n}, 32))
	f.exec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, f.org, p.session, p.id, bytes.Repeat([]byte{n}, 32))
	return p
}

// page is the person on the playbook page (a browser session).
func (f *rxFixture) page(p person) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id}, Bindings: []td.Binding{
			{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}},
		}},
		Credential: tenancy.CredBrowserSession, Session: p.session,
	})
}

// ceremony stores the person's open BINDING ceremony over challenge, as
// the page's confirm-options and a verified assertion leave it.
func (f *rxFixture) ceremony(t *testing.T, p person, request ids.UUID, challenge []byte) Assertion {
	t.Helper()
	id := ids.NewV7()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		// A new ceremony replaces the person's open one (BeginBinding).
		if err := q.DeleteOpenBindingCeremonies(ctx, dbq.DeleteOpenBindingCeremoniesParams{
			OrgID: f.org, UserID: p.id, IdentityPlaybookRequestID: &request,
		}); err != nil {
			return err
		}
		return q.InsertBindingCeremony(ctx, dbq.InsertBindingCeremonyParams{
			OrgID: f.org, ID: id, SessionID: p.session, UserID: p.id, Challenge: challenge, AllowedCredentials: [][]byte{{1}},
			IdentityPlaybookRequestID: &request, TtlSeconds: 300,
		})
	}); err != nil {
		t.Fatal(err)
	}
	return Assertion{Ceremony: id, Credential: p.key}
}

func (f *rxFixture) confirm(t *testing.T, p person, r PlaybookRequest) (PlaybookRequest, error) {
	t.Helper()
	return f.svc.Confirm(f.page(p), r.ID, f.ceremony(t, p, r.ID, r.Binding[:]))
}

// issuedGrant gives the person an active root grant they issued and a
// waiting approval under it.
func (f *rxFixture) issuedGrant(t *testing.T, user ids.UUID) (grant, approval ids.UUID) {
	t.Helper()
	env, agent, run, txn := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	grant, approval = ids.NewV7(), ids.NewV7()
	binding := sha256.Sum256(approval[:])
	f.exec(t, "INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, $3, 'Dev', 'DEVELOPMENT')", f.org, env, "dev-"+env.String()[28:])
	f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", f.org, agent)
	f.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, f.org, run, agent, env, user)
	f.exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, f.org, grant, agent, user, env)
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'R', 'gw', 'OPEN')`, f.org, txn, run, ids.NewV7(), binding[:])
	f.exec(t, `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'payments.refund.create', $7, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1}]', '{}', $7, '\x7b7d', date_trunc('second', now()) + interval '1 hour')`,
		f.org, approval, agent, txn, run, grant, binding[:])
	return grant, approval
}

// TestHR262_PlaybookNeedsTwoPeopleWithTwoKeysAndActsOnlyOnIssSub: the
// identity playbook is off by default, cannot be enabled without
// containment, is enabled only by two distinct people with distinct keys
// in BINDING ceremonies over its request, and then contains a person
// matched by issuer and subject (principal DENY_ALL, their issued grants)
// and voids their waiting approvals; an email match or another event type
// only opens a case; disabling takes one person; a request made against
// an older playbook version is voided.
func TestHR262_PlaybookNeedsTwoPeopleWithTwoKeysAndActsOnlyOnIssSub(t *testing.T) {
	f := newRxFixture(t)
	cases, box := &fakeCases{}, &fakeContainer{}
	f.svc.WithCases(cases).WithFailures(&failures.Sink{})
	bob, dave := f.person(t, "bob-admin", 5), f.person(t, "dave-admin", 6)
	grant, approval := f.issuedGrant(t, f.alice)
	events := []string{TypeSessionRevoked, TypeCredentialCompromise}

	if pb, err := f.svc.GetPlaybook(f.page(bob)); err != nil || pb.Enabled {
		t.Fatalf("default playbook: %+v %v", pb, err)
	}
	if _, err := f.svc.RequestPlaybookChange(f.page(bob), PlaybookEnable, events); !errors.Is(err, ErrPlaybookUnavailable) {
		t.Fatalf("enable without containment: %v", err)
	}
	f.svc.WithContainer(box)
	for _, bad := range [][]string{nil, {"https://example.com/other"}, {TypeSessionRevoked, TypeSessionRevoked}} {
		if _, err := f.svc.RequestPlaybookChange(f.page(bob), PlaybookEnable, bad); !errors.Is(err, ErrPlaybookInvalid) {
			t.Errorf("events %v: %v", bad, err)
		}
	}
	if _, err := f.svc.RequestPlaybookChange(f.page(bob), PlaybookDisable, nil); !errors.Is(err, ErrPlaybookState) {
		t.Fatalf("disable a disabled playbook: %v", err)
	}
	req, err := f.svc.RequestPlaybookChange(f.page(bob), PlaybookEnable, events)
	if err != nil || req.Required != 2 || req.State != RequestPending {
		t.Fatalf("request: %+v %v", req, err)
	}
	if _, err := f.svc.RequestPlaybookChange(f.page(dave), PlaybookEnable, events); !errors.Is(err, ErrPlaybookPending) {
		t.Fatalf("second pending request: %v", err)
	}

	out, err := f.confirm(t, bob, req)
	if err != nil || out.State != RequestPending || len(out.Confirmations) != 1 {
		t.Fatalf("first confirmation: %+v %v", out, err)
	}
	if _, err := f.confirm(t, bob, req); !errors.Is(err, ErrSamePerson) {
		t.Fatalf("same person twice: %v", err)
	}
	// A key used by an earlier confirmation, a ceremony over other bytes
	// and a confirmation outside a browser session are refused.
	a := f.ceremony(t, dave, req.ID, req.Binding[:])
	a.Credential = bob.key
	if _, err := f.svc.Confirm(f.page(dave), req.ID, a); !errors.Is(err, ErrSameKey) {
		t.Fatalf("same key: %v", err)
	}
	if _, err := f.svc.Confirm(f.page(dave), req.ID, f.ceremony(t, dave, req.ID, bytes.Repeat([]byte{9}, 32))); !errors.Is(err, ErrCeremony) {
		t.Fatalf("ceremony over other bytes: %v", err)
	}
	api := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: dave.id},
		Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
	}, Credential: tenancy.CredAccessToken})
	if _, err := f.svc.Confirm(api, req.ID, f.ceremony(t, dave, req.ID, req.Binding[:])); !errors.Is(err, ErrBrowserSession) {
		t.Fatalf("confirmation through the API: %v", err)
	}
	if pb, _ := f.svc.GetPlaybook(f.page(bob)); pb.Enabled {
		t.Fatal("enabled by one confirmation")
	}
	out, err = f.confirm(t, dave, req)
	if err != nil || out.State != RequestApplied {
		t.Fatalf("second confirmation: %+v %v", out, err)
	}
	if pb, _ := f.svc.GetPlaybook(f.page(bob)); !pb.Enabled || len(pb.Events) != 2 || pb.Version != 1 {
		t.Fatalf("playbook = %+v", pb)
	}

	// An email match opens a case and never acts.
	if a := f.post(t, f.org, f.tx, ContentType, f.token(t, f.key, f.tx, func(c map[string]any) {
		c["sub_id"] = map[string]any{"format": "email", "email": "alice@example.com"}
	})); a.status != http.StatusAccepted {
		t.Fatalf("email push: %+v", a)
	}
	if len(box.got) != 0 || len(cases.seeds) != 1 {
		t.Fatalf("email match: contain %d, cases %d", len(box.got), len(cases.seeds))
	}
	// An event type the playbook does not act on opens a case only.
	if a := f.post(t, f.org, f.tx, ContentType, f.token(t, f.key, f.tx, func(c map[string]any) {
		c["events"] = map[string]any{TypeAccountPurged: map[string]any{}}
	})); a.status != http.StatusAccepted || len(box.got) != 0 {
		t.Fatalf("other type: %+v, contain %d", a, len(box.got))
	}
	// An iss_sub match of a playbook event type contains the person and
	// the grant they issued, and voids their waiting approval.
	if a := f.post(t, f.org, f.tx, ContentType, f.token(t, f.key, f.tx, nil)); a.status != http.StatusAccepted {
		t.Fatalf("iss_sub push: %+v", a)
	}
	if len(box.got) != 2 {
		t.Fatalf("contain requests = %+v", box.got)
	}
	for _, r := range box.got {
		if r.Control != reflexdomain.ControlDenyAll || r.Actor != PlaybookActor || r.PreviewDigest != nil || r.CaseID == nil ||
			len(r.Reason) < len(PlaybookReason) || r.Reason[:len(PlaybookReason)] != PlaybookReason {
			t.Errorf("request = %+v", r)
		}
	}
	if box.got[0].Scope != (reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: f.alice.String()}) ||
		box.got[1].Scope != (reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: grant.String()}) {
		t.Fatalf("scopes = %v, %v", box.got[0].Scope, box.got[1].Scope)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.approval_requests WHERE id = $1 AND state = 'INVALIDATED' AND end_reason = 'IDENTITY_PLAYBOOK'", approval); n != 1 {
		t.Fatal("the waiting approval was not voided")
	}
	last := cases.seeds[len(cases.seeds)-1]
	if last.Source != reflexdomain.SourceSignals || len(last.Subjects) != 2 || last.Subjects[1].ID != grant.String() || len(last.Evidence) != 1 {
		t.Fatalf("case seed = %+v", last)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ssf_events WHERE outcome = 'ACCEPTED' AND case_id IS NOT NULL"); n != 3 {
		t.Fatalf("events with cases = %d", n)
	}

	// A containment failure keeps the event and its case and becomes an
	// owned failure.
	box.fail = errors.New("response unavailable")
	if a := f.post(t, f.org, f.tx, ContentType, f.token(t, f.key, f.tx, nil)); a.status != http.StatusAccepted {
		t.Fatalf("push with failing containment: %+v", a)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.operational_failures WHERE kind = 'signals.playbook_failed'"); n != 1 {
		t.Fatalf("playbook failures = %d", n)
	}
	box.fail = nil

	// Without cases the event says so.
	f.svc.WithCases(nil)
	if a := f.post(t, f.org, f.tx, ContentType, f.token(t, f.key, f.tx, func(c map[string]any) {
		c["events"] = map[string]any{TypeAccountPurged: map[string]any{}}
	})); a.status != http.StatusAccepted {
		t.Fatalf("push without cases: %+v", a)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ssf_events WHERE case_note = $1", NoCaseNote); n != 1 {
		t.Fatalf("events noted without a case = %d", n)
	}

	// Disabling takes one person.
	dis, err := f.svc.RequestPlaybookChange(f.page(dave), PlaybookDisable, nil)
	if err != nil || dis.Required != 1 {
		t.Fatalf("disable request: %+v %v", dis, err)
	}
	if out, err := f.confirm(t, dave, dis); err != nil || out.State != RequestApplied {
		t.Fatalf("disable: %+v %v", out, err)
	}
	if pb, _ := f.svc.GetPlaybook(f.page(bob)); pb.Enabled {
		t.Fatal("still enabled")
	}

	// A request made against an older version is voided.
	stale, err := f.svc.RequestPlaybookChange(f.page(bob), PlaybookEnable, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.confirm(t, bob, stale); err != nil {
		t.Fatal(err)
	}
	f.exec(t, "UPDATE pc.identity_playbooks SET version = version + 1")
	if _, err := f.confirm(t, dave, stale); !errors.Is(err, ErrRequestVoided) {
		t.Fatalf("stale request: %v", err)
	}
	if pb, _ := f.svc.GetPlaybook(f.page(bob)); pb.Enabled {
		t.Fatal("a voided request enabled the playbook")
	}
}
