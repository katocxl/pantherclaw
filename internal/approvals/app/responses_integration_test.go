// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type person struct {
	id, cred, browser, cli ids.UUID
}

// fx is an org with a held request: alice launched the run and is its
// principal; bob and dave are Approvers at org scope (granted by alice, a
// month ago, with month-old keys); carol has no role.
type fx struct {
	t                       *testing.T
	d                       *dbtest.DB
	p                       *db.Pool
	org                     ids.OrgID
	alice, bob, carol, dave person
	agent, run, grant, txn  ids.UUID
	svc                     *approvals.Service
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fx) str(sql string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&s)
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

func (f *fx) person(name string, approver bool) person {
	f.t.Helper()
	p := person{id: ids.NewV7(), cred: ids.NewV7(), browser: ids.NewV7(), cli: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	f.exec(`INSERT INTO pc.users (org_id, id, issuer, subject, created_at) VALUES ($1, $2, 'https://idp.test', $3, now() - interval '30 days')`,
		f.org, p.id, name)
	f.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', now() - interval '30 days')`,
		f.org, p.cred, p.id, secret[:16], secret)
	f.exec(`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, f.org, p.browser, p.id, secret)
	f.exec(`INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '{}', $4, now() + interval '1 day')`, f.org, p.cli, p.id, secret)
	if approver {
		f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
			VALUES ($1, $2, 'approver', $3, 'ORG', $4, now() - interval '30 days')`, f.org, ids.NewV7(), p.id, "user:"+f.alice.id.String())
	}
	return p
}

func newFx(t *testing.T, count int) *fx {
	t.Helper()
	d := dbtest.New(t)
	f := &fx{t: t, d: d, p: d.AppPool(t), org: ids.New[ids.Org](), agent: ids.NewV7(), run: ids.NewV7(), grant: ids.NewV7(), txn: ids.NewV7()}
	f.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", f.org)
	f.alice = f.person("alice", false)
	f.bob, f.carol, f.dave = f.person("bob", true), f.person("carol", false), f.person("dave", true)
	env := ids.NewV7()
	f.exec("INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", f.org, env)
	f.exec("INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", f.org, f.agent)
	f.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, f.org, f.run, f.agent, env, f.alice.id)
	f.exec(`INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, f.org, f.grant, f.agent, f.alice.id, env)
	f.exec("INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)", f.org, f.grant)
	f.exec("INSERT INTO pc.org_containment (org_id) VALUES ($1)", f.org)
	pkg, version := ids.NewV7(), ids.NewV7()
	f.exec("INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, 'pc.mock-payments')", f.org, pkg)
	f.exec(`INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.0.0', 'sha256:' || repeat('0', 64), '{7d', 'ACTIVE')`, f.org, version, pkg)
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'REFUND_OVER_50', 'gw', 'OPEN')`,
		f.org, f.txn, f.run, ids.NewV7(), make([]byte, 32))
	f.svc = &approvals.Service{Pool: f.p, Simulator: fakeSimulator{}}
	return f
}

// request inserts a PENDING request needing count approvers, with its hold
// slots and its ACTION_HOLD entry, and returns its id.
func (f *fx) request(count int) ids.UUID {
	f.t.Helper()
	id := ids.NewV7()
	binding := make([]byte, 32)
	copy(binding, id[:])
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'payments.refund.create', $7, '\x7b7d', $8, '{}', $7,
		convert_to('{"definition":{"package":"pc.mock-payments","version":"1.0.0"}}', 'UTF8'),
		date_trunc('second', now()) + interval '1 hour')`, f.org, id, f.agent, f.txn, f.run, f.grant, binding,
		`[{"kind":"approval","role":"approver","count":`+string(rune('0'+count))+`,"sources":[]}]`)
	f.exec(`INSERT INTO pc.hold_slots (org_id, scope_kind, scope_id, pending) VALUES ($1, 'grant', $2, 1), ($1, 'run', $3, 1)
		ON CONFLICT (org_id, scope_kind, scope_id) DO UPDATE SET pending = pc.hold_slots.pending + 1`, f.org, f.grant, f.run)
	f.exec(`INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, deadline_at)
		VALUES ($1, $2, 'ACTION_HOLD', 'approval_request', $3, $4, $5, $6, now() + interval '1 hour')`, f.org, ids.NewV7(), id, f.agent, f.run, f.txn)
	return id
}

// as is p calling the API with a CLI access token.
func (f *fx) as(p person, roles ...td.Binding) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id}, Bindings: roles},
		Credential: tenancy.CredAccessToken, Session: p.cli,
	})
}

// ceremony stores a BINDING ceremony for p on request and returns its id.
func (f *fx) ceremony(p person, request ids.UUID) ids.UUID {
	f.t.Helper()
	id := ids.NewV7()
	f.exec(`INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, approval_request_id, expires_at)
		SELECT $1, $2, $3, $4, 'BINDING', binding, id, now() + interval '5 minutes' FROM pc.approval_requests WHERE id = $5`,
		f.org, id, p.browser, p.id, request)
	return id
}

func (f *fx) approve(p person, request ids.UUID) (approvals.Request, error) {
	return f.svc.Approve(context.Background(), f.org, approvals.Responder{User: p.id, Browser: p.browser}, request,
		approvals.Assertion{
			Ceremony: f.ceremony(p, request), Credential: p.cred, AuthenticatorData: make([]byte, 37),
			ClientDataJSON: []byte(`{}`), Signature: []byte{1},
		})
}

type fakeSimulator struct{}

func (fakeSimulator) Narrow(context.Context, ids.OrgID, []byte, []byte) (approvals.Simulation, error) {
	return approvals.Simulation{Params: []byte(`{"amount":{"value":"40.00","currency":"USD"},"reason":"duplicate"}`), Decision: "ALLOW"}, nil
}

// TestHR172_ADeclineEndsTheRequestAndGrantsNothing: a decline from a CLI
// session ends the request (the action becomes DENY at use), frees its
// slots, rejects its entry, and cannot happen twice.
func TestHR172_ADeclineEndsTheRequestAndGrantsNothing(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	r, err := f.svc.Decline(f.as(f.bob), req, "TOO_RISKY", "PERSON_PERFORMS", "call the customer first")
	if err != nil {
		t.Fatal(err)
	}
	if r.State != "DECLINED" || r.EndReason == nil || *r.EndReason != "APPROVAL_DECLINED" {
		t.Fatalf("request %s %v", r.State, r.EndReason)
	}
	if s := f.str("SELECT cli_session_id::text FROM pc.approval_responses WHERE request_id = $1", req); s != f.bob.cli.String() {
		t.Fatalf("response session %s", s)
	}
	if s := f.str("SELECT state || ' ' || (first_response_at IS NOT NULL) FROM pc.waitlist_entries WHERE subject_id = $1", req); s != "REJECTED true" {
		t.Fatalf("entry %s", s)
	}
	if s := f.str("SELECT sum(pending)::text FROM pc.hold_slots"); s != "0" {
		t.Fatalf("slots %s", s)
	}
	if _, err := f.svc.Decline(f.as(f.dave), req, "OTHER", "", ""); !errors.Is(err, approvals.ErrNotWaiting) {
		t.Fatalf("a second decline: %v", err)
	}
	if _, err := f.svc.Decline(f.as(f.bob), f.request(1), "BECAUSE", "", ""); !errors.Is(err, approvals.ErrInvalidCode) {
		t.Fatalf("a reason off the list: %v", err)
	}
}

// TestHR032_ApprovingNeedsABrowserSessionAndTheBindingCeremony (decision
// 1): an API key or a CLI session never approves; the page's approval
// needs the BINDING ceremony of this person, session and request, once.
func TestHR032_ApprovingNeedsABrowserSessionAndTheBindingCeremony(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	key := tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()}},
		Credential: tenancy.CredAPIKey,
	}
	if _, err := approvals.ResponderFrom(key); !errors.Is(err, approvals.ErrHumanSession) {
		t.Fatalf("an API key as a responder: %v", err)
	}
	if _, err := f.svc.Approve(context.Background(), f.org, approvals.Responder{User: f.bob.id, CLI: f.bob.cli}, req,
		approvals.Assertion{Credential: f.bob.cred}); !errors.Is(err, approvals.ErrHumanSession) {
		t.Fatalf("an approval from the CLI: %v", err)
	}
	if _, err := f.svc.Approve(context.Background(), f.org, approvals.Responder{User: f.bob.id, Browser: f.bob.browser}, req,
		approvals.Assertion{Ceremony: f.ceremony(f.dave, req), Credential: f.bob.cred}); !errors.Is(err, approvals.ErrCeremony) {
		t.Fatalf("another person's ceremony: %v", err)
	}
	r, err := f.approve(f.bob, req)
	if err != nil || r.State != "APPROVED" || r.ConsumeBy == nil || r.ConsumeBy.After(r.DeadlineAt) {
		t.Fatalf("approval: %s %v, %v", r.State, r.ConsumeBy, err)
	}
	if s := f.str("SELECT state FROM pc.waitlist_entries WHERE subject_id = $1", req); s != "APPROVED" {
		t.Fatalf("entry %s", s)
	}
}

// TestHR036_TheLauncherNeitherApprovesNorDeclines (T-002): alice launched
// the run; even with the Approver role she cannot approve or decline, and
// she is told so (she may see the request), while a stranger gets "not
// found" (T-037).
func TestHR036_TheLauncherNeitherApprovesNorDeclines(t *testing.T) {
	f := newFx(t, 1)
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
		VALUES ($1, $2, 'approver', $3, 'ORG', 'user:'||$4::text, now() - interval '30 days')`, f.org, ids.NewV7(), f.alice.id, f.bob.id)
	req := f.request(1)
	if _, err := f.approve(f.alice, req); !errors.Is(err, approvals.ErrNotEligible) {
		t.Fatalf("the launcher approving: %v", err)
	}
	if _, err := f.svc.Decline(f.as(f.alice), req, "OTHER", "", ""); !errors.Is(err, approvals.ErrNotEligible) {
		t.Fatalf("the launcher declining: %v", err)
	}
	if _, err := f.svc.Decline(f.as(f.carol), req, "OTHER", "", ""); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("a stranger declining: %v, want not found", err)
	}
}

// TestHR035_TwoPeopleWithTwoKeys: a two-person requirement needs two
// people; the same person twice counts once; the second approval completes
// it and records the admins' notice.
func TestHR035_TwoPeopleWithTwoKeys(t *testing.T) {
	f := newFx(t, 2)
	req := f.request(2)
	if r, err := f.approve(f.bob, req); err != nil || r.State != "PENDING" {
		t.Fatalf("first approval: %s, %v", r.State, err)
	}
	if _, err := f.approve(f.bob, req); err == nil {
		t.Fatal("the same person approved twice")
	}
	if r, err := f.approve(f.dave, req); err != nil || r.State != "APPROVED" {
		t.Fatalf("second approval: %s, %v", r.State, err)
	}
	if s := f.str("SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.approval.multi_person_completed'"); s != "1" {
		t.Fatalf("%s multi-person notices", s)
	}
}

// TestHR172_EvidenceIsAskedForAndGivenByTheRun: a decider asks; only the
// run's launcher or principal (or its workload) answers, with untrusted,
// bounded notes; the request returns to PENDING.
func TestHR172_EvidenceIsAskedForAndGivenByTheRun(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	if _, err := f.svc.RequestEvidence(f.as(f.bob), req, "WHY_NEEDED", "", time.Now().Add(2*time.Hour)); !errors.Is(err, approvals.ErrEvidenceDeadline) {
		t.Fatalf("an evidence deadline after the deadline: %v", err)
	}
	r, err := f.svc.RequestEvidence(f.as(f.bob), req, "WHY_NEEDED", "which ticket?", time.Now().Add(10*time.Minute))
	if err != nil || r.State != "EVIDENCE_REQUESTED" {
		t.Fatalf("request evidence: %s, %v", r.State, err)
	}
	if _, _, err := f.svc.SubmitEvidence(f.as(f.carol), req, "trust me"); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("a stranger's evidence: %v", err)
	}
	r, ev, err := f.svc.SubmitEvidence(f.as(f.alice), req, "ticket 77: charged twice")
	if err != nil || r.State != "PENDING" || ev.IsZero() {
		t.Fatalf("evidence: %s %s, %v", r.State, ev, err)
	}
	for range 19 {
		if _, _, err := f.svc.SubmitEvidence(f.as(f.alice), req, "more"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.svc.SubmitEvidence(f.as(f.alice), req, "one too many"); !errors.Is(err, approvals.ErrTooMuchEvidence) {
		t.Fatalf("the 21st note: %v", err)
	}
}

// TestHR172_ANarrowerProposalEndsTheHeldAction: the proposal is simulated;
// validate_only changes nothing; otherwise the request ends DECLINED
// (NARROWER_PROPOSED) with the proposed parameters kept for the wait handle.
func TestHR172_ANarrowerProposalEndsTheHeldAction(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	params := []byte(`{"amount":{"value":"40.00","currency":"USD"},"reason":"duplicate"}`)
	p, err := f.svc.ProposeNarrower(f.as(f.bob), req, params, "", true)
	if err != nil || p.Request.State != "PENDING" || p.Simulation.Decision != "ALLOW" {
		t.Fatalf("validate only: %+v, %v", p.Request.State, err)
	}
	p, err = f.svc.ProposeNarrower(f.as(f.bob), req, params, "smaller first", false)
	if err != nil || p.Request.State != "DECLINED" || *p.Request.EndReason != "NARROWER_PROPOSED" {
		t.Fatalf("proposal: %s, %v", p.Request.State, err)
	}
	if s := f.str("SELECT proposed_params::text FROM pc.approval_responses WHERE request_id = $1", req); s == "" {
		t.Fatal("the proposal was not kept")
	}
}

func (f *fx) sweep() approvals.Swept {
	f.t.Helper()
	s, err := approvals.SweepOrg(context.Background(), f.p, nil, f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// TestHR039_TheJanitorExpiresOverdueRequests: the minute janitor records
// what use would decide anyway: an overdue request expires, its entry
// expires and its slots are freed.
func TestHR039_TheJanitorExpiresOverdueRequests(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	if s := f.sweep(); s.Expired+s.Invalidated != 0 {
		t.Fatalf("a waiting request was swept: %+v", s)
	}
	f.d.AdminExec(t, `UPDATE pc.approval_requests SET created_at = now() - interval '2 hours',
		deadline_at = date_trunc('second', now()) - interval '1 second' WHERE id = $1`, req)
	if s := f.sweep(); s.Expired != 1 {
		t.Fatalf("swept %+v", s)
	}
	if s := f.str("SELECT r.state || '/' || e.state FROM pc.approval_requests r JOIN pc.waitlist_entries e ON e.subject_id = r.id WHERE r.id = $1", req); s != "EXPIRED/EXPIRED" {
		t.Fatalf("request/entry %s", s)
	}
	if s := f.str("SELECT sum(pending)::text FROM pc.hold_slots"); s != "0" {
		t.Fatalf("slots %s", s)
	}
}

// TestHR171_ChangesInvalidateLiveRequests (decision 6, F153): a suspended
// agent, a revoked or revised grant, an ended run, the kill switch or a
// quarantined definition makes a live request moot; the janitor records it
// INVALIDATED with the change, and the next evaluation decides again.
func TestHR171_ChangesInvalidateLiveRequests(t *testing.T) {
	for _, c := range []struct {
		reason string
		change func(f *fx)
	}{
		{"AGENT_SUSPENDED", func(f *fx) {
			f.exec("UPDATE pc.agents SET state = 'SUSPENDED', suspended_from = 'DISCOVERED' WHERE id = $1", f.agent)
		}},
		{"GRANT_REVOKED", func(f *fx) {
			f.exec("UPDATE pc.grants SET state = 'REVOKED', revoked_at = now(), revoke_reason = 'test' WHERE id = $1", f.grant)
		}},
		{"GRANT_REVISED", func(f *fx) { f.d.AdminExec(f.t, "UPDATE pc.grants SET current_revision = 2 WHERE id = $1", f.grant) }},
		{"RUN_ENDED", func(f *fx) {
			f.exec("UPDATE pc.runs SET state = 'ENDED', end_reason = 'DONE', ended_at = now() WHERE id = $1", f.run)
		}},
		{"KILL_SWITCH_ENGAGED", func(f *fx) {
			f.d.AdminExec(f.t, "UPDATE pc.org_containment SET kill_switch = true, engaged_at = now(), engaged_by = 'test' WHERE org_id = $1", f.org)
		}},
		{"DEFINITION_CHANGED", func(f *fx) {
			f.exec("UPDATE pc.package_versions SET state = 'QUARANTINED'")
		}},
	} {
		t.Run(c.reason, func(t *testing.T) {
			f := newFx(t, 1)
			req := f.request(1)
			c.change(f)
			if s := f.sweep(); s.Invalidated != 1 {
				t.Fatalf("swept %+v", s)
			}
			if s := f.str("SELECT state || '/' || end_reason FROM pc.approval_requests WHERE id = $1", req); s != "INVALIDATED/"+c.reason {
				t.Fatalf("request %s", s)
			}
			if s := f.str("SELECT state FROM pc.waitlist_entries WHERE subject_id = $1", req); s != "CANCELLED" {
				t.Fatalf("entry %s", s)
			}
		})
	}
}

// TestHR170_RemovingTheRoleDisablingTheUserOrTheKeyVoidsResponses: an
// approval stops counting as soon as its person is no longer eligible; an
// approved request below its count returns to PENDING with a new entry.
func TestHR170_RemovingTheRoleDisablingTheUserOrTheKeyVoidsResponses(t *testing.T) {
	for _, c := range []struct {
		void   string
		change func(f *fx)
	}{
		{"ROLE_REMOVED", func(f *fx) { f.exec("DELETE FROM pc.role_bindings WHERE user_id = $1", f.bob.id) }},
		{"USER_DISABLED", func(f *fx) { f.exec("UPDATE pc.users SET state = 'DISABLED' WHERE id = $1", f.bob.id) }},
		{"CREDENTIAL_REMOVED", func(f *fx) {
			f.exec(`UPDATE pc.webauthn_credentials SET state = 'SUSPENDED', state_reason = 'CLONE_SUSPECTED', changed_at = now(),
				changed_by = 'test' WHERE id = $1`, f.bob.cred)
		}},
	} {
		t.Run(c.void, func(t *testing.T) {
			f := newFx(t, 1)
			req := f.request(1)
			if r, err := f.approve(f.bob, req); err != nil || r.State != "APPROVED" {
				t.Fatalf("approve: %v", err)
			}
			c.change(f)
			f.sweep()
			if s := f.str("SELECT void_reason FROM pc.approval_responses WHERE request_id = $1", req); s != c.void {
				t.Fatalf("void reason %s", s)
			}
			if s := f.str("SELECT state FROM pc.approval_requests WHERE id = $1", req); s != "PENDING" {
				t.Fatalf("request %s", s)
			}
			if s := f.str("SELECT count(*)::text FROM pc.waitlist_entries WHERE subject_id = $1 AND state = 'OPEN'", req); s != "1" {
				t.Fatalf("%s open entries", s)
			}
		})
	}
}

// TestHR033_OnlyAnEligibleDeciderGetsTheBindingToSign: approve-options
// gives the binding (the ceremony's challenge) only to a person who may
// approve now, once.
func TestHR033_OnlyAnEligibleDeciderGetsTheBindingToSign(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	ctx := context.Background()
	b, err := f.svc.BeginApproval(ctx, f.org, approvals.Responder{User: f.bob.id, Browser: f.bob.browser}, req)
	if err != nil || f.str("SELECT encode(binding, 'hex') FROM pc.approval_requests WHERE id = $1", req) != hexString(b[:]) {
		t.Fatalf("bob: %x, %v", b, err)
	}
	for name, p := range map[string]person{"the launcher": f.alice, "someone without the role": f.carol} {
		if _, err := f.svc.BeginApproval(ctx, f.org, approvals.Responder{User: p.id, Browser: p.browser}, req); !errors.Is(err, approvals.ErrNotEligible) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.BeginApproval(ctx, f.org, approvals.Responder{User: f.bob.id, CLI: f.bob.cli}, req); !errors.Is(err, approvals.ErrHumanSession) {
		t.Fatalf("from the CLI: %v", err)
	}
	if _, err := f.approve(f.bob, req); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginApproval(ctx, f.org, approvals.Responder{User: f.dave.id, Browser: f.dave.browser}, req); !errors.Is(err, approvals.ErrNotWaiting) {
		t.Fatalf("after approval: %v", err)
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
