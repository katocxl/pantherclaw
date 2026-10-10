// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// heldRequest inserts an approval request held for the env's org (with the
// agent, run, grant and transaction it needs) and returns its id and
// binding.
func (e *waEnv) heldRequest(t *testing.T) (ids.UUID, [32]byte) {
	t.Helper()
	env, agent, run, grant, txn, req := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	binding := sha256.Sum256(req[:])
	e.exec(t, e.org, "INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, $3, 'Dev', 'DEVELOPMENT')", e.org, env, "dev-"+env.String()[28:])
	e.exec(t, e.org, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", e.org, agent)
	e.exec(t, e.org, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, e.org, run, agent, env, e.user)
	e.exec(t, e.org, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, e.org, grant, agent, e.user, env)
	e.exec(t, e.org, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'R', 'gw', 'OPEN')`, e.org, txn, run, ids.NewV7(), binding[:])
	e.exec(t, e.org, `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'payments.refund.create', $7, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1}]', '{}', $7, '\x7b7d', date_trunc('second', now()) + interval '1 hour')`,
		e.org, req, agent, txn, run, grant, binding[:])
	return req, binding
}

// TestHR033_TheBindingCeremonySignsExactlyTheBinding (design decision 12):
// the approval ceremony's challenge is the request's binding; the verified
// assertion names the request, the key, and the parts kept for M6; the
// ceremony stays open for the approvals use case to consume with the
// response, and is spent on any failure.
func TestHR033_TheBindingCeremonySignsExactlyTheBinding(t *testing.T) {
	e := newWAEnv(t)
	ctx := context.Background()
	s, _ := e.session(t, true)
	a := e.authenticator(t, webauthntest.ES256)
	key, err := e.register(t, s, a, "key")
	if err != nil {
		t.Fatal(err)
	}
	req, binding := e.heldRequest(t)
	c, err := e.wa.BeginBinding(ctx, s, authnapp.BindingSubject{Request: req}, binding)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Assert(c.Options)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.wa.VerifyBinding(ctx, s, c.ID, resp)
	if err != nil {
		t.Fatal(err)
	}
	if got.Challenge != binding || got.Subject.Request != req || got.Credential != key.ID || got.Ceremony != c.ID ||
		len(got.AuthenticatorData) < 37 || len(got.Signature) == 0 || len(got.ClientDataJSON) == 0 {
		t.Fatalf("assertion %+v", got)
	}
	// A used (spent) ceremony refuses a fresh assertion.
	e.wa.SpendBinding(ctx, s, c.ID)
	resp, _ = a.Assert(c.Options)
	if _, err := e.wa.VerifyBinding(ctx, s, c.ID, resp); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Fatalf("a used ceremony: %v", err)
	}

	// Without user verification: refused, and the ceremony is spent.
	a.NoUV = true
	c, _ = e.wa.BeginBinding(ctx, s, authnapp.BindingSubject{Request: req}, binding)
	resp, _ = a.Assert(c.Options)
	if _, err := e.wa.VerifyBinding(ctx, s, c.ID, resp); !errors.Is(err, authnapp.ErrWebAuthnFailed) {
		t.Fatalf("no UV: %v", err)
	}
	a.NoUV = false
	resp, _ = a.Assert(c.Options)
	if _, err := e.wa.VerifyBinding(ctx, s, c.ID, resp); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Fatalf("a ceremony spent by a failure: %v", err)
	}

	// From another browser session of the same person: refused.
	other, _ := e.session(t, true)
	c, _ = e.wa.BeginBinding(ctx, s, authnapp.BindingSubject{Request: req}, binding)
	resp, _ = a.Assert(c.Options)
	if _, err := e.wa.VerifyBinding(ctx, other, c.ID, resp); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Fatalf("another session: %v", err)
	}

	// An assertion over another request's binding: refused.
	req2, binding2 := e.heldRequest(t)
	c1, _ := e.wa.BeginBinding(ctx, s, authnapp.BindingSubject{Request: req}, binding)
	c2, _ := e.wa.BeginBinding(ctx, s, authnapp.BindingSubject{Request: req2}, binding2)
	resp, _ = a.Assert(c2.Options)
	if _, err := e.wa.VerifyBinding(ctx, s, c1.ID, resp); !errors.Is(err, authnapp.ErrWebAuthnFailed) {
		t.Fatalf("another request's binding: %v", err)
	}
	if _, err := e.wa.BeginBinding(ctx, s, authnapp.BindingSubject{}, binding); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Fatalf("a ceremony about nothing: %v", err)
	}
}
