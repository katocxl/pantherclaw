// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// edition is a fixed edition.
type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Edition(e)
	return x, nil
}

// held adds a transaction of the run and its PENDING request for
// operation, needing one approver.
func (f *fx) held(operation string) ids.UUID {
	f.t.Helper()
	txn, id := ids.NewV7(), ids.NewV7()
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'REQUIRE_APPROVAL', 'R', 'gw', 'OPEN')`, f.org, txn, f.run, ids.NewV7(), make([]byte, 32), operation)
	binding := append(append([]byte{}, id[:]...), id[:]...)
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, $8, $7, '\x7b7d', '[{"kind":"approval","role":"approver","count":1,"sources":[]}]',
		'{}', $7, convert_to('{"definition":{"package":"pc.mock-payments","version":"1.0.0"}}', 'UTF8'),
		date_trunc('second', now()) + interval '1 hour')`, f.org, id, f.agent, txn, f.run, f.grant, binding, operation)
	f.exec(`INSERT INTO pc.hold_slots (org_id, scope_kind, scope_id, pending) VALUES ($1, 'grant', $2, 1), ($1, 'run', $3, 1)
		ON CONFLICT (org_id, scope_kind, scope_id) DO UPDATE SET pending = pc.hold_slots.pending + 1`, f.org, f.grant, f.run)
	return id
}

// TestHR175_ABatchDeclineIsAllOrNothingAndRecordsEachResponse: Team
// edition only; every request must be one the caller may decline and of
// one operation; each gets its own response tied to the recorded batch.
func TestHR175_ABatchDeclineIsAllOrNothingAndRecordsEachResponse(t *testing.T) {
	f := newFx(t, 1)
	a, b := f.held("payments.refund.create"), f.held("payments.refund.create")
	if _, _, err := f.svc.DeclineBatch(f.as(f.bob), []ids.UUID{a, b}, "TOO_RISKY", ""); !errors.Is(err, approvals.ErrEditionRequired) {
		t.Fatalf("without an edition: %v", err)
	}
	f.svc.Ents = edition(billing.Community)
	if _, _, err := f.svc.DeclineBatch(f.as(f.bob), []ids.UUID{a, b}, "TOO_RISKY", ""); !errors.Is(err, approvals.ErrEditionRequired) {
		t.Fatalf("Community: %v", err)
	}
	f.svc.Ents = edition(billing.Team)
	other := f.held("payments.charge.capture")
	if _, _, err := f.svc.DeclineBatch(f.as(f.bob), []ids.UUID{a, other}, "TOO_RISKY", ""); !errors.Is(err, approvals.ErrBatchInvalid) {
		t.Fatalf("two operations: %v", err)
	}
	if _, _, err := f.svc.DeclineBatch(f.as(f.alice), []ids.UUID{a, b}, "TOO_RISKY", ""); err == nil {
		t.Fatal("the launcher declined a batch")
	}
	if s := f.str("SELECT count(*)::text FROM pc.approval_requests WHERE id IN ($1, $2) AND state = 'PENDING'", a, b); s != "2" {
		t.Fatalf("a refused batch changed %s requests", s)
	}
	batch, rows, err := f.svc.DeclineBatch(f.as(f.bob), []ids.UUID{b, a}, "NOT_NEEDED", "already refunded")
	if err != nil || len(rows) != 2 || rows[0].State != "DECLINED" || rows[1].State != "DECLINED" {
		t.Fatalf("decline: %v %v", rows, err)
	}
	if s := f.str(`SELECT count(*)::text FROM pc.approval_responses WHERE batch_id = $1 AND kind = 'DECLINE' AND reason_code = 'NOT_NEEDED'`, batch); s != "2" {
		t.Fatalf("%s responses in the batch", s)
	}
	if s := f.str("SELECT kind || ' ' || state || ' ' || cardinality(request_ids) FROM pc.approval_batches WHERE id = $1", batch); s != "DECLINE COMPLETED 2" {
		t.Fatalf("batch %q", s)
	}
	if s := f.str("SELECT count(*)::text FROM pc.ledger_entries WHERE kind IN ('audit.approval.declined', 'audit.approval.batch_declined')"); s != "3" {
		t.Fatalf("%s audit events", s)
	}
}

// releaseDefs pins every action to a reversible definition with one money
// parameter.
type releaseDefs struct{}

func (releaseDefs) PinnedInTx(context.Context, db.TenantTx, ids.OrgID, actionir.Definition) (*defs.Definition, defs.State, error) {
	return &defs.Definition{
		Operation: "payments.hold.release", Reversibility: defs.Reversible,
		Params: map[string]defs.ParamSpec{"amount": {Type: defs.TypeMoney, Required: true, Currencies: []string{"USD"}}},
	}, defs.StateActive, nil
}

// release adds a held release of amount USD needing one approver.
func (f *fx) release(amount string) ids.UUID {
	f.t.Helper()
	id := f.held("payments.hold.release")
	f.d.AdminExec(f.t, `UPDATE pc.approval_requests SET action_ir = convert_to($1, 'UTF8') WHERE id = $2`,
		`{"definition":{"package":"pc.mock-payments","version":"1.0.0","digest":"sha256:aa"},"params":{"amount":{"value":"`+amount+`","currency":"USD"}}}`, id)
	return id
}

// TestHR175_ABatchApprovalSignsExactlyItsBindings: only batchable holds of
// one operation; one ceremony over the hash of their bindings; each gets
// its own approval; a ceremony is used once.
func TestHR175_ABatchApprovalSignsExactlyItsBindings(t *testing.T) {
	f := newFx(t, 1)
	f.svc.Ents, f.svc.Defs = edition(billing.Team), releaseDefs{}
	f.exec(`INSERT INTO pc.waitlist_settings (org_id, batch_ceilings, updated_by) VALUES ($1, '{"USD": "100.00"}', 'test')`, f.org)
	a, b, big := f.release("40.00"), f.release("60.00"), f.release("500.00")
	bob := approvals.Responder{User: f.bob.id, Browser: f.bob.browser}
	if _, _, err := f.svc.BeginBatch(f.as(f.bob), f.org, bob, []ids.UUID{a, big}); pcerr.ReasonOf(err) != apdomain.BatchOverCeiling {
		t.Fatalf("over the ceiling: %v", err)
	}
	f.svc.Defs = nil
	if _, _, err := f.svc.BeginBatch(f.as(f.bob), f.org, bob, []ids.UUID{a, b}); err == nil {
		t.Fatal("a batch without the definitions store")
	}
	f.svc.Defs = releaseDefs{}
	if _, _, err := f.svc.BeginBatch(f.as(f.alice), f.org, approvals.Responder{User: f.alice.id, Browser: f.alice.browser},
		[]ids.UUID{a, b}); err == nil {
		t.Fatal("the launcher began a batch")
	}
	if s := f.str("SELECT count(*)::text FROM pc.approval_batches"); s != "0" {
		t.Fatalf("%s refused batches recorded", s)
	}
	batch, hash, err := f.svc.BeginBatch(f.as(f.bob), f.org, bob, []ids.UUID{b, a})
	if err != nil {
		t.Fatal(err)
	}
	var bindings [][32]byte
	for _, id := range []ids.UUID{a, b} {
		var x [32]byte
		copy(x[:], append(append([]byte{}, id[:]...), id[:]...))
		bindings = append(bindings, x)
	}
	if want, _ := apdomain.BatchChallenge(bindings); want.Hash != hash {
		t.Fatal("the challenge is not the hash of the batch's bindings")
	}
	ceremony := ids.NewV7()
	f.exec(`INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, batch_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, f.org, ceremony, f.bob.browser, f.bob.id, hash[:], batch)
	assertion := approvals.Assertion{Ceremony: ceremony, Credential: f.bob.cred, AuthenticatorData: make([]byte, 37), ClientDataJSON: []byte(`{}`), Signature: []byte{1}}
	rows, err := f.svc.ApproveBatch(context.Background(), f.org, bob, batch, assertion)
	if err != nil || len(rows) != 2 || rows[0].State != "APPROVED" || rows[1].State != "APPROVED" {
		t.Fatalf("approve: %v, %v", rows, err)
	}
	if s := f.str("SELECT count(*)::text FROM pc.approval_responses WHERE batch_id = $1 AND kind = 'APPROVE'", batch); s != "2" {
		t.Fatalf("%s responses", s)
	}
	if s := f.str("SELECT state FROM pc.approval_batches WHERE id = $1", batch); s != "COMPLETED" {
		t.Fatalf("batch %s", s)
	}
	if _, err := f.svc.ApproveBatch(context.Background(), f.org, bob, batch, assertion); !errors.Is(err, approvals.ErrCeremony) {
		t.Fatalf("a used ceremony: %v", err)
	}
}
