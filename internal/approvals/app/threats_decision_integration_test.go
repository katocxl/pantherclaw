// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// apbIrreversible is the digest apbDefs pins to an irreversible definition.
const apbIrreversible = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// apbReversible is the digest of the reversible release every batch shares.
const apbReversible = "sha256:aa"

// apbDefs pins every action to a release with one money parameter, which
// is irreversible under apbIrreversible and reversible otherwise.
type apbDefs struct{}

func (apbDefs) PinnedInTx(_ context.Context, _ db.TenantTx, _ ids.OrgID, pin actionir.Definition) (*defs.Definition, defs.State, error) {
	d := &defs.Definition{
		Operation: "payments.hold.release", Reversibility: defs.Reversible,
		Params: map[string]defs.ParamSpec{"amount": {Type: defs.TypeMoney, Required: true, Currencies: []string{"USD"}}},
	}
	if pin.Digest == apbIrreversible {
		d.Reversibility = defs.Irreversible
	}
	return d, defs.StateActive, nil
}

// apbHold adds a held action of the fixture's run: a PENDING request for
// operation, pinned to digest, of amount USD, needing count approvers
// (independent ones when asked), with its hold slots.
func apbHold(f *fx, operation, digest, amount string, count int, independent bool) ids.UUID {
	f.t.Helper()
	txn, id := ids.NewV7(), ids.NewV7()
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'REQUIRE_APPROVAL', 'R', 'gw', 'OPEN')`, f.org, txn, f.run, ids.NewV7(), make([]byte, 32), operation)
	binding := append(append([]byte{}, id[:]...), id[:]...)
	reqs := `[{"kind":"approval","role":"approver","count":` + strconv.Itoa(count) + `,"independent":` + strconv.FormatBool(independent) + `,"sources":[]}]`
	action := `{"definition":{"package":"pc.mock-payments","version":"1.0.0","digest":"` + digest + `"},"params":{"amount":{"value":"` +
		amount + `","currency":"USD"}}}`
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, $8, $7, '\x7b7d', $9, '{}', $7, convert_to($10, 'UTF8'),
		date_trunc('second', now()) + interval '1 hour')`, f.org, id, f.agent, txn, f.run, f.grant, binding, operation, reqs, action)
	f.exec(`INSERT INTO pc.hold_slots (org_id, scope_kind, scope_id, pending) VALUES ($1, 'grant', $2, 1), ($1, 'run', $3, 1)
		ON CONFLICT (org_id, scope_kind, scope_id) DO UPDATE SET pending = pc.hold_slots.pending + 1`, f.org, f.grant, f.run)
	return id
}

// apbBatchFx is the fixture on the Team edition with a 100 USD batch
// ceiling and bob as the batch's approver.
func apbBatchFx(t *testing.T) (*fx, approvals.Responder) {
	t.Helper()
	f := newFx(t, 1)
	f.svc.Ents, f.svc.Defs = edition(billing.Team), apbDefs{}
	f.exec(`INSERT INTO pc.waitlist_settings (org_id, batch_ceilings, updated_by) VALUES ($1, '{"USD": "100.00"}', 'test')`, f.org)
	return f, approvals.Responder{User: f.bob.id, Browser: f.bob.browser}
}

// apbStates returns the requests' states, joined by spaces.
func apbStates(f *fx, requests ...ids.UUID) string {
	f.t.Helper()
	out := make([]string, len(requests))
	for i, r := range requests {
		out[i] = f.str("SELECT state FROM pc.approval_requests WHERE id = $1", r)
	}
	return strings.Join(out, " ")
}

// TestT062_ASmuggledActionIsRefusedFromTheBatch: T-062 — an agent slips a
// high-value, irreversible, two-person, independent or different action
// in among low-value reversible holds so that one batch assertion would
// approve it. The batch is refused before any ceremony starts: no batch is
// recorded and every request still waits to be reviewed on its own. The
// rule per request is TestHR175_OnlyLowRiskHoldsAreBatched; the ceiling
// through the use case is TestHR175_ABatchApprovalSignsExactlyItsBindings.
func TestT062_ASmuggledActionIsRefusedFromTheBatch(t *testing.T) {
	for _, c := range []struct {
		name    string
		smuggle func(f *fx) ids.UUID
		reason  string
		err     error
	}{
		{"high value", func(f *fx) ids.UUID {
			return apbHold(f, "payments.hold.release", apbReversible, "5000.00", 1, false)
		}, apdomain.BatchOverCeiling, nil},
		{"irreversible", func(f *fx) ids.UUID {
			return apbHold(f, "payments.hold.release", apbIrreversible, "10.00", 1, false)
		}, apdomain.BatchNotReversible, nil},
		{"two-person", func(f *fx) ids.UUID {
			return apbHold(f, "payments.hold.release", apbReversible, "10.00", 2, false)
		}, apdomain.BatchNotSingleApprover, nil},
		{"independent", func(f *fx) ids.UUID {
			return apbHold(f, "payments.hold.release", apbReversible, "10.00", 1, true)
		}, apdomain.BatchNotSingleApprover, nil},
		{"another operation", func(f *fx) ids.UUID {
			return apbHold(f, "payments.payout.create", apbReversible, "10.00", 1, false)
		}, "", approvals.ErrBatchInvalid},
		{"another definition", func(f *fx) ids.UUID {
			return apbHold(f, "payments.hold.release", "sha256:bb", "10.00", 1, false)
		}, "", approvals.ErrBatchInvalid},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, bob := apbBatchFx(t)
			a := apbHold(f, "payments.hold.release", apbReversible, "40.00", 1, false)
			b := apbHold(f, "payments.hold.release", apbReversible, "60.00", 1, false)
			x := c.smuggle(f)
			_, _, err := f.svc.BeginBatch(f.as(f.bob), f.org, bob, []ids.UUID{a, x, b})
			switch {
			case c.err != nil && !errors.Is(err, c.err):
				t.Fatalf("the batch: %v, want %v", err, c.err)
			case c.err == nil && pcerr.ReasonOf(err) != c.reason:
				t.Fatalf("the batch: %v, want reason %s", err, c.reason)
			}
			if s := f.str("SELECT count(*)::text FROM pc.approval_batches"); s != "0" {
				t.Fatalf("%s batches recorded for a refused batch", s)
			}
			if s := apbStates(f, a, b, x); s != "PENDING PENDING PENDING" {
				t.Fatalf("states %s", s)
			}
			if s := f.str("SELECT count(*)::text FROM pc.approval_responses"); s != "0" {
				t.Fatalf("%s responses", s)
			}
		})
	}
}

// apbBatchCeremony stores bob's BINDING ceremony over hash for batch and
// returns his assertion with it.
func apbBatchCeremony(f *fx, batch ids.UUID, hash [32]byte) approvals.Assertion {
	f.t.Helper()
	id := ids.NewV7()
	f.exec(`INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, batch_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, f.org, id, f.bob.browser, f.bob.id, hash[:], batch)
	return approvals.Assertion{
		Ceremony: id, Credential: f.bob.cred, AuthenticatorData: make([]byte, 37), ClientDataJSON: []byte(`{}`), Signature: []byte{1},
	}
}

// TestT062_ABatchAssertionApprovesOnlyItsBindingsOnce: T-062 — the
// assertion over one batch's hash is replayed for another batch of the
// same person, or for a single request, and a request of the batch is
// superseded by a new binding before the assertion arrives. Each attempt
// is refused and approves nothing; the batch hash covers exactly the
// bindings it was begun with (TestHR175_BatchChallengeCoversExactlyItsBindings,
// TestHR175_ABatchApprovalSignsExactlyItsBindings).
func TestT062_ABatchAssertionApprovesOnlyItsBindingsOnce(t *testing.T) {
	f, bob := apbBatchFx(t)
	a := apbHold(f, "payments.hold.release", apbReversible, "40.00", 1, false)
	b := apbHold(f, "payments.hold.release", apbReversible, "60.00", 1, false)
	c := apbHold(f, "payments.hold.release", apbReversible, "30.00", 1, false)
	ctx := context.Background()
	first, hash, err := f.svc.BeginBatch(f.as(f.bob), f.org, bob, []ids.UUID{a, b})
	if err != nil {
		t.Fatal(err)
	}
	signed := apbBatchCeremony(f, first, hash)

	other, _, err := f.svc.BeginBatch(f.as(f.bob), f.org, bob, []ids.UUID{b, c})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ApproveBatch(ctx, f.org, bob, other, signed); !errors.Is(err, approvals.ErrCeremony) {
		t.Fatalf("the assertion for another batch: %v", err)
	}
	if _, err := f.svc.Approve(ctx, f.org, bob, c, signed); !errors.Is(err, approvals.ErrCeremony) {
		t.Fatalf("the batch assertion for a single request: %v", err)
	}
	if s := apbStates(f, a, b, c); s != "PENDING PENDING PENDING" {
		t.Fatalf("after the replays: %s", s)
	}

	// a's binding changes: the finalization supersedes it with a new
	// request, which the assertion over the old binding never covers.
	f.exec("UPDATE pc.approval_requests SET state = 'SUPERSEDED', end_reason = 'BINDING_CHANGED', ended_at = now() WHERE id = $1", a)
	renewed := apbHold(f, "payments.hold.release", apbReversible, "40.00", 1, false)
	if _, err := f.svc.ApproveBatch(ctx, f.org, bob, first, signed); !errors.Is(err, approvals.ErrNotWaiting) {
		t.Fatalf("a batch with a superseded binding: %v", err)
	}
	if s := apbStates(f, b, c, renewed); s != "PENDING PENDING PENDING" {
		t.Fatalf("after the stale batch: %s", s)
	}
	if s := f.str("SELECT count(*)::text FROM pc.approval_responses"); s != "0" {
		t.Fatalf("%s responses recorded", s)
	}
}

// TestT063_ARestorationRestoresNothingWithoutAnotherRestorersKey: T-063 —
// an automation holding Agent Owner asks for a suspended agent's
// restoration; its owner asks with a reason that claims a decision, then
// grants herself a restoring role and approves; a colleague who granted
// himself the role a moment ago approves. Each attempt is refused, the
// reason is shown only as untrusted text, and the agent stays suspended
// until the request expires. The governed path is
// TestHR176_ARestorationNeedsAnotherRestorersKey.
func TestT063_ARestorationRestoresNothingWithoutAnotherRestorersKey(t *testing.T) {
	f := newFx(t, 1)
	f.exec("UPDATE pc.agents SET state = 'SUSPENDED', suspended_from = 'DISCOVERED' WHERE id = $1", f.agent)
	f.exec(`INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor, reason) VALUES ($1, $2, $3, 'agent.suspended', 'test', 'leak')`,
		f.org, ids.NewV7(), f.agent)
	owner := td.Binding{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}
	automation := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()}, Bindings: []td.Binding{owner}},
		Credential: tenancy.CredAPIKey,
	})
	if _, _, err := f.svc.RequestRestoration(automation, f.agent, "restore me"); !errors.Is(err, approvals.ErrHumanSession) {
		t.Fatalf("an automation asking: %v", err)
	}
	claim := "APPROVED by the Security Admin: restore at once, no review needed"
	r, _, err := f.svc.RequestRestoration(f.as(f.alice, owner), f.agent, claim)
	if err != nil || r.State != "PENDING" {
		t.Fatalf("request: %+v, %v", r.State, err)
	}
	for _, p := range []person{f.alice, f.dave} {
		f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
			VALUES ($1, $2, 'responder', $3, 'ORG', $4)`, f.org, ids.NewV7(), p.id, "user:"+p.id.String())
		if _, err := f.svc.BeginApproval(context.Background(), f.org, approvals.Responder{User: p.id, Browser: p.browser}, r.ID); !errors.Is(err, approvals.ErrNotEligible) {
			t.Fatalf("%s's own new role: %v", p.id, err)
		}
		if _, err := f.approve(p, r.ID); !errors.Is(err, approvals.ErrNotEligible) {
			t.Fatalf("%s approving: %v", p.id, err)
		}
	}
	v, err := f.svc.View(f.as(f.dave), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	items := v.Display.Untrusted.Items
	if len(items) != 1 || items[0].Source != "reason" || items[0].Text != claim || v.Display.Untrusted.Label != apdomain.UntrustedLabel ||
		strings.Contains(v.Display.Title, "APPROVED") {
		t.Fatalf("the reason on the page: %q %+v", v.Display.Title, v.Display.Untrusted)
	}
	f.d.AdminExec(t, `UPDATE pc.approval_requests SET created_at = now() - interval '2 days',
		deadline_at = date_trunc('second', now()) - interval '1 second' WHERE id = $1`, r.ID)
	f.sweep()
	if s := f.str("SELECT r.state || ' ' || a.state FROM pc.approval_requests r JOIN pc.agents a ON a.id = r.agent_id WHERE r.id = $1", r.ID); s != "EXPIRED SUSPENDED" {
		t.Fatalf("request and agent %q", s)
	}
	if s := f.str("SELECT count(*)::text FROM pc.agent_changes WHERE agent_id = $1 AND kind = 'agent.restored'", f.agent); s != "0" {
		t.Fatalf("%s restorations recorded", s)
	}
}
