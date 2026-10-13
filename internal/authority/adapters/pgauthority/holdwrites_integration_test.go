// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"strings"
	"sync"
	"testing"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// heldGrant issues a grant whose refunds over 50 USD need one approver.
func (w *world) heldGrant() gdomain.Grant {
	w.t.Helper()
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create", "payments.refund.get"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	reqs, err := gdomain.DecodeRequirements([]byte(`[{"operations": ["payments.refund.create"], "param": "amount",
	  "unless": {"max": {"USD": "50.00"}}, "approval": {"role": "approver", "count": 1}, "reason": "REFUND_OVER_50"}]`))
	if err != nil {
		w.t.Fatal(err)
	}
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Requirements: reqs, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (w *world) str(sql string, args ...any) string {
	w.t.Helper()
	var s string
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&s)
	}); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

// approve has bob, an Approver at org scope granted by alice, approve the
// request with his security key: the response the approval page records
// (slice 208), and the request APPROVED. It returns bob's role binding.
func (w *world) approve(request ids.UUID) ids.UUID {
	w.t.Helper()
	return w.approveAs(request, "approver")
}

// approveAs approves request as a new person holding role.
func (w *world) approveAs(request ids.UUID, role string) ids.UUID {
	w.t.Helper()
	bob, cred, session, binding := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	secret := make([]byte, 32)
	copy(secret, bob[:])
	exec(w.t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, bob, bob.String())
	exec(w.t, w.pool, w.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, $3, $4, 'ORG', $5)`, w.org, binding, role, bob, "user:"+w.alice.String())
	exec(w.t, w.pool, w.org, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`, w.org, cred, bob, secret[:16], secret)
	exec(w.t, w.pool, w.org, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, w.org, session, bob, secret)
	exec(w.t, w.pool, w.org, `INSERT INTO pc.approval_responses (org_id, id, request_id, user_id, session_id, kind, requirement,
		credential_id, authenticator_data, client_data_json, signature) VALUES ($1, $2, $3, $4, $5, 'APPROVE', 0, $6, $7, '\x7b7d', '\x01')`,
		w.org, ids.NewV7(), request, bob, session, cred, make([]byte, 37))
	exec(w.t, w.pool, w.org, `UPDATE pc.approval_requests SET state = 'APPROVED', approved_at = now(),
		consume_by = least(now() + interval '15 minutes', deadline_at) WHERE id = $1`, request)
	exec(w.t, w.pool, w.org, `UPDATE pc.waitlist_entries SET state = 'APPROVED', decided_by = 'test', decided_at = now()
		WHERE subject_id = $1 AND state = 'OPEN'`, request)
	return binding
}

func held(t *testing.T, r finalize.Result) ids.UUID {
	t.Helper()
	if r.Decision != adomain.RequireApproval || r.Wait == nil || r.Wait.RequestID.IsZero() || r.Wait.State != apdomain.WaitPending {
		t.Fatalf("not held: %s %s wait %+v", r.Decision, decisive(r), r.Wait)
	}
	return r.Wait.RequestID
}

// TestHR171_AHoldIsRecordedOnceAndSupersededWhenItsBindingChanges: the
// finalization that records a hold creates the request, its hold slots and
// its ACTION_HOLD entry; resubmitting while waiting creates nothing, and
// so does a fact observed again, which the approval does not bind (HR-030,
// founder decision 2026-10-13); a new policy version changes the binding,
// so the request is superseded, never updated.
func TestHR171_AHoldIsRecordedOnceAndSupersededWhenItsBindingChanges(t *testing.T) {
	w := newWorld(t)
	w.refundableAt(time.Now().Add(-2*time.Minute), "ch_1")
	g := w.heldGrant()
	run := w.run(g.ID, ids.UUID{})
	req := w.request(run, ids.NewV7(), "ch_1", "85.00")
	first := held(t, w.authorize(req))
	if again := held(t, w.authorize(req)); again != first {
		t.Fatalf("a resubmission while waiting made request %s, want %s kept", again, first)
	}
	if n := w.count("SELECT count(*) FROM pc.approval_requests"); n != 1 {
		t.Fatalf("%d requests", n)
	}
	if n := w.count("SELECT count(*) FROM pc.waitlist_entries WHERE kind = 'ACTION_HOLD' AND state = 'OPEN' AND subject_id = $1", first); n != 1 {
		t.Fatalf("%d open hold entries", n)
	}
	if n := w.count("SELECT pending FROM pc.hold_slots WHERE scope_kind = 'run' AND scope_id = $1", run); n != 1 {
		t.Fatalf("run slots %d", n)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.approval.requested'"); n != 1 {
		t.Fatalf("%d approval.requested events", n)
	}

	w.refundable("ch_1") // the same fact observed again: the same binding
	if again := held(t, w.authorize(req)); again != first {
		t.Fatalf("a re-observed fact made request %s, want %s kept", again, first)
	}
	w.publishPolicy(1, false, pgHoldOver50) // a new basis, so a new binding
	second := held(t, w.authorize(req))
	if second == first {
		t.Fatal("a changed binding kept the old request")
	}
	if s := w.str("SELECT state || '/' || end_reason FROM pc.approval_requests WHERE id = $1", first); s != "SUPERSEDED/BINDING_CHANGED" {
		t.Fatalf("old request %s", s)
	}
	if s := w.str("SELECT previous_id::text FROM pc.approval_requests WHERE id = $1", second); s != first.String() {
		t.Fatalf("previous %s", s)
	}
	if s := w.str("SELECT state FROM pc.waitlist_entries WHERE subject_id = $1", first); s != "CANCELLED" {
		t.Fatalf("old entry %s", s)
	}
	if n := w.count("SELECT pending FROM pc.hold_slots WHERE scope_kind = 'grant' AND scope_id = $1", g.ID.UUID()); n != 1 {
		t.Fatalf("grant slots %d after a supersede, want 1", n)
	}
	// A refund under 50 USD needs nothing and records nothing.
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "40.00")); r.Decision != adomain.Allow || r.Wait != nil {
		t.Fatalf("unheld refund: %s %+v", r.Decision, r.Wait)
	}
}

// TestRace_ApprovalConsumedOnce (HR-171, HR-005): concurrent resubmissions
// of an approved action get exactly one permit; the request is CONSUMED by
// it, and the permit's receipt names the request and its binding.
func TestRace_ApprovalConsumedOnce(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.heldGrant()
	req := w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "85.00")
	request := held(t, w.authorize(req))
	w.approve(request)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var permits []finalize.Result
	for range 20 {
		wg.Go(func() {
			r, err := w.auth.Authorize(context.Background(), w.gw, req)
			if err != nil {
				t.Error(err)
				return
			}
			if r.Decision != adomain.Allow {
				t.Errorf("a resubmission of the approved action: %s %s", r.Decision, decisive(r))
			}
			if r.Permit != "" {
				mu.Lock()
				permits = append(permits, r)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(permits) != 1 {
		t.Fatalf("%d permits, want exactly 1", len(permits))
	}
	if s := w.str("SELECT state || '/' || permit_id::text FROM pc.approval_requests WHERE id = $1", request); s != "CONSUMED/"+permits[0].PermitID.String() {
		t.Fatalf("request %s", s)
	}
	if !strings.Contains(receiptClaims(t, permits[0].Receipt), `"approval":{"request":"`+request.String()+`","binding":"`) {
		t.Fatal("the receipt does not name the approval")
	}
	if n := w.count("SELECT coalesce(sum(pending), 0)::int FROM pc.hold_slots"); n != 0 {
		t.Fatalf("%d slots still taken after consumption", n)
	}
}

// TestHR170_ConsumptionChecksEligibilityAgain (F149): when the approver
// loses the role between approving and the resubmission, the approval is
// not used; the response is voided and the request waits again.
func TestHR170_ConsumptionChecksEligibilityAgain(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.heldGrant()
	req := w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "85.00")
	request := held(t, w.authorize(req))
	binding := w.approve(request)
	exec(t, w.pool, w.org, "DELETE FROM pc.role_bindings WHERE id = $1", binding)
	r := w.authorize(req)
	if r.Decision != adomain.RequireApproval || r.Permit != "" {
		t.Fatalf("an approval by someone no longer eligible was used: %s %s", r.Decision, decisive(r))
	}
	if s := w.str("SELECT state FROM pc.approval_requests WHERE id = $1", request); s != "PENDING" {
		t.Fatalf("request %s, want PENDING", s)
	}
	if s := w.str("SELECT void_reason FROM pc.approval_responses WHERE request_id = $1", request); s != "ROLE_REMOVED" {
		t.Fatalf("void reason %s", s)
	}
	if n := w.count("SELECT count(*) FROM pc.waitlist_entries WHERE subject_id = $1 AND state = 'OPEN'", request); n != 1 {
		t.Fatalf("%d open entries after the request reopened", n)
	}
}

// TestRace_HoldCapUnderConcurrency (HR-037, decision 7): concurrent holds
// never exceed the cap; the rest are CANNOT_AUTHORIZE HOLD_LIMIT_REACHED.
func TestRace_HoldCapUnderConcurrency(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	exec(t, w.pool, w.org, "INSERT INTO pc.waitlist_settings (org_id, max_holds_per_run, updated_by) VALUES ($1, 2, 'test')", w.org)
	g := w.heldGrant()
	run := w.run(g.ID, ids.UUID{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]int{}
	for i := range 8 {
		wg.Go(func() {
			r, err := w.auth.Authorize(context.Background(), w.gw, w.request(run, ids.NewV7(), "ch_1", "6"+string(rune('0'+i))+".00"))
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			got[string(r.Decision)+"/"+decisive(r)]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if got["REQUIRE_APPROVAL/REFUND_OVER_50"] != 2 || got["CANNOT_AUTHORIZE/"+apdomain.ReasonHoldLimitReached] != 6 {
		t.Fatalf("decisions %v, want 2 holds and 6 HOLD_LIMIT_REACHED", got)
	}
	if n := w.count("SELECT pending FROM pc.hold_slots WHERE scope_kind = 'run' AND scope_id = $1", run); n != 2 {
		t.Fatalf("run slots %d", n)
	}
}

// TestHR171_NoHoldIsRecordedUnderTheKillSwitch: containment refuses the
// action, and the finalization records no request.
func TestHR171_NoHoldIsRecordedUnderTheKillSwitch(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.heldGrant()
	run := w.run(g.ID, ids.UUID{})
	w.db.AdminExec(t, "UPDATE pc.org_containment SET epoch = epoch + 1, kill_switch = true, engaged_at = now(), engaged_by = 'test' WHERE org_id = $1", w.org)
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "85.00")); r.Decision != adomain.Deny || r.Wait != nil {
		t.Fatalf("under the kill switch: %s %s %+v", r.Decision, decisive(r), r.Wait)
	}
	if n := w.count("SELECT count(*) FROM pc.approval_requests"); n != 0 {
		t.Fatalf("%d requests recorded under the kill switch", n)
	}
}

// TestHR039_AnExpiredHoldEndsAsDenyAtUse: a hold past its deadline is
// DENY APPROVAL_EXPIRED when the agent resubmits, whether or not the
// janitor ran; the request is recorded EXPIRED and its slots are freed.
func TestHR039_AnExpiredHoldEndsAsDenyAtUse(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.heldGrant()
	req := w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "85.00")
	request := held(t, w.authorize(req))
	w.db.AdminExec(t, `UPDATE pc.approval_requests SET created_at = now() - interval '2 hours',
		deadline_at = date_trunc('second', now()) - interval '1 second' WHERE id = $1`, request)
	r := w.authorize(req)
	if r.Decision != adomain.Deny || decisive(r) != apdomain.ReasonApprovalExpired || r.Wait == nil || r.Wait.State != apdomain.WaitExpired {
		t.Fatalf("expired hold: %s %s %+v", r.Decision, decisive(r), r.Wait)
	}
	if s := w.str("SELECT state FROM pc.approval_requests WHERE id = $1", request); s != "EXPIRED" {
		t.Fatalf("request %s", s)
	}
	if n := w.count("SELECT coalesce(sum(pending), 0)::int FROM pc.hold_slots"); n != 0 {
		t.Fatalf("%d slots after expiry", n)
	}
	if again := w.authorize(req); !again.Repeat || again.Decision != adomain.Deny {
		t.Fatalf("an expired action is terminal: %+v", again)
	}
}

// TestHR037_TheThirdVariantRaisesASignal: three held variants of one
// grant, operation and target within 24 hours raise
// security.variant_suspected (the detection rule is M10).
func TestHR037_TheThirdVariantRaisesASignal(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.heldGrant()
	run := w.run(g.ID, ids.UUID{})
	for i, amount := range []string{"85.00", "84.00", "83.00"} {
		held(t, w.authorize(w.request(run, ids.NewV7(), "ch_1", amount)))
		want := 0
		if i == 2 {
			want = 1
		}
		if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.security.variant_suspected'"); n != want {
			t.Fatalf("after variant %d: %d signals, want %d", i+1, n, want)
		}
	}
}

// receiptClaims returns a receipt JWS's payload.
func receiptClaims(t *testing.T, jws string) string {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("receipt %q is not a compact JWS", jws)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// refundableAt reports a "refundable" fact observed at t, as the provider.
func (w *world) refundableAt(t time.Time, charge string) {
	w.t.Helper()
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{
		Org:       w.org,
		Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing},
	}})
	res, err := w.facts.PutFacts(ctx, []fdomain.Observation{{
		Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: charge,
		Value: jsontext.Value(`{"bool": true}`), ObservedAt: t,
	}})
	if err != nil || res[0].Err != nil {
		w.t.Fatalf("fact: %v %v", err, res)
	}
}
