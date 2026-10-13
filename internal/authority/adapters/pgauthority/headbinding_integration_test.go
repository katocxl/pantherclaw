// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// boundRefunds binds a refund's reason to the charge's state object, as
// pc.github binds a merge to its pull request's head, and names that fact
// as the one whose change supersedes the refund's approval requests.
func boundRefunds(pkg string) string {
	pkg = strings.Replace(pkg, "      - fact: payments.charge.refundable\n        max_age_seconds: 300\n",
		"      - fact: payments.charge.refundable\n        max_age_seconds: 300\n      - fact: payments.charge.state\n"+
			"        max_age_seconds: 300\n        binds: {member: reason, param: reason, reason: STATE_MOVED}\n", 1)
	return strings.Replace(pkg, "      fields: [params.amount, params.reason, target.id]\n",
		"      fields: [params.amount, params.reason, target.id]\n      invalidate_on: payments.charge.state\n", 1)
}

// state pushes the charge's state object, as the provider.
func (w *world) state(charge, reason string) {
	w.t.Helper()
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing}}})
	res, err := w.facts.PutFacts(ctx, []fdomain.Observation{{
		Name: "payments.charge.state", SubjectType: "payments.charge", SubjectID: charge,
		Value: jsontext.Value(`{"object": {"reason": "` + reason + `"}}`), ObservedAt: time.Now().Add(-time.Second),
	}})
	if err != nil || len(res) != 1 || res[0].Err != nil {
		w.t.Fatalf("state: %v %+v", err, res)
	}
}

// TestHR205_ANewHeadSupersedesTheRequestsBoundToTheOldOne: an action held
// for approval records the key of the fact it is bound to; when that fact
// changes (a pull request's new head), every live request with the key is
// superseded in the same transaction, released and audited, and only
// those. A new decision at the old value is CANNOT_AUTHORIZE with the
// binding's reason, never a quiet approval of what moved.
func TestHR205_ANewHeadSupersedesTheRequestsBoundToTheOldOne(t *testing.T) {
	w := newWorldWith(t, boundRefunds)
	w.refundable("ch_1", "ch_2")
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Requirements: []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.refund.create"}, Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
			Reason: "REFUNDS_NEED_APPROVAL",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	run := w.run(g.ID, ids.UUID{})
	w.state("ch_1", "duplicate")
	w.state("ch_2", "duplicate")
	held := map[string]ids.UUID{}
	for _, ch := range []string{"ch_1", "ch_2"} {
		r := w.authorize(w.request(run, ids.NewV7(), ch, "30.00"))
		if r.Decision != adomain.RequireApproval || r.Wait == nil || r.Wait.RequestID.IsZero() {
			t.Fatalf("%s: %s %+v", ch, r.Decision, r.Wait)
		}
		held[ch] = r.Wait.RequestID
	}
	request := func(id ids.UUID) (state, key, end string) {
		t.Helper()
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT state, coalesce(invalidation_key, ''), coalesce(end_reason, '') FROM pc.approval_requests
				WHERE org_id = $1 AND id = $2`, w.org, id).Scan(&state, &key, &end)
		}); err != nil {
			t.Fatal(err)
		}
		return state, key, end
	}
	if state, key, _ := request(held["ch_1"]); state != "PENDING" || key != "payments.charge.state@payments.charge:ch_1" {
		t.Fatalf("held: %s %q", state, key)
	}

	w.state("ch_1", "duplicate") // the same value: nothing moved
	if state, _, _ := request(held["ch_1"]); state != "PENDING" {
		t.Fatalf("an unchanged fact superseded it: %s", state)
	}
	w.state("ch_1", "fraudulent")
	if state, _, end := request(held["ch_1"]); state != "SUPERSEDED" || end != "BINDING_CHANGED" {
		t.Fatalf("after the change: %s %s", state, end)
	}
	if state, _, _ := request(held["ch_2"]); state != "PENDING" {
		t.Fatalf("another target's request: %s", state)
	}
	var audited int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.approval.superseded'
			AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $2
			AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'changed' = 'payments.charge.state@payments.charge:ch_1'`, w.org, held["ch_1"].String()).Scan(&audited)
	}); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("%d audit events", audited)
	}
	r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00"))
	if r.Decision != adomain.CannotAuthorize || decisive(r) != "STATE_MOVED" {
		t.Fatalf("at the old value: %s %s", r.Decision, decisive(r))
	}
}

// longCharges is boundRefunds with charge ids of up to 300 characters, so
// an invalidation key can be longer than its column.
func longCharges(pkg string) string {
	return strings.ReplaceAll(boundRefunds(pkg), "'^ch_[A-Za-z0-9]{1,64}$'", "'^ch_[A-Za-z0-9]{1,300}$'")
}

// TestHR205_ARequestAboutALongSubjectIsSupersededToo: a key too long for
// the column is recorded as its SHA-256, never left out, so the fact's new
// value supersedes the request about a long subject id as it does any
// other.
func TestHR205_ARequestAboutALongSubjectIsSupersededToo(t *testing.T) {
	w := newWorldWith(t, longCharges)
	charge := "ch_" + strings.Repeat("a", 280)
	w.refundable(charge)
	g := w.heldGrant()
	run := w.run(g.ID, ids.UUID{})
	w.state(charge, "duplicate")
	id := held(t, w.authorize(w.request(run, ids.NewV7(), charge, "85.00")))
	sum := sha256.Sum256([]byte("payments.charge.state@payments.charge:" + charge))
	key := "sha256:" + hex.EncodeToString(sum[:])
	if s := w.str("SELECT state || ' ' || coalesce(invalidation_key, '') FROM pc.approval_requests WHERE id = $1", id); s != "PENDING "+key {
		t.Fatalf("held: %s", s)
	}
	w.state(charge, "fraudulent")
	if s := w.str("SELECT state || '/' || coalesce(end_reason, '') FROM pc.approval_requests WHERE id = $1", id); s != "SUPERSEDED/BINDING_CHANGED" {
		t.Fatalf("after the change: %s", s)
	}
}
