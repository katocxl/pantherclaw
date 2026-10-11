// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/waitlistrpc"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// idrOrg adds a second org to f's database the way newWFx seeds the first,
// and returns it with its agent.
func idrOrg(f *wfx) (*wfx, ids.UUID) {
	f.t.Helper()
	o := &wfx{
		t: f.t, d: f.d, p: f.p, w: f.w, org: ids.New[ids.Org](), txn: ids.NewV7(), ann: ids.NewV7(), ben: ids.NewV7(),
		run: ids.NewV7(), grant: ids.NewV7(), instance: ids.NewV7(),
	}
	agent, env := ids.NewV7(), ids.NewV7()
	o.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'globex')", o.org)
	for _, u := range []ids.UUID{o.ann, o.ben} {
		o.exec(`INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)`, o.org, u, u.String())
	}
	o.exec("INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", o.org, env)
	o.exec("INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", o.org, agent)
	o.exec(`INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, o.org, o.instance, agent, o.instance.String()[:36]+"0000000")
	o.exec(`INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, o.org, o.grant, agent, o.ann, env)
	o.exec(`INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id, principal_source,
		grant_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $6, 'launcher', $7, now() + interval '8 hours')`,
		o.org, o.run, agent, o.instance, env, o.ann, o.grant)
	o.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'OK', 'gw', 'OPEN')`, o.org, o.txn, o.run, ids.NewV7(), make([]byte, 32))
	return o, agent
}

// TestT037_WaitlistEntriesOfAnotherOrgAreNotFound: T-037 — a person holding
// every waitlist-reading role at org scope asks WaitlistService for another
// org's real entries, one about its agent's unknown outcome and one tool
// review, by their ids: each is NotFound exactly as for an unknown id, no
// list shows them, even filtered by that org's agent, and they stay open.
// The same person reads its own org's entry. TestF626_* and TestHR177_*
// cover who may read an entry inside an org.
func TestT037_WaitlistEntriesOfAnotherOrgAreNotFound(t *testing.T) {
	f := newWFx(t)
	other, agent := idrOrg(f)
	recon := other.reconciliation()
	var review ids.UUID
	other.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		review, err = pgwaitlist.OpenToolReview(ctx, tx, other.org, ids.NewV7(), "pc.mock-payments", "1.0.0", pgwaitlist.System)
		return err
	})
	mine := f.reconciliation()
	h := waitlistrpc.NewWaitlist(waitlist.NewReader(f.p)).WithWriter(f.w)
	reader := f.as(f.ben, td.RoleOrgAdmin, td.RoleSecurityAdmin, td.RoleAuditor, td.RolePolicyPublisher)

	if e, err := h.GetWaitlistEntry(reader, &pantherclawv1.GetWaitlistEntryRequest{Id: mine.String()}); err != nil || e.GetEntry().GetId() != mine.String() {
		t.Fatalf("its own entry: %v, %v", e, err)
	}
	for what, id := range map[string]ids.UUID{"their reconciliation": recon, "their tool review": review, "unknown": ids.NewV7()} {
		if e, err := h.GetWaitlistEntry(reader, &pantherclawv1.GetWaitlistEntryRequest{Id: id.String()}); !errors.Is(err, waitlist.ErrEntryNotFound) {
			t.Errorf("%s: %v, %v", what, e, err)
		}
	}
	theirAgent := agent.String()
	for name, c := range map[string]struct {
		req  *pantherclawv1.ListWaitlistEntriesRequest
		want int
	}{
		"all":         {&pantherclawv1.ListWaitlistEntriesRequest{}, 1},
		"their agent": {&pantherclawv1.ListWaitlistEntriesRequest{AgentId: &theirAgent}, 0},
	} {
		l, err := h.ListWaitlistEntries(reader, c.req)
		if err != nil || len(l.GetEntries()) != c.want {
			t.Errorf("%s: %v, %v", name, l, err)
		}
		for _, e := range l.GetEntries() {
			if e.GetId() != mine.String() {
				t.Errorf("%s lists %s", name, e.GetId())
			}
		}
	}
	for _, id := range []ids.UUID{recon, review} {
		if s := other.state(id); s != "OPEN" {
			t.Errorf("their entry %s is %s", id, s)
		}
	}
}
