// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The core-B review fixes (D91).

func (e *env) grantState(g gdomain.Grant) string {
	e.t.Helper()
	var s string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state FROM pc.grants WHERE org_id = $1 AND id = $2", e.org, g.ID.UUID()).Scan(&s)
	}); err != nil {
		e.t.Fatal(err)
	}
	return s
}

// TestD91_SameContentMayBeAskedForAgain (K1): after a request ended, the
// same content of the same kind for the same subject is asked for again.
func TestD91_SameContentMayBeAskedForAgain(t *testing.T) {
	e := newEnv(t)
	log := &closedLog{}
	e.svc.Changes.Register(changes.DomainProtected, "TEST_CHANGE", log.handler(td.PermProtectedChangeManage))
	eve := e.person("eve", td.RoleSecurityAdmin)
	subject := ids.NewV7()
	ask := func() changes.Request {
		t.Helper()
		r, err := e.svc.Changes.Request(eve.cli, changes.Requested{
			Domain: changes.DomainProtected, Kind: "TEST_CHANGE", Subject: subject, Content: sha256.Sum256([]byte("same")),
			Summary: map[string]string{"same": "content"},
		})
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		return r
	}
	first := ask()
	if again := ask(); again.ID != first.ID {
		t.Fatal("a pending request was not returned as it is")
	}
	if _, err := e.svc.Changes.Decline(eve.cli, first.ID, "not yet"); err != nil {
		t.Fatal(err)
	}
	second := ask()
	if second.ID == first.ID || second.Binding != first.Binding {
		t.Fatalf("after a decline: %s (same binding %v)", second.ID, second.Binding == first.Binding)
	}
	e.exec("UPDATE pc.change_requests SET state = 'VOIDED', decided_at = now(), decided_reason = 'TEST' WHERE org_id = $1 AND id = $2",
		e.org, second.ID)
	if third := ask(); third.ID == second.ID {
		t.Fatal("after a void the old request came back")
	}
}

// TestD91_RevokeAuthorityRevokesEveryRowsGrants (K2): grants issued under
// a superseded COHORT row are revoked too, and RevokeAuthority works after
// the ceiling was voided, which itself revokes the ceiling's grants.
func TestD91_RevokeAuthorityRevokesEveryRowsGrants(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutCohort, 5)
	cohortGrant, err := e.issue(a, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	en, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutFull, nil, ids.UUID{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []person{e.bob, e.cat}[:en.Required] {
		if _, err := e.svc.Changes.Confirm(p.page, en.Request.ID, e.sign(p, en.Request)); err != nil {
			t.Fatal(err)
		}
	}
	if a, err = e.svc.GetAutomation(e.alice.cli, a.ID); err != nil || a.Rollout != autodomain.RolloutFull {
		t.Fatalf("widen: %v %s", err, a.Rollout)
	}
	fullGrant, err := e.issue(a, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, eff, err := e.svc.RevokeAuthority(e.alice.cli, a.ID, "incident")
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.GrantsRevoked) != 2 || e.grantState(cohortGrant) != "REVOKED" || e.grantState(fullGrant) != "REVOKED" {
		t.Errorf("revoked %v; cohort grant %s, full grant %s", eff.GrantsRevoked, e.grantState(cohortGrant), e.grantState(fullGrant))
	}

	b, bv := e.enabled("payouts", autodomain.RolloutCohort, 5)
	g, err := e.issue(b, bv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.VoidCeiling(context.Background(), e.org, b.Ceiling.ID, "TEST"); err != nil {
		t.Fatal(err)
	}
	if s := e.grantState(g); s != "REVOKED" {
		t.Errorf("a void ceiling's grant is %s", s)
	}
	if _, _, err := e.svc.RevokeAuthority(e.alice.cli, b.ID, "incident"); err != nil {
		t.Errorf("RevokeAuthority after a void: %v", err)
	}
}

// TestD91_ApplyDuringKillSwitchStaysPaused (K5).
func TestD91_ApplyDuringKillSwitchStaysPaused(t *testing.T) {
	e := newEnv(t)
	_, v := e.validated("refunds")
	en, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutShadow, nil, ids.UUID{})
	if err != nil {
		t.Fatal(err)
	}
	e.exec(`UPDATE pc.org_containment SET kill_switch = true, engaged_by = 'user:test', engaged_at = now(), engage_reason = 'test'
		WHERE org_id = $1`, e.org)
	if _, err := e.svc.Changes.Confirm(e.bob.page, en.Request.ID, e.sign(e.bob, en.Request)); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.GetAutomation(e.alice.cli, v.Automation)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != autodomain.StatePaused || got.PauseReason != autodomain.PauseKillSwitch {
		t.Errorf("enabled during the kill switch: %s %s", got.State, got.PauseReason)
	}
}

// TestD91_ExpirySweepFiresClosed (K7).
func TestD91_ExpirySweepFiresClosed(t *testing.T) {
	e := newEnv(t)
	log := &closedLog{}
	e.svc.Changes.Register(changes.DomainProtected, "TEST_CHANGE", log.handler(td.PermProtectedChangeManage))
	e.exec(`INSERT INTO pc.change_requests (org_id, id, domain, kind, subject_id, content_digest, binding, summary, required,
		requested_by, created_at, expires_at) VALUES ($1, gen_random_uuid(), 'protected', 'TEST_CHANGE', gen_random_uuid(),
		decode(repeat('ab', 32), 'hex'), decode(repeat('cd', 32), 'hex'), '{}', 1, 'user:x', now() - interval '2 hours',
		now() - interval '1 hour')`, e.org)
	n, err := e.svc.Changes.ExpireOrg(context.Background(), e.org)
	if err != nil || n != 1 {
		t.Fatalf("expired %d: %v", n, err)
	}
	if len(log.states) != 1 || log.states[0] != "TEST_CHANGE:EXPIRED" {
		t.Errorf("closed callbacks %v", log.states)
	}
	if c := e.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.change.expired'`, e.org); c != 1 {
		t.Errorf("change.expired records %d", c)
	}
}

// TestD91_ListPagesOnScannedRows (K8): rows the caller may not read never
// end paging early.
func TestD91_ListPagesOnScannedRows(t *testing.T) {
	e := newEnv(t)
	log := &closedLog{}
	e.svc.Changes.Register(changes.DomainPublisher, "TEST_CLEAR", log.handler(td.PermPublisherCompromise))
	eve := e.person("eve", td.RoleSecurityAdmin)
	dave := e.person("dave", td.RoleViewer)
	_, v := e.validated("refunds")
	en, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutShadow, nil, ids.UUID{})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		e.request(eve, changes.DomainPublisher, "TEST_CLEAR") // newer, hidden from dave
	}
	var seen []ids.UUID
	f := changes.Filter{Limit: 2}
	for range 5 {
		page, next, err := e.svc.Changes.List(dave.cli, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page {
			seen = append(seen, r.ID)
		}
		if next.IsZero() {
			break
		}
		f.Before = next
	}
	if len(seen) != 1 || seen[0] != en.Request.ID {
		t.Errorf("dave saw %v, want the enabling %s", seen, en.Request.ID)
	}
}

// TestD91_NoCancellationWithoutTheEngine (K10).
func TestD91_NoCancellationWithoutTheEngine(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	if _, _, err := e.svc.PauseAutomation(e.alice.cli, a.ID, true, "stop"); reason(err) != "EXECUTIONS_UNAVAILABLE" {
		t.Errorf("cancel_active without the engine: %v", err)
	}
	if _, _, err := e.svc.PauseAutomation(e.alice.cli, a.ID, false, "stop"); err != nil {
		t.Errorf("a plain pause: %v", err)
	}
}
