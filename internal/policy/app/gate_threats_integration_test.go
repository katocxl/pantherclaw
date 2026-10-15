// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestT100_OnePersonCannotWeakenThePolicyAlone (T-100, HR-230, HR-231,
// HR-236): in an org with two people holding policy.publish, one of them
// can neither publish a looser version, nor roll back to one, nor confirm
// either alone (not with a second key of their own either); the published
// version stays until the second person confirms with their key.
func TestT100_OnePersonCannotWeakenThePolicyAlone(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.person("alice", td.RolePolicyPublisher), e.person("bob", td.RolePolicyPublisher)
	spare := ids.NewV7()
	secret := make([]byte, 32)
	copy(secret, spare[:])
	e.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'spare')`,
		e.org, spare, alice.id, secret[:16], secret)

	v1, v2, req := e.loosen(alice)
	if req.Required != 2 {
		t.Fatalf("required %d", req.Required)
	}
	if _, err := e.v.Changes.Confirm(alice.ctx, req.ID, e.sign(alice, req.ID, req.Binding)); err != nil {
		t.Fatal(err)
	}
	second := e.sign(alice, req.ID, req.Binding)
	second.Credential = spare
	if _, err := e.v.Changes.Confirm(alice.ctx, req.ID, second); !errors.Is(err, app.ErrSamePerson) {
		t.Fatalf("a second key of the same person: %v", err)
	}
	if e.state(v1) != app.StatePublished || e.state(v2) != app.StateTested {
		t.Fatalf("one person loosened the policy: v1 %s, v2 %s", e.state(v1), e.state(v2))
	}

	// A tighter version is published at once; rolling back from it to the
	// looser v2 waits for two people as well.
	v3 := e.draft(denyAbove("deny-large", "1000"), denyAbove("deny-huge", "900"))
	if out, err := e.v.Publish(alice.ctx, v3); err != nil || out.Version.State != app.StatePublished {
		t.Fatalf("tighter = %+v, %v", out, err)
	}
	back, err := e.v.Rollback(alice.ctx, v2, nil)
	if err != nil || back.ChangeRequest == nil || back.ChangeRequest.Required != 2 || back.Version.State != app.StateTested {
		t.Fatalf("a looser rollback = %+v, %v", back, err)
	}
	cr := *back.ChangeRequest
	if _, err := e.v.Changes.Confirm(alice.ctx, cr.ID, e.sign(alice, cr.ID, cr.Binding)); err != nil {
		t.Fatal(err)
	}
	if e.state(v3) != app.StatePublished {
		t.Fatal("one person's rollback replaced the published version")
	}
	got, err := e.v.Changes.Confirm(bob.ctx, cr.ID, e.sign(bob, cr.ID, cr.Binding))
	if err != nil || got.State != app.ChangeApproved || e.state(back.Version.ID) != app.StatePublished {
		t.Fatalf("the second person's key = %+v, %v", got, err)
	}
}

// TestHR231_ConfirmersWhoLostTheRoleNoLongerCount (D29): at the last
// confirmation every earlier confirmer must still be active and hold
// policy.publish; one who lost the role, or was disabled, does not count
// and the request stays pending until enough people who qualify confirm.
func TestHR231_ConfirmersWhoLostTheRoleNoLongerCount(t *testing.T) {
	for _, lose := range []string{
		"DELETE FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2",
		"UPDATE pc.users SET state = 'DISABLED' WHERE org_id = $1 AND id = $2",
	} {
		e := newEnv(t)
		alice, bob := e.person("alice", td.RolePolicyPublisher), e.person("bob", td.RolePolicyPublisher)
		carol := e.person("carol", td.RolePolicyPublisher)
		_, v2, req := e.loosen(alice)
		if _, err := e.v.Changes.Confirm(alice.ctx, req.ID, e.sign(alice, req.ID, req.Binding)); err != nil {
			t.Fatal(err)
		}
		e.d.AdminExec(t, lose, e.org, alice.id)
		got, err := e.v.Changes.Confirm(bob.ctx, req.ID, e.sign(bob, req.ID, req.Binding))
		if err != nil || got.State != app.ChangePending || e.state(v2) != app.StateTested {
			t.Fatalf("%s: a confirmation by someone who lost the role counted: %+v, %v", lose, got, err)
		}
		got, err = e.v.Changes.Confirm(carol.ctx, req.ID, e.sign(carol, req.ID, req.Binding))
		if err != nil || got.State != app.ChangeApproved || e.state(v2) != app.StatePublished {
			t.Fatalf("%s: two who qualify = %+v, %v", lose, got, err)
		}
	}
}

// tenancyWorld is an org with a pending, once-confirmed change request for
// a looser version, and a publisher of another org.
type tenancyWorld struct {
	e, them *env
	alice   person
	eve     person
	v2      ids.UUID
	req     app.ChangeRequest
}

func newTenancyWorld(t *testing.T) *tenancyWorld {
	t.Helper()
	e := newEnv(t)
	w := &tenancyWorld{e: e, alice: e.person("alice", td.RolePolicyPublisher)}
	e.person("bob", td.RolePolicyPublisher) // two publishers: the request stays pending
	_, w.v2, w.req = e.loosen(w.alice)
	if _, err := e.v.Changes.Confirm(w.alice.ctx, w.req.ID, e.sign(w.alice, w.req.ID, w.req.Binding)); err != nil {
		t.Fatal(err)
	}
	w.them = &env{
		t: t, d: e.d, pool: e.pool, org: ids.New[ids.Org](), store: e.store, gate: e.gate, notes: e.notes, v: e.v,
		digests: e.digests,
	}
	w.them.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'them')", w.them.org)
	w.eve = w.them.person("eve", td.RolePolicyPublisher)
	return w
}

// isolated checks that the other org reads none of table's rows about v2
// (and this org reads some), and cannot write one into this org with
// insert(org, v2).
func (w *tenancyWorld) isolated(t *testing.T, table, where, insert string, args func() []any) {
	t.Helper()
	if n := w.them.count("SELECT count(*) FROM pc."+table+" WHERE "+where, w.v2); n != 0 {
		t.Errorf("%s: their tenant reads %d of our rows", table, n)
	}
	if n := w.e.count("SELECT count(*) FROM pc."+table+" WHERE "+where, w.v2); n == 0 {
		t.Errorf("%s: our tenant reads none of its rows", table)
	}
	err := w.them.pool.InTenantTx(context.Background(), w.them.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, insert, args()...)
		return err
	})
	if err == nil {
		t.Errorf("%s: a row written into another org", table)
	}
}

func digest32() []byte { return make([]byte, 32) }

// TestTenancy_policy_validations: an org's validations are its own.
func TestTenancy_policy_validations(t *testing.T) {
	w := newTenancyWorld(t)
	w.isolated(t, "policy_validations", "version_id = $1", `INSERT INTO pc.policy_validations (org_id, id, version_id,
		content_digest, definitions_digest, catalog_digest, passed, run_by) VALUES ($1, $2, $3, $4, $4, $4, true, 'x')`,
		func() []any { return []any{w.e.org, ids.NewV7(), w.v2, digest32()} })
	if _, _, err := w.e.v.Validate(w.eve.ctx, w.v2); err == nil {
		t.Error("validated another org's version")
	}
}

// TestTenancy_policy_test_runs: an org's test runs are its own, and
// another org's passing run never publishes a version.
func TestTenancy_policy_test_runs(t *testing.T) {
	w := newTenancyWorld(t)
	w.isolated(t, "policy_test_runs", "version_id = $1", `INSERT INTO pc.policy_test_runs (org_id, id, version_id,
		content_digest, definitions_digest, catalog_digest, passed, cases, mutants, survivors, run_by)
		VALUES ($1, $2, $3, $4, $4, $4, true, 0, 0, 0, 'x')`,
		func() []any { return []any{w.e.org, ids.NewV7(), w.v2, digest32()} })
	if _, _, err := w.e.v.Test(w.eve.ctx, w.v2); err == nil {
		t.Error("tested another org's version")
	}
	if _, err := w.e.v.Publish(w.eve.ctx, w.v2); !errors.Is(err, app.ErrVersionNotFound) {
		t.Errorf("published another org's version: %v", err)
	}
}

// TestTenancy_policy_change_requests: another org neither sees, lists,
// confirms nor declines an org's change requests.
func TestTenancy_policy_change_requests(t *testing.T) {
	w := newTenancyWorld(t)
	w.isolated(t, "policy_change_requests", "subject_id = $1", `INSERT INTO pc.policy_change_requests (org_id, id, kind,
		subject_id, binding, summary, required, requested_by) VALUES ($1, $2, 'PUBLISH', $3, $4, '{}', 1, 'x')`,
		func() []any { return []any{w.e.org, ids.NewV7(), w.v2, digest32()} })
	v := w.e.v
	if _, err := v.Changes.Get(w.eve.ctx, w.req.ID); !errors.Is(err, app.ErrChangeNotFound) {
		t.Errorf("get: %v", err)
	}
	if rs, err := v.Changes.List(w.eve.ctx, "", 50); err != nil || len(rs) != 0 {
		t.Errorf("list: %d, %v", len(rs), err)
	}
	// Its ceremony cannot even name our request (a foreign key in its own
	// org); a confirmation with any ceremony is refused.
	if _, err := v.Changes.Confirm(w.eve.ctx, w.req.ID, app.Assertion{Ceremony: ids.NewV7(), Credential: w.eve.key}); err == nil {
		t.Error("confirmed another org's request")
	}
	if _, err := v.Changes.Decline(w.eve.ctx, w.req.ID, "no"); !errors.Is(err, app.ErrChangeNotFound) {
		t.Errorf("decline: %v", err)
	}
	if got, _ := v.Changes.Get(w.alice.ctx, w.req.ID); got.State != app.ChangePending || len(got.Confirmations) != 1 {
		t.Fatalf("our request changed: %+v", got)
	}
}

// TestTenancy_policy_change_confirmations: an org's confirmations are its
// own; another org cannot add one to its request.
func TestTenancy_policy_change_confirmations(t *testing.T) {
	w := newTenancyWorld(t)
	w.isolated(t, "policy_change_confirmations",
		"request_id = (SELECT id FROM pc.policy_change_requests WHERE subject_id = $1)",
		`INSERT INTO pc.policy_change_confirmations (org_id, request_id, principal_id, credential_id) VALUES ($1, $2, $3, $4)`,
		func() []any { return []any{w.e.org, w.req.ID, w.eve.id, w.eve.key} })
}
