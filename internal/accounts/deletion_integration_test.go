// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package accounts_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	evd "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func noopRecorder(context.Context, ids.UUID, string, evd.Actor) error { return nil }

func admin(t *testing.T, f *fixture, org ids.OrgID, user ids.UUID) {
	t.Helper()
	f.exec(t, org, `INSERT INTO pc.role_bindings(org_id,id,user_id,role,scope_type,created_by) VALUES($1,$2,$3,'org_admin','ORG','test')`, org, ids.NewV7(), user)
}

// An unavailable durable intent sink must leave every user's PII intact,
// including legacy users whose account_id has never been populated.
func TestHR394_AccountDeletionIntentBeforeErasureAndRetry(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	a := f.account(t, "delete-me", "delete@example.test", true)
	org1, org2 := f.org(t, "first"), f.org(t, "second")
	u1, u2 := f.user(t, org1, "delete-me"), f.user(t, org2, "delete-me")
	stopped := errors.New("simulated durable sink outage")
	var digest string
	intent := func(_ context.Context, id ids.UUID, h string, _ evd.Actor) error {
		if id != a.ID || len(h) != 64 {
			t.Errorf("unexpected intent: %s/%s", id, h)
		}
		if digest != "" && digest != h {
			t.Error("retry changed journal digest")
		}
		digest = h
		return stopped
	}
	d := accounts.NewDeletion(f.store, noopRecorder, intent)
	if err := d.Begin(context.Background(), a.ID); !errors.Is(err, stopped) {
		t.Fatalf("intent outage: %v", err)
	}
	if err := d.Begin(context.Background(), a.ID); !errors.Is(err, stopped) {
		t.Fatalf("duplicate begin: %v", err)
	}
	for _, v := range []struct {
		o ids.OrgID
		u ids.UUID
	}{{org1, u1}, {org2, u2}} {
		if n := f.count(t, v.o, `SELECT count(*) FROM pc.users WHERE org_id=$1 AND id=$2 AND issuer=$3 AND subject='delete-me'`, v.o, v.u, issuer); n != 1 {
			t.Fatal("PII erased before durable intent")
		}
		err := f.pool.InTenantTx(context.Background(), v.o, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, `UPDATE pc.users SET state='ACTIVE' WHERE org_id=$1 AND id=$2`, v.o, v.u)
			return err
		})
		if err == nil {
			t.Fatal("legacy identity reactivated during pending deletion")
		}
	}
	if _, err := f.store.Resolve(context.Background(), accounts.Identity{Issuer: issuer, Subject: "delete-me"}, ""); err == nil {
		t.Fatal("pending identity signed in")
	}
	third := f.org(t, "late-legacy-user")
	err := f.pool.InTenantTx(context.Background(), third, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.users(org_id,id,issuer,subject,state)
                               VALUES($1,$2,$3,'delete-me','DISABLED')`, third, ids.NewV7(), issuer)
		return err
	})
	if !db.IsCheckViolation(err) {
		t.Fatalf("disabled legacy identity bypassed pending guard: %v", err)
	}
	// The same journal resumes after a restart, without replaying erased steps.
	d = accounts.NewDeletion(f.store, noopRecorder, func(ctx context.Context, id ids.UUID, h string, actor evd.Actor) error {
		stopped = nil
		return intent(ctx, id, h, actor)
	})
	if err := d.Resume(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.Resume(context.Background(), a.ID); err != nil {
		t.Fatal("duplicate resume:", err)
	}
	var retained, personal int
	f.d.AdminQueryRow(t, `SELECT count(*)::int FROM pc.account_events WHERE account_id=$1 AND kind='SIGNED_IN'`, []any{a.ID}, &retained)
	f.d.AdminQueryRow(t, `SELECT count(*)::int FROM pc.account_events WHERE account_id=$1 AND client_ip<>''`, []any{a.ID}, &personal)
	if retained != 1 || personal != 0 {
		t.Fatalf("account history: retained=%d personal IP rows=%d", retained, personal)
	}
	for _, v := range []struct {
		o ids.OrgID
		u ids.UUID
	}{{org1, u1}, {org2, u2}} {
		if n := f.count(t, v.o, `SELECT count(*) FROM pc.users WHERE org_id=$1 AND id=$2 AND state='DISABLED' AND issuer='deleted' AND email='' AND display_name LIKE 'deleted user %'`, v.o, v.u); n != 1 {
			t.Fatal("user not erased")
		}
	}
	next := f.account(t, "delete-me", "new@example.test", true)
	if next.ID == a.ID {
		t.Fatal("new sign-in revived tombstoned account")
	}
}

func TestHR394_AccountDeletionLastAdminRollbackAndRace(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	a, b := f.account(t, "admin-a", "a@example.test", true), f.account(t, "admin-b", "b@example.test", true)
	org := f.org(t, "shared")
	ua, ub := f.user(t, org, "admin-a"), f.user(t, org, "admin-b")
	admin(t, f, org, ua)
	admin(t, f, org, ub)
	d := accounts.NewDeletion(f.store, noopRecorder, noopRecorder)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []ids.UUID{a.ID, b.ID} {
		wg.Go(func() { results <- d.Begin(context.Background(), id) })
	}
	wg.Wait()
	close(results)
	success, refused := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, accounts.ErrLastAdmin) {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || refused != 1 {
		t.Fatalf("deletion race: success=%d refused=%d", success, refused)
	}
	if n := f.count(t, org, `SELECT count(*) FROM pc.users WHERE org_id=$1 AND state='ACTIVE'`, org); n != 1 {
		t.Fatalf("active admins: %d", n)
	}
	if n := f.count(t, org, `SELECT count(*) FROM pc.account_deletion_steps WHERE org_id=$1 AND state='PREPARED'`, org); n != 0 {
		t.Fatal("refused reservation not rolled back")
	}
}

func TestHR394_AccountDeletionCompletionDeliveryIsRetryable(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	a := f.account(t, "completion", "done@example.test", true)
	org := f.org(t, "org")
	f.user(t, org, "completion")
	down := errors.New("sink down")
	calls := 0
	record := func(context.Context, ids.UUID, string, evd.Actor) error { calls++; return down }
	d := accounts.NewDeletion(f.store, record, noopRecorder)
	if err := d.Begin(context.Background(), a.ID); !errors.Is(err, down) {
		t.Fatal(err)
	}
	down = nil
	if err := d.ResumePending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := d.ResumePending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("completion deliveries: %d", calls)
	}
}

func TestHR394_LastAdminAfterFiveHundredBindingsStillBlocksDeletion(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	a := f.account(t, "many-bindings", "admin@example.test", true)
	org := f.org(t, "many-bindings")
	u := f.user(t, org, "many-bindings")
	f.exec(t, org, `WITH teams AS (
        INSERT INTO pc.teams(org_id,id,slug,name)
        SELECT $1,format('00000000-0000-7000-8000-%s',lpad(n::text,12,'0'))::uuid,
               'team-' || n::text,'Team ' || n::text FROM generate_series(1,500) n RETURNING id
    ) INSERT INTO pc.role_bindings(org_id,id,user_id,role,scope_type,team_id,created_by)
      SELECT $1,id,$2,'auditor','TEAM',id,'test' FROM teams`, org, u)
	f.exec(t, org, `INSERT INTO pc.role_bindings(org_id,id,user_id,role,scope_type,created_by)
                   VALUES($1,'ffffffff-ffff-4fff-8fff-ffffffffffff',$2,'org_admin','ORG','test')`, org, u)
	d := accounts.NewDeletion(f.store, noopRecorder, noopRecorder)
	if err := d.Begin(context.Background(), a.ID); !errors.Is(err, accounts.ErrLastAdmin) {
		t.Fatalf("last admin outside display page was not protected: %v", err)
	}
	if n := f.count(t, org, `SELECT count(*) FROM pc.users WHERE org_id=$1 AND id=$2 AND state='ACTIVE' AND subject='many-bindings'`, org, u); n != 1 {
		t.Fatal("last administrator was altered")
	}
}

func TestHR394_PendingIntentDoesNotStarveLaterAcknowledgedDeletion(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	var queue []ids.UUID
	for n := range 101 {
		a := f.account(t, fmt.Sprintf("queue-%03d", n), "queue@example.test", true)
		queue = append(queue, a.ID)
	}
	err := f.pool.InGlobalTx(t.Context(), db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		for _, account := range queue {
			if _, err := tx.Exec(ctx, `INSERT INTO pc.account_deletions(account_id,state,updated_at)
                                       VALUES($1,'INTENT_PENDING',clock_timestamp())`, account); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	acked := queue[len(queue)-1]
	intent := func(_ context.Context, account ids.UUID, _ string, _ evd.Actor) error {
		if account == acked {
			return nil
		}
		return pcerr.New(pcerr.FailedPrecondition, "DELETION_AWAITING_SECURITY_COPY", "waiting")
	}
	d := accounts.NewDeletion(f.store, noopRecorder, intent)
	for range 2 {
		if err := d.ResumePending(t.Context()); err != nil {
			t.Fatal("expected pending intents to remain retryable:", err)
		}
	}
	var complete bool
	f.d.AdminQueryRow(t, `SELECT state='DONE' AND event_recorded FROM pc.account_deletions WHERE account_id=$1`, []any{acked}, &complete)
	if !complete {
		t.Fatal("first hundred pending intents starved the later acknowledged deletion")
	}
}

func TestHR394_IdentityGuardIsHashOnlyAndTenantBounded(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	a := f.account(t, "private-subject", "secret@example.test", true)
	org := f.org(t, "tenant")
	u := f.user(t, org, "private-subject")
	waiting := errors.New("await external security copy")
	d := accounts.NewDeletion(f.store, noopRecorder, func(context.Context, ids.UUID, string, evd.Actor) error { return waiting })
	if err := d.Begin(context.Background(), a.ID); !errors.Is(err, waiting) {
		t.Fatal(err)
	}
	if n := f.count(t, org, `SELECT count(*) FROM pc.identity_deletion_guards`); n != 0 {
		t.Fatal("tenant enumerated identity guards")
	}
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		var available bool
		if err := tx.QueryRow(ctx, `SELECT pc.identity_available($1,$2,false)`, issuer, "private-subject").Scan(&available); err != nil {
			return err
		}
		if available {
			t.Error("pending legacy identity reported available")
		}
		var setting string
		if err := tx.QueryRow(ctx, `SELECT coalesce(current_setting('app.identity_hash',true),'')`).Scan(&setting); err != nil {
			return err
		}
		if setting != "" {
			t.Error("identity predicate leaked its context")
		}
		_, err := tx.Exec(ctx, `UPDATE pc.users SET state='ACTIVE' WHERE org_id=$1 AND id=$2`, org, u)
		return err
	})
	if err == nil {
		t.Fatal("pending identity user mutation succeeded")
	}
	var columns int
	f.d.AdminQueryRow(t, `SELECT count(*)::int FROM information_schema.columns WHERE table_schema='pc' AND table_name='identity_deletion_guards' AND column_name NOT IN ('identity_hash','state')`, nil, &columns)
	if columns != 0 {
		t.Fatal("identity guard stores identifying metadata")
	}
}

func TestHR394_AccountDeletionResumesAfterTenantCommit(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	a := f.account(t, "partial", "partial@example.test", true)
	first, second := f.org(t, "one"), f.org(t, "two")
	if strings.Compare(first.String(), second.String()) > 0 {
		first, second = second, first
	}
	u1, u2 := f.user(t, first, "partial"), f.user(t, second, "partial")
	f.d.AdminExec(t, `CREATE FUNCTION pc.test_account_scrub_crash() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='`+second.String()+`'::uuid AND NEW.issuer='deleted' THEN RAISE EXCEPTION 'injected crash'; END IF; RETURN NEW; END $$`)
	f.d.AdminExec(t, `CREATE TRIGGER test_account_scrub_crash BEFORE UPDATE ON pc.users FOR EACH ROW EXECUTE FUNCTION pc.test_account_scrub_crash()`)
	d := accounts.NewDeletion(f.store, noopRecorder, noopRecorder)
	if err := d.Begin(context.Background(), a.ID); err == nil {
		t.Fatal("injected tenant failure did not stop deletion")
	}
	if n := f.count(t, first, `SELECT count(*) FROM pc.users WHERE org_id=$1 AND id=$2 AND state='DISABLED'`, first, u1); n != 1 {
		t.Fatal("first tenant commit lost")
	}
	if n := f.count(t, second, `SELECT count(*) FROM pc.users WHERE org_id=$1 AND id=$2 AND state='ACTIVE'`, second, u2); n != 1 {
		t.Fatal("failed tenant partially erased")
	}
	f.d.AdminExec(t, `DROP TRIGGER test_account_scrub_crash ON pc.users`)
	f.d.AdminExec(t, `DROP FUNCTION pc.test_account_scrub_crash()`)
	if err := d.Resume(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	for _, org := range []ids.OrgID{first, second} {
		if n := f.count(t, org, `SELECT count(*) FROM pc.account_deletion_steps WHERE org_id=$1 AND id=$2 AND state='DELETED'`, org, a.ID); n != 1 {
			t.Fatal("tenant step did not finish")
		}
	}
}
