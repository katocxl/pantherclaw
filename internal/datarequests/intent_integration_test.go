// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package datarequests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/restore"
)

func TestT176_OrgErasureWaitsForExactExternalIntentACK(t *testing.T) {
	d, s, org := setup(t)
	id := deletionRequest(t, s, org, time.Now().Add(-time.Hour))
	for range 2 {
		if err := s.DeleteOrg(t.Context(), org, id); !errors.Is(err, ErrAwaitingSecurityCopy) {
			t.Fatalf("unacknowledged retry: %v", err)
		}
	}
	var rows, journal, completions int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.data_requests WHERE org_id=$1", []any{org}, &rows)
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.org_deletion_journal WHERE deleted_org_id=$1", []any{org}, &journal)
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.deletion_records WHERE deleted_org_id=$1", []any{org}, &completions)
	if rows != 1 || journal != 1 || completions != 0 {
		t.Fatalf("before ACK: rows=%d journal=%d completions=%d", rows, journal, completions)
	}
	// Chaining, local emission and exporting alone must not allow erasure.
	chainPlatform(t, s)
	if _, err := securityevent.Attempt(t.Context(), s.Pool, ids.PlatformOrg); err != nil {
		t.Fatal(err)
	}
	var exported bytes.Buffer
	if n, _, err := securityevent.Export(t.Context(), s.Pool, ids.PlatformOrg, 0, 500, &exported); err != nil || n != 1 {
		t.Fatalf("export: n=%d err=%v", n, err)
	}
	if err := s.DeleteOrg(t.Context(), org, id); !errors.Is(err, ErrAwaitingSecurityCopy) {
		t.Fatalf("local copy bypassed ACK: %v", err)
	}
	acknowledgeIntents(t, s)
	if err := s.DeleteOrg(t.Context(), org, id); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteOrg(t.Context(), org, id); err != nil {
		t.Fatal("completed retry:", err)
	}
}

// TestT176_RemovalHoldsNoTransactionOpen: while the org's rows are being
// removed on the Deleter's connection, the application holds no transaction
// on the journal row. One held there sits idle until the idle-in-transaction
// timeout ends it, which a large org reaches.
func TestT176_RemovalHoldsNoTransactionOpen(t *testing.T) {
	d, s, org := setup(t)
	id := deletionRequest(t, s, org, time.Now().Add(-time.Hour))
	if err := s.DeleteOrg(t.Context(), org, id); !errors.Is(err, ErrAwaitingSecurityCopy) {
		t.Fatalf("unacknowledged: %v", err)
	}
	acknowledgeIntents(t, s)

	// A held write barrier stops the removal at its first statement.
	locked, release, held := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		held <- s.Pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			if err := writeBarrier(ctx, tx); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	deleted := make(chan error, 1)
	go func() { deleted <- s.DeleteOrg(context.Background(), org, id) }()
	deadline := time.Now().Add(30 * time.Second)
	for waiting := 0; waiting == 0; {
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("the removal never reached the write barrier")
		}
		time.Sleep(10 * time.Millisecond)
		d.AdminQueryRow(t, "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())", nil, &waiting)
	}
	lock := s.Pool.InTenantTx(t.Context(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "SELECT 1 FROM pc.org_deletion_journal WHERE org_id=$1 AND id=$2 FOR UPDATE NOWAIT", ids.PlatformOrg, id)
		return err
	})
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if lock != nil {
		t.Fatalf("the journal row was locked during removal: %v", lock)
	}
	var completions int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.deletion_records WHERE deleted_org_id=$1", []any{org}, &completions)
	if completions != 1 {
		t.Fatalf("completions=%d", completions)
	}
}

// TestT176_RacingErasureWorkersLeaveOneRecord: four workers erase one org at
// once. Each finishes or fails with the lock timeout the job retries, and a
// retry leaves the erasure complete with exactly one deletion record.
func TestT176_RacingErasureWorkersLeaveOneRecord(t *testing.T) {
	d, s, org := setup(t)
	id := deletionRequest(t, s, org, time.Now().Add(-time.Hour))
	if err := s.DeleteOrg(t.Context(), org, id); !errors.Is(err, ErrAwaitingSecurityCopy) {
		t.Fatalf("unacknowledged: %v", err)
	}
	acknowledgeIntents(t, s)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			<-start
			if err := s.DeleteOrg(context.Background(), org, id); err != nil && !db.IsLockTimeout(err) {
				t.Errorf("a racing worker: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if err := s.DeleteOrg(t.Context(), org, id); err != nil {
		t.Fatal("retry:", err)
	}
	var complete bool
	var completions int
	d.AdminQueryRow(t, "SELECT complete FROM pc.org_deletion_journal WHERE deleted_org_id=$1", []any{org}, &complete)
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.deletion_records WHERE deleted_org_id=$1", []any{org}, &completions)
	if !complete || completions != 1 {
		t.Fatalf("complete=%v completions=%d", complete, completions)
	}
}

func TestT176_AccountIntentAndCompletionHaveSeparateDedupe(t *testing.T) {
	d, s, _ := setup(t)
	ctx := t.Context()
	account, digest := ids.NewV7(), strings.Repeat("a", 64)
	actor := evdomain.Actor{Type: "system", ID: "account.delete"}
	for range 2 {
		if err := s.RecordAccountDeletionIntent(ctx, account, digest, actor); !errors.Is(err, ErrAwaitingSecurityCopy) {
			t.Fatalf("intent: %v", err)
		}
	}
	var n int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.account_deletion_events WHERE account_id=$1", []any{account}, &n)
	if n != 1 {
		t.Fatalf("intent duplicated: %d", n)
	}
	acknowledgeIntents(t, s)
	if err := s.RecordAccountDeletionIntent(ctx, account, digest, actor); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.RecordDeletedAccount(ctx, account, digest, actor); err != nil {
			t.Fatal(err)
		}
	}
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.account_deletion_events WHERE account_id=$1", []any{account}, &n)
	if n != 2 {
		t.Fatalf("intent/completion dedupe collision: %d", n)
	}
	if err := s.RecordAccountDeletionIntent(ctx, account, strings.ToUpper(digest), actor); err == nil {
		t.Fatal("noncanonical digest accepted")
	}
}

func TestT176_OrgIntentReplaysWhenCompletionNeverExisted(t *testing.T) {
	d, s, org := setup(t)
	ctx := t.Context()
	// A post-backup intent is sufficient to freeze and schedule the target,
	// while retaining its original request and journal digest as provenance.
	request := ids.NewV7()
	sum := sha256.Sum256([]byte("verified external intent"))
	digest := hex.EncodeToString(sum[:])
	e := restore.Event{Org: ids.PlatformOrg, Kind: "org.deletion_started", Object: securityevent.Object{Type: "org", ID: org.String()}, RequestID: request, JournalDigest: digest, LedgerSeq: 1, Direction: "tighten", Timestamp: time.Now(), Actor: evdomain.Actor{Type: "system", ID: "test"}}
	r := restore.NewRegistry()
	if err := s.RegisterRestore(r); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := r.Reapply(ctx, s.Pool, []restore.Event{e}, true, evdomain.Actor{Type: "operator", ID: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	var id ids.UUID
	var state string
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.org_deletion_journal WHERE deleted_org_id=$1", []any{org}, &n)
	d.AdminQueryRow(t, "SELECT id FROM pc.org_deletion_journal WHERE deleted_org_id=$1", []any{org}, &id)
	d.AdminQueryRow(t, "SELECT state FROM pc.orgs WHERE id=$1", []any{org}, &state)
	if n != 1 || state != "DELETED" {
		t.Fatalf("replay journal=%d state=%s", n, state)
	}
	finishDeletion(t, s, org, id)
}

func TestT176_FrozenBackupReplayKeepsCompletionChronology(t *testing.T) {
	d, s, org := setup(t)
	d.AdminExec(t, `UPDATE pc.orgs SET state='DELETED',deleted_at=now()-interval '1 day' WHERE id=$1`, org)
	sum := sha256.Sum256([]byte("external intent after frozen backup"))
	e := restore.Event{Org: ids.PlatformOrg, Kind: "org.deletion_started", Object: securityevent.Object{Type: "org", ID: org.String()}, RequestID: ids.NewV7(), JournalDigest: hex.EncodeToString(sum[:]), LedgerSeq: 1, Direction: "tighten", Timestamp: time.Now(), Actor: evdomain.Actor{Type: "system", ID: "test"}}
	r := restore.NewRegistry()
	if err := s.RegisterRestore(r); err != nil {
		t.Fatal(err)
	}
	if err := r.Reapply(t.Context(), s.Pool, []restore.Event{e}, true, evdomain.Actor{Type: "operator", ID: "test"}); err != nil {
		t.Fatal(err)
	}
	var id ids.UUID
	d.AdminQueryRow(t, "SELECT id FROM pc.org_deletion_journal WHERE deleted_org_id=$1", []any{org}, &id)
	finishDeletion(t, s, org, id)
	var raw []byte
	d.AdminQueryRow(t, "SELECT record FROM pc.deletion_records WHERE deleted_org_id=$1", []any{org}, &raw)
	var record DeletionRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.StartTime.Before(record.WindowEndTime) || record.CompleteTime.Before(record.StartTime) {
		t.Fatalf("replayed record has invalid chronology: %+v", record)
	}
}

func TestHR391_LegalHoldCommittedBeforeFreezeWins(t *testing.T) {
	d, s, org := setup(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	user := ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.users(org_id,id,issuer,subject,email,display_name) VALUES($1,$2,'test','holder','holder@example.com','Holder')", org, user)
	id := deletionRequest(t, s, org, time.Now().Add(-time.Hour))
	inserted, release := make(chan struct{}), make(chan struct{})
	holdResult := make(chan error, 1)
	go func() {
		holdResult <- s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			if _, err := tx.Exec(ctx, "INSERT INTO pc.legal_holds(org_id,id,scope,reason,created_by) VALUES($1,$2,'org','test hold',$3)", org, ids.NewV7(), user); err != nil {
				return err
			}
			close(inserted)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-inserted:
	case err := <-holdResult:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	deleted := make(chan error, 1)
	go func() { deleted <- s.DeleteOrg(ctx, org, id) }()
	select {
	case err := <-deleted:
		close(release)
		t.Fatalf("freeze passed in-flight hold: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-holdResult; err != nil {
		t.Fatal(err)
	}
	if err := <-deleted; !errors.Is(err, ErrHeld) {
		t.Fatalf("hold lost: %v", err)
	}
	var state string
	d.AdminQueryRow(t, "SELECT state FROM pc.orgs WHERE id=$1", []any{org}, &state)
	if state != "ACTIVE" {
		t.Fatalf("held org became %s", state)
	}
	d.AdminQueryRow(t, "SELECT state FROM pc.data_requests WHERE org_id=$1 AND id=$2", []any{org, id}, &state)
	if state != "HELD" {
		t.Fatalf("legal hold was not visible on request: %s", state)
	}
}
