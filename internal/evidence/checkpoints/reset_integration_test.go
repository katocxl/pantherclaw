// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package checkpoints_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var operator = domain.Actor{Type: "operator", ID: "test-operator"}

type integrityRow struct {
	State        string
	FailureCode  *string
	FailedSeq    *int64
	FailedAt     *time.Time
	VerifiedSize *int64
	VerifiedAt   *time.Time
	UpdatedAt    time.Time
}

// integrityOf returns the org's evidence_integrity row (false: none).
func (f *fixture) integrityOf(t *testing.T) (integrityRow, bool) {
	t.Helper()
	if f.count(t, "SELECT count(*) FROM pc.evidence_integrity") == 0 {
		return integrityRow{}, false
	}
	var r integrityRow
	f.d.AdminQueryRow(t, `SELECT state, failure_code, failed_seq, failed_at, verified_size, verified_at, updated_at
		FROM pc.evidence_integrity WHERE org_id = $1`, []any{f.org},
		&r.State, &r.FailureCode, &r.FailedSeq, &r.FailedAt, &r.VerifiedSize, &r.VerifiedAt, &r.UpdatedAt)
	return r, true
}

func (f *fixture) sent() []napp.Message {
	f.notify.mu.Lock()
	defer f.notify.mu.Unlock()
	return slices.Clone(f.notify.sent)
}

func (f *fixture) audited(t *testing.T, name string) int {
	t.Helper()
	return f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = $1", "audit."+name)
}

// chained returns how many entries the org's chain holds once every
// entry is chained (the audit entries of a failure and a reset included).
func (f *fixture) chained(t *testing.T) uint64 {
	t.Helper()
	f.grow(t, 0)
	return uint64(f.count(t, "SELECT count(*) FROM pc.ledger_chain")) //nolint:gosec // G115: a count
}

// failAt edits the chained entry at seq and lets the checkpoint job find
// it; it returns the entry's original body.
func (f *fixture) failAt(t *testing.T, seq int64) []byte {
	t.Helper()
	var body []byte
	f.d.AdminQueryRow(t, `SELECT e.body FROM pc.ledger_entries e
		JOIN pc.ledger_chain c ON c.org_id = e.org_id AND c.entry_id = e.id
		WHERE c.org_id = $1 AND c.seq = $2`, []any{f.org, seq}, &body)
	f.adminAt(t, `UPDATE pc.ledger_entries SET body = '{"i":999}' WHERE id = $1`, seq)
	_, err := f.svc.Checkpoint(context.Background(), f.org)
	f.wantFailure(t, err, checkpoints.CodeChainLink, seq)
	return body
}

// TestHR194_AResetOrgIsCheckpointedAgain: once the operator restored the
// edited entry and reset the org, it is due again and gets its checkpoint.
// The reset clears the failure and the last verification, is audited with
// the cleared failure and the reason, and is notified with the code alone.
func TestHR194_AResetOrgIsCheckpointedAgain(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.grow(t, 10)
	f.checkpoint(t)
	f.grow(t, 5)
	body := f.failAt(t, 12)
	failed, _ := f.integrityOf(t)

	f.adminAt(t, `UPDATE pc.ledger_entries SET body = $2 WHERE id = $1`, 12, body)
	reason := "seq 12 restored from the 2026-10-09 backup; ticket SEC-17"
	cleared, done, err := f.svc.Reset(ctx, f.org, operator, reason)
	if err != nil || !done || cleared.Code != checkpoints.CodeChainLink || cleared.Seq != 12 || !cleared.FailedAt.Equal(*failed.FailedAt) {
		t.Fatalf("reset = %+v, %t, %v", cleared, done, err)
	}
	r, _ := f.integrityOf(t)
	if r.State != "OK" || r.FailureCode != nil || r.FailedSeq != nil || r.FailedAt != nil || r.VerifiedSize != nil || r.VerifiedAt != nil {
		t.Fatalf("integrity after the reset = %+v", r)
	}
	if n := f.audited(t, "evidence.integrity_reset"); n != 1 {
		t.Fatalf("%d reset audit entries, want 1", n)
	}
	var entry struct {
		ActorType, ActorID string
		Body               []byte
	}
	f.d.AdminQueryRow(t, `SELECT actor_type, actor_id, body FROM pc.ledger_entries
		WHERE org_id = $1 AND kind = 'audit.evidence.integrity_reset'`, []any{f.org}, &entry.ActorType, &entry.ActorID, &entry.Body)
	var ev struct {
		Outcome string            `json:"outcome"`
		Object  map[string]string `json:"object"`
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal(entry.Body, &ev); err != nil {
		t.Fatal(err)
	}
	if entry.ActorType != operator.Type || entry.ActorID != operator.ID || ev.Outcome != "success" ||
		ev.Object["type"] != "evidence_log" || ev.Object["id"] != f.org.String() ||
		ev.Details["failure_code"] != checkpoints.CodeChainLink || ev.Details["failed_seq"] != "12" ||
		ev.Details["failed_at"] == "" || ev.Details["reason"] != reason {
		t.Fatalf("reset audit entry %s %s %+v", entry.ActorType, entry.ActorID, ev)
	}
	sent := f.sent()
	if len(sent) != 2 || sent[1].Type != "security.evidence_integrity_reset" || sent[1].Org != f.org ||
		len(sent[1].Params) != 1 || sent[1].Params["reason"] != checkpoints.CodeChainLink {
		t.Fatalf("notifications = %+v", sent)
	}

	size := f.chained(t)
	if !f.due(t, db.ListCheckpointsDue) || !f.due(t, db.ListIntegrityDue) {
		t.Fatal("a reset org is not due for checkpoints and verification")
	}
	if res := f.checkpoint(t); !res.Signed || res.Size != size {
		t.Fatalf("checkpoint after the reset = %+v, want size %d", res, size)
	}
	if res, err := f.svc.Verify(ctx, f.org); err != nil || res.Size != size {
		t.Fatalf("verification after the reset = %+v, %v", res, err)
	}
	if f.due(t, db.ListCheckpointsDue) || f.due(t, db.ListIntegrityDue) {
		t.Fatal("the org is still due after its checkpoint and verification")
	}
	if n := f.audited(t, "security.evidence_integrity_failed"); n != 1 || len(f.sent()) != 2 {
		t.Fatalf("intact data failed again: %d failures audited, notifications %+v", n, f.sent())
	}
}

// TestHR194_AResetOrgWithBrokenEvidenceFailsAgain: a reset repairs
// nothing. An entry still edited fails the next checkpoint; a tile still
// altered under a checkpoint, which the checkpoint job does not read, fails
// the daily verification, which the reset made due again at once.
func TestHR194_AResetOrgWithBrokenEvidenceFailsAgain(t *testing.T) {
	ctx := context.Background()
	failedAgain := func(t *testing.T, f *fixture, err error, code string) {
		t.Helper()
		var ie *checkpoints.IntegrityError
		if !errors.As(err, &ie) || ie.Code != code {
			t.Fatalf("err = %v, want integrity failure %s", err, code)
		}
		if r, _ := f.integrityOf(t); r.State != "FAILED" || r.FailureCode == nil || *r.FailureCode != code {
			t.Fatalf("integrity = %+v, want FAILED %s", r, code)
		}
		if n := f.audited(t, "security.evidence_integrity_failed"); n != 2 {
			t.Fatalf("%d failures audited, want 2", n)
		}
		sent := f.sent()
		types := make([]string, 0, len(sent))
		for _, m := range sent {
			types = append(types, m.Type)
		}
		if !slices.Equal(types, []string{
			"security.evidence_integrity_failed", "security.evidence_integrity_reset", "security.evidence_integrity_failed",
		}) {
			t.Fatalf("notifications = %v", types)
		}
		if f.due(t, db.ListCheckpointsDue) || f.due(t, db.ListIntegrityDue) {
			t.Fatal("an org that failed again is still due")
		}
	}

	t.Run("edited entry", func(t *testing.T) {
		f := newFixture(t)
		f.grow(t, 10)
		f.checkpoint(t)
		f.grow(t, 5)
		f.failAt(t, 12)
		if _, done, err := f.svc.Reset(ctx, f.org, operator, "investigating"); err != nil || !done {
			t.Fatalf("reset = %t, %v", done, err)
		}
		f.chained(t)
		if !f.due(t, db.ListCheckpointsDue) {
			t.Fatal("a reset org is not due for checkpoints")
		}
		_, err := f.svc.Checkpoint(ctx, f.org)
		failedAgain(t, f, err, checkpoints.CodeChainLink)
		if row := f.latest(t); row.TreeSize != 10 {
			t.Fatalf("a checkpoint of size %d was signed over the edited entry", row.TreeSize)
		}
	})
	t.Run("altered tile", func(t *testing.T) {
		f := newFixture(t)
		f.grow(t, 300)
		f.checkpoint(t)
		if _, err := f.svc.Verify(ctx, f.org); err != nil {
			t.Fatal(err)
		}
		f.d.AdminExec(t, `UPDATE pc.ledger_tiles SET hashes = overlay(hashes placing '\xff'::bytea from 1 for 1)
			WHERE org_id = $1 AND level = 0 AND tile_index = 0`, f.org)
		_, err := f.svc.Verify(ctx, f.org)
		f.wantFailure(t, err, checkpoints.CodeTreeMismatch, 0)
		if _, done, err := f.svc.Reset(ctx, f.org, operator, "investigating"); err != nil || !done {
			t.Fatalf("reset = %t, %v", done, err)
		}
		// The org was verified less than a day ago: only the reset makes
		// it due again now.
		if !f.due(t, db.ListIntegrityDue) {
			t.Fatal("a reset org is not due for verification")
		}
		size := f.chained(t)
		if res := f.checkpoint(t); !res.Signed || res.Size != size {
			t.Fatalf("checkpoint after the reset = %+v", res)
		}
		_, err = f.svc.Verify(ctx, f.org)
		failedAgain(t, f, err, checkpoints.CodeTreeMismatch)
	})
}

// TestHR194_AResetOfAnOrgThatDidNotFailChangesNothing: an org without a
// status row, or with an OK one, is left as it is; nothing is audited or
// notified. Unknown orgs and bad reasons are refused.
func TestHR194_AResetOfAnOrgThatDidNotFailChangesNothing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.grow(t, 5)
	f.checkpoint(t)
	unchanged := func(t *testing.T, want integrityRow, wantRow bool) {
		t.Helper()
		cleared, done, err := f.svc.Reset(ctx, f.org, operator, "nothing to see")
		if err != nil || done || cleared != (checkpoints.Cleared{}) {
			t.Fatalf("reset = %+v, %t, %v", cleared, done, err)
		}
		if got, ok := f.integrityOf(t); ok != wantRow || got.State != want.State || !got.UpdatedAt.Equal(want.UpdatedAt) ||
			*got.VerifiedSize != *want.VerifiedSize {
			t.Fatalf("integrity = %+v (%t), want %+v (%t)", got, ok, want, wantRow)
		}
		if n := f.audited(t, "evidence.integrity_reset"); n != 0 || len(f.sent()) != 0 {
			t.Fatalf("%d reset audit entries, notifications %+v", n, f.sent())
		}
	}
	t.Run("no status", func(t *testing.T) {
		if _, done, err := f.svc.Reset(ctx, f.org, operator, "nothing to see"); err != nil || done {
			t.Fatalf("reset = %t, %v", done, err)
		}
		if _, ok := f.integrityOf(t); ok {
			t.Fatal("a reset created a status row")
		}
		if n := f.audited(t, "evidence.integrity_reset"); n != 0 || len(f.sent()) != 0 {
			t.Fatalf("%d reset audit entries, notifications %+v", n, f.sent())
		}
	})
	t.Run("OK", func(t *testing.T) {
		if _, err := f.svc.Verify(ctx, f.org); err != nil {
			t.Fatal(err)
		}
		before, ok := f.integrityOf(t)
		if !ok || before.State != "OK" || before.VerifiedSize == nil {
			t.Fatalf("integrity after a verification = %+v", before)
		}
		unchanged(t, before, true)
	})
	t.Run("refused", func(t *testing.T) {
		before, _ := f.integrityOf(t)
		for _, r := range []string{
			"", "   ", "line\nbreak", "bidi " + string(rune(0x202e)), strings.Repeat("a", checkpoints.MaxResetReason+1), "\xff",
		} {
			if _, _, err := f.svc.Reset(ctx, f.org, operator, r); !errors.Is(err, checkpoints.ErrResetReason) {
				t.Errorf("reason %q: %v", r, err)
			}
		}
		if _, _, err := f.svc.Reset(ctx, ids.New[ids.Org](), operator, "typo"); !errors.Is(err, checkpoints.ErrNoOrg) {
			t.Errorf("unknown org: %v", err)
		}
		unchanged(t, before, true)
	})
}
