// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package checkpoints_test

import (
	"context"
	"crypto/mldsa"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const origin = "pc.test"

type notes struct {
	mu   sync.Mutex
	sent []napp.Message
}

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

type fixture struct {
	d      *dbtest.DB
	p      *db.Pool
	reg    *keys.Registry
	kp     keys.KeyProvider
	org    ids.OrgID
	notify *notes
	svc    *checkpoints.Service
}

func newFixture(t *testing.T, extra ...keys.Purpose) *fixture {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	path := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(path); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(context.Background(), p, kp, reg, extra...); err != nil {
		t.Fatal(err)
	}
	f := &fixture{d: d, p: p, reg: reg, kp: kp, org: ids.New[ids.Org](), notify: &notes{}}
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", f.org)
	f.svc = &checkpoints.Service{Pool: p, Keys: reg, LogOrigin: origin, Notify: f.notify, Log: pclog.Discard()}
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// grow appends n entries and chains them.
func (f *fixture) grow(t *testing.T, n int) {
	t.Helper()
	ctx := context.Background()
	err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		for i := range n {
			body, err := domain.CanonicalBody(map[string]int{"i": i})
			if err != nil {
				return err
			}
			if _, err := ledger.Append(ctx, tx, "test.appended", domain.Actor{Type: "system", ID: "test"}, body); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The chainer links only entries below the cluster's oldest running
	// transaction, which other tests on the shared cluster can hold back.
	want := f.count(t, "SELECT count(*) FROM pc.ledger_entries")
	for deadline := time.Now().Add(30 * time.Second); ; {
		if _, err := ledger.ChainAll(ctx, f.p, f.org, 500); err != nil {
			t.Fatal(err)
		}
		if f.count(t, "SELECT count(*) FROM pc.ledger_chain") == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the entries were not chained within 30 seconds")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (f *fixture) checkpoint(t *testing.T) checkpoints.Result {
	t.Helper()
	res, err := f.svc.Checkpoint(context.Background(), f.org)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// latest returns the latest stored checkpoint.
func (f *fixture) latest(t *testing.T) dbq.LatestCheckpointRow {
	t.Helper()
	var row dbq.LatestCheckpointRow
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).LatestCheckpoint(ctx, f.org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// chainRoot recomputes the root of the first n chained entries.
func (f *fixture) chainRoot(t *testing.T, n uint64) merkle.Hash {
	t.Helper()
	var b merkle.Builder
	if _, err := ledger.VerifyEach(context.Background(), f.p, f.org, func(l domain.Link) error {
		if b.Size() < n {
			b.Add(merkle.LeafHash(l.EntryHash))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return b.Root()
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) due(t *testing.T, purpose db.ListerPurpose) bool {
	t.Helper()
	refs, err := f.p.CrossOrgList(context.Background(), purpose, 10000)
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(refs, func(r db.OrgRef) bool { return r.Org == f.org })
}

// adminAt runs sql as the superuser on the entry at seq ($1 is its id).
func (f *fixture) adminAt(t *testing.T, sql string, seq int64, args ...any) {
	t.Helper()
	var id ids.UUID
	f.d.AdminQueryRow(t, "SELECT entry_id FROM pc.ledger_chain WHERE org_id = $1 AND seq = $2", []any{f.org, seq}, &id)
	f.d.AdminExec(t, sql, append([]any{id}, args...)...)
}

// wantFailure checks err is an integrity failure with code that was
// reported once: FAILED, audited, notified, and no longer due.
func (f *fixture) wantFailure(t *testing.T, err error, code string, seq int64) {
	t.Helper()
	var ie *checkpoints.IntegrityError
	if !errors.As(err, &ie) || ie.Code != code || (seq > 0 && ie.Seq != seq) {
		t.Fatalf("err = %v, want integrity failure %s at seq %d", err, code, seq)
	}
	var state, got string
	f.d.AdminQueryRow(t, "SELECT state, failure_code FROM pc.evidence_integrity WHERE org_id = $1", []any{f.org}, &state, &got)
	if state != "FAILED" || got != code {
		t.Fatalf("integrity %s %s, want FAILED %s", state, got, code)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.security.evidence_integrity_failed'"); n != 1 {
		t.Fatalf("%d audit entries, want 1", n)
	}
	f.notify.mu.Lock()
	sent := slices.Clone(f.notify.sent)
	f.notify.mu.Unlock()
	if len(sent) != 1 || sent[0].Type != "security.evidence_integrity_failed" || sent[0].Params["reason"] != code || sent[0].Org != f.org {
		t.Fatalf("notifications = %+v", sent)
	}
	if f.due(t, db.ListCheckpointsDue) || f.due(t, db.ListIntegrityDue) {
		t.Fatal("a failed org is still due for checkpoints or verification")
	}
	// Later runs do nothing and report nothing again.
	res, err := f.svc.Checkpoint(context.Background(), f.org)
	if err != nil || !res.Stopped || res.Signed {
		t.Fatalf("checkpoint after the failure = %+v, %v", res, err)
	}
	if res, err := f.svc.Verify(context.Background(), f.org); err != nil || !res.Stopped {
		t.Fatalf("verification after the failure = %+v, %v", res, err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.security.evidence_integrity_failed'"); n != 1 {
		t.Fatalf("the failure was audited %d times", n)
	}
}

func TestHR194_CheckpointsAreSignedAndExtendEachOther(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if res := f.checkpoint(t); res.Signed {
		t.Fatal("an org without entries got a checkpoint")
	}
	f.grow(t, 300)
	if res := f.checkpoint(t); !res.Signed || res.Size != 300 {
		t.Fatalf("first checkpoint = %+v", res)
	}
	first := f.latest(t)
	key := f.reg.Keys(keys.PurposeCheckpoints)[0]
	v, err := note.NewEd25519Verifier(origin+"/org/"+f.org.String(), key.Public)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := note.OpenCheckpoint(first.Note, origin+"/org/"+f.org.String(), v)
	if err != nil || c.Size != 300 || c.Root != f.chainRoot(t, 300) || first.Kid != key.KID || first.PqKid != nil {
		t.Fatalf("checkpoint note %+v, %v", c, err)
	}
	if f.due(t, db.ListCheckpointsDue) {
		t.Fatal("a checkpointed org is due again")
	}
	f.grow(t, 50)
	if !f.due(t, db.ListCheckpointsDue) {
		t.Fatal("a grown chain is not due")
	}
	if res := f.checkpoint(t); !res.Signed || res.Size != 350 {
		t.Fatalf("second checkpoint = %+v", res)
	}
	second := f.latest(t)
	c2, _, err := note.OpenCheckpoint(second.Note, origin+"/org/"+f.org.String(), v)
	if err != nil || c2.Root != f.chainRoot(t, 350) {
		t.Fatalf("second note: %v", err)
	}
	// The stored tiles prove the second tree extends the first.
	err = f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		r := tileReader{q: dbq.New(tx), org: f.org}
		proof, err := merkle.ConsistencyProof(ctx, r, 300, 350)
		if err != nil {
			return err
		}
		return merkle.VerifyConsistency(300, 350, proof, c.Root, c2.Root)
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := f.checkpoint(t); res.Signed {
		t.Fatal("a chain that did not grow got a new checkpoint")
	}
	res, err := f.svc.Verify(ctx, f.org)
	if err != nil || res.Size != 350 {
		t.Fatalf("daily verification = %+v, %v", res, err)
	}
	if f.due(t, db.ListIntegrityDue) {
		t.Fatal("an org verified now is due again")
	}
	if len(f.notify.sent) != 0 {
		t.Fatalf("notifications without a failure: %+v", f.notify.sent)
	}
}

type tileReader struct {
	q   *dbq.Queries
	org ids.OrgID
}

func (r tileReader) ReadTile(ctx context.Context, id merkle.TileID) ([]byte, error) {
	b, err := r.q.ReadLedgerTile(ctx, r.org, int16(id.Level), int64(id.Index)) //nolint:gosec // G115: test sizes
	if err != nil || len(b) < id.Width*merkle.HashSize {
		return nil, merkle.ErrTileNotFound
	}
	return b, nil
}

func TestHR111_ABacklogBecomesBoundedCheckpoints(t *testing.T) {
	f := newFixture(t)
	f.svc.MaxLeaves = 100
	f.grow(t, 250)
	for _, want := range []uint64{100, 200, 250} {
		if res := f.checkpoint(t); !res.Signed || res.Size != want {
			t.Fatalf("checkpoint = %+v, want size %d", res, want)
		}
	}
	if res := f.checkpoint(t); res.Signed {
		t.Fatal("a caught-up org got another checkpoint")
	}
	if res, err := f.svc.Verify(context.Background(), f.org); err != nil || res.Size != 250 {
		t.Fatalf("verification = %+v, %v", res, err)
	}
}

// TestHR194_CheckpointsAreCoSignedWithMLDSA65: with co-signing on, every
// checkpoint also carries the ML-DSA-65 line under its own key name
// (decision 6), and without the key nothing is signed.
func TestHR194_CheckpointsAreCoSignedWithMLDSA65(t *testing.T) {
	f := newFixture(t, keys.PurposeCheckpointsPQ)
	f.svc.Cosign = true
	f.grow(t, 3)
	if res := f.checkpoint(t); !res.Signed {
		t.Fatalf("no checkpoint: %+v", res)
	}
	row := f.latest(t)
	pq := f.reg.AltKeys(keys.PurposeCheckpointsPQ)[0]
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pq.Public)
	if err != nil {
		t.Fatal(err)
	}
	orgOrigin := origin + "/org/" + f.org.String()
	mv, err := note.NewMLDSA65Verifier(note.MLDSA65KeyName(orgOrigin), pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, verified, err := note.Open(row.Note, mv); err != nil || !note.SignedBy(verified, mv) {
		t.Fatalf("the ML-DSA-65 line does not verify: %v", err)
	}
	if row.PqKid == nil || *row.PqKid != pq.KID {
		t.Fatalf("pq_kid = %v, want %s", row.PqKid, pq.KID)
	}

	g := newFixture(t)
	g.svc.Cosign = true
	g.grow(t, 1)
	if _, err := g.svc.Checkpoint(context.Background(), g.org); !errors.Is(err, checkpoints.ErrNoSigner) {
		t.Fatalf("co-signing without the key: %v", err)
	}
}

// TestHR194_ARowEditedBeforeSealingStopsCheckpointing: an entry edited
// after it was chained but before a checkpoint covers it is caught when the
// links are recomputed; nothing is signed.
func TestHR194_ARowEditedBeforeSealingStopsCheckpointing(t *testing.T) {
	f := newFixture(t)
	f.grow(t, 10)
	f.checkpoint(t)
	f.grow(t, 5)
	f.adminAt(t, `UPDATE pc.ledger_entries SET body = '{"i":999}' WHERE id = $1`, 12)
	_, err := f.svc.Checkpoint(context.Background(), f.org)
	f.wantFailure(t, err, checkpoints.CodeChainLink, 12)
	if row := f.latest(t); row.TreeSize != 10 {
		t.Fatalf("a checkpoint of size %d was signed over the edited row", row.TreeSize)
	}
}

// TestHR194_TheDailyJobFindsARowEditedAfterSealing: an entry edited after a
// checkpoint covers it is caught by the daily re-verification.
func TestHR194_TheDailyJobFindsARowEditedAfterSealing(t *testing.T) {
	f := newFixture(t)
	f.grow(t, 10)
	f.checkpoint(t)
	f.adminAt(t, `UPDATE pc.ledger_entries SET body = '{"i":999}' WHERE id = $1`, 3)
	if res := f.checkpoint(t); res.Signed {
		t.Fatal("a checkpoint was signed though nothing grew")
	}
	_, err := f.svc.Verify(context.Background(), f.org)
	f.wantFailure(t, err, checkpoints.CodeChainLink, 3)
}

// TestT029_DeletedRowsAreDetected: a deleted chained row is caught by the
// next checkpoint when no checkpoint covers it, and by the daily job when
// one does.
func TestT029_DeletedRowsAreDetected(t *testing.T) {
	t.Run("unsealed", func(t *testing.T) {
		f := newFixture(t)
		f.grow(t, 10)
		f.checkpoint(t)
		f.grow(t, 5)
		f.adminAt(t, `DELETE FROM pc.ledger_chain WHERE entry_id = $1`, 12)
		_, err := f.svc.Checkpoint(context.Background(), f.org)
		f.wantFailure(t, err, checkpoints.CodeChainLink, 12)
	})
	t.Run("sealed", func(t *testing.T) {
		f := newFixture(t)
		f.grow(t, 10)
		f.checkpoint(t)
		f.adminAt(t, `DELETE FROM pc.ledger_chain WHERE entry_id = $1`, 5)
		_, err := f.svc.Verify(context.Background(), f.org)
		f.wantFailure(t, err, checkpoints.CodeChainLink, 5)
	})
}

// TestT029_ADeletedCheckpointIsDetected: removing the latest checkpoint
// leaves tiles it covered, which the next checkpoint finds.
func TestT029_ADeletedCheckpointIsDetected(t *testing.T) {
	f := newFixture(t)
	f.grow(t, 10)
	f.checkpoint(t)
	f.grow(t, 5)
	f.checkpoint(t)
	f.d.AdminExec(t, "DELETE FROM pc.checkpoints WHERE org_id = $1 AND tree_size = 15", f.org)
	f.grow(t, 2)
	_, err := f.svc.Checkpoint(context.Background(), f.org)
	f.wantFailure(t, err, checkpoints.CodeCheckpointMissing, 11)
}

// TestHR194_AnInconsistentTreeIsNeverSigned: tiles altered under a
// checkpoint make the new tree inconsistent with it, and the signer
// refuses; a full tile altered under it is found by the daily job.
func TestHR194_AnInconsistentTreeIsNeverSigned(t *testing.T) {
	t.Run("partial tile", func(t *testing.T) {
		f := newFixture(t)
		f.grow(t, 300)
		f.checkpoint(t)
		f.d.AdminExec(t, `UPDATE pc.ledger_tiles SET hashes = overlay(hashes placing '\xff'::bytea from 1 for 1)
			WHERE org_id = $1 AND level = 0 AND tile_index = 1`, f.org)
		f.grow(t, 10)
		_, err := f.svc.Checkpoint(context.Background(), f.org)
		f.wantFailure(t, err, checkpoints.CodeTreeInconsistent, 300)
		if row := f.latest(t); row.TreeSize != 300 {
			t.Fatalf("an inconsistent checkpoint of size %d was signed", row.TreeSize)
		}
	})
	t.Run("full tile", func(t *testing.T) {
		f := newFixture(t)
		f.grow(t, 300)
		f.checkpoint(t)
		f.d.AdminExec(t, `UPDATE pc.ledger_tiles SET hashes = overlay(hashes placing '\xff'::bytea from 1 for 1)
			WHERE org_id = $1 AND level = 0 AND tile_index = 0`, f.org)
		_, err := f.svc.Verify(context.Background(), f.org)
		f.wantFailure(t, err, checkpoints.CodeTreeMismatch, 0)
	})
	t.Run("edited checkpoint", func(t *testing.T) {
		f := newFixture(t)
		f.grow(t, 10)
		f.checkpoint(t)
		f.d.AdminExec(t, `UPDATE pc.checkpoints SET root_hash = overlay(root_hash placing '\xff'::bytea from 1 for 1)
			WHERE org_id = $1`, f.org)
		f.grow(t, 1)
		_, err := f.svc.Checkpoint(context.Background(), f.org)
		f.wantFailure(t, err, checkpoints.CodeCheckpointInvalid, 10)
	})
}

// TestHR194_RemovedBodiesStayInTheTree: an entry whose body retention
// removed is checkpointed and verified by its stored hash (decision 4).
func TestHR194_RemovedBodiesStayInTheTree(t *testing.T) {
	f := newFixture(t)
	f.grow(t, 5)
	f.adminAt(t, `UPDATE pc.ledger_entries SET body = NULL, body_removed_at = now(), removed_by_policy = $2 WHERE id = $1`, 3, ids.NewV7())
	if res := f.checkpoint(t); !res.Signed || res.Size != 5 {
		t.Fatalf("checkpoint = %+v", res)
	}
	if res, err := f.svc.Verify(context.Background(), f.org); err != nil || res.Size != 5 {
		t.Fatalf("verification = %+v, %v", res, err)
	}
}

// TestIntCheckpointJobsRunThroughTheLister: the dispatchers find due orgs
// through the audited lister and the org jobs checkpoint and verify them.
func TestIntCheckpointJobsRunThroughTheLister(t *testing.T) {
	f := newFixture(t)
	f.grow(t, 20)
	reg := jobs.NewRegistry()
	if err := checkpoints.Register(reg, f.svc); err != nil {
		t.Fatal(err)
	}
	client, err := jobs.NewClient(f.p, reg, jobs.Config{
		Queues: map[string]int{"default": 2}, PeriodicJobs: checkpoints.PeriodicJobs(time.Minute), Logger: pclog.Discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Stop(context.Background()) }()
	deadline := time.Now().Add(30 * time.Second)
	for f.count(t, "SELECT count(*) FROM pc.checkpoints WHERE tree_size = 20") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the checkpoint job did not run")
		}
		time.Sleep(100 * time.Millisecond)
	}
	var audited int
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.cross_org_list_audit WHERE purpose = 'checkpoints_due'", nil, &audited)
	if audited == 0 {
		t.Fatal("the dispatcher did not use the audited lister")
	}
}
