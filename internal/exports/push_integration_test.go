// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type pushFixture struct {
	*fixture
	sim   *s3Sim
	url   string
	reg   *keys.Registry
	admin context.Context
}

func newPushFixture(t *testing.T) *pushFixture {
	t.Helper()
	sim := newS3Sim()
	srv := httptest.NewTLSServer(sim)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	f := newFixture(t, Config{RootCAs: roots})
	reg := keys.NewRegistry()
	k, err := keys.GenerateSigningKey(keys.PurposeEvidencePacks)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	jc, err := jobs.NewClient(f.p, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.WithPushes(jc, nil, reg, nil)
	f.svc.partSize = 32
	f.d.AdminExec(t, `INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by)
		VALUES($1,$2,'org_admin',$3,'ORG','system:test'),($1,$4,'security_admin',$3,'ORG','system:test')`, f.org, ids.NewV7(), f.user, ids.NewV7())
	return &pushFixture{fixture: f, sim: sim, url: srv.URL, reg: reg, admin: f.as(td.KindUser, td.RoleOrgAdmin, td.RoleSecurityAdmin)}
}

func (f *pushFixture) destination(t *testing.T, name string, classes ...string) ids.UUID {
	t.Helper()
	d, err := f.svc.Create(f.admin, NewDestination{
		Name: name, DataClasses: classes, Credential: s3Key,
		Target: Target{Kind: KindS3, URL: f.url, Bucket: "bkt", Region: "eu-west-1", PathStyle: true, Internal: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Activate(f.admin, d.ID, stepup.StepUp{Credential: f.key, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return d.ID
}

func (f *pushFixture) pack(t *testing.T, content []byte, captures bool) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	sum := sha256.Sum256(content)
	include := `{"receipts": true}`
	if captures {
		include = `{"captures": true}`
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.d.AdminExec(t, `INSERT INTO pc.evidence_packs (org_id, id, created_by, scope_kind, scope, include, state, manifest, manifest_sha256,
		content, content_sha256, content_size, items, ready_at, expires_at)
		VALUES ($1, $2, $3, 'run', '{}', $4::jsonb, 'READY', 'signed-manifest-text', $5, $6, $5, $7, 0, $8, $8::timestamptz + interval '7 days')`,
		f.org, id, f.user, include, sum[:], content, int64(len(content)), now)
	return id
}

func (f *pushFixture) receipt(t *testing.T, id ids.UUID) Receipt {
	t.Helper()
	r, err := f.svc.GetReceipt(f.admin, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var packBody = bytes.Repeat([]byte("evidence "), 10)

func (s *s3Sim) openUploads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.uploads)
}

func (s *s3Sim) abortCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.aborted)
}

func (f *pushFixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	f.d.AdminQueryRow(t, sql, args, &n)
	return n
}

// TestHR514_EveryPushLeavesAReceipt: a delivered push records the object,
// its size, its hash and the destination's answer, and moves health; a
// failed one is a receipt too, with why.
// Covers: F517
func TestHR514_EveryPushLeavesAReceipt(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	pack := f.pack(t, packBody, false)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
	if err != nil {
		t.Fatal(err)
	}
	if r.State != ReceiptQueued {
		t.Fatalf("queued = %+v", r)
	}
	ctx := context.Background()
	if err := f.svc.Run(ctx, f.org, r.ID, false); err != nil {
		t.Fatal(err)
	}
	got := f.receipt(t, r.ID)
	sum := sha256.Sum256(packBody)
	if got.State != ReceiptDelivered || got.SizeBytes != int64(len(packBody)) || got.SHA256 != hex.EncodeToString(sum[:]) ||
		got.Parts < 2 || got.ETag == "" || got.DeliveredAt == nil {
		t.Fatalf("delivered = %+v", got)
	}
	if b, ok := f.sim.object("bkt/" + got.ObjectKey); !ok || !bytes.Equal(b, packBody) {
		t.Fatalf("object %q %v of %v", b, ok, f.sim.keys())
	}
	if !strings.Contains(got.Status, "delivered to vault") {
		t.Fatalf("status %q", got.Status)
	}
	d, err := f.svc.Get(f.admin, dest)
	if err != nil || d.Health != HealthHealthy || d.DeliveredPushes != 1 {
		t.Fatalf("health: %+v %v", d, err)
	}
	// Running it again sends nothing twice.
	if err := f.svc.Run(ctx, f.org, r.ID, false); err != nil {
		t.Fatal(err)
	}

	f.sim.failPart = 1
	r2, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Run(ctx, f.org, r2.ID, false); err == nil {
		t.Fatal("a failed attempt reported success")
	}
	if got := f.receipt(t, r2.ID); got.State != ReceiptQueued || got.FailureCode != "http_5xx" {
		t.Fatalf("retrying = %+v", got)
	}
	if err := f.svc.Run(ctx, f.org, r2.ID, true); err != nil {
		t.Fatal(err)
	}
	got = f.receipt(t, r2.ID)
	if got.State != ReceiptFailed || got.FailureCode != "http_5xx" || got.LastStatus != 500 || got.Attempts != 2 {
		t.Fatalf("failed = %+v", got)
	}
	if d, err := f.svc.Get(f.admin, dest); err != nil || d.FailedPushes != 2 || d.LastFailureCode != "http_5xx" {
		t.Fatalf("health: %+v %v", d, err)
	}
	list, _, err := f.svc.ListReceipts(f.admin, dest, 0, "")
	if err != nil || len(list) != 2 || list[0].ID != r2.ID {
		t.Fatalf("list: %d %v", len(list), err)
	}
}

// TestHR516_AFailedMultipartIsAborted: a part that fails ends in an abort,
// on the failing attempt and every later one, and nothing stays open.
// Covers: F517
func TestHR516_AFailedMultipartIsAborted(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	f.sim.failPart = 2
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: f.pack(t, packBody, false)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Run(context.Background(), f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	got := f.receipt(t, r.ID)
	if got.State != ReceiptFailed || got.AbortState != "ABORTED" || f.sim.abortCount() != 1 || f.sim.openUploads() != 0 {
		t.Fatalf("receipt %+v, %d aborts, %d open", got, f.sim.abortCount(), f.sim.openUploads())
	}
	if len(f.sim.keys()) != 0 {
		t.Fatalf("objects %v", f.sim.keys())
	}
}

// TestHR516_ACanceledPushStillAborts: the abort runs on its own context,
// so a job that was stopped mid-part still ends its upload.
// Covers: F517
func TestHR516_ACanceledPushStillAborts(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: f.pack(t, packBody, false)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.load(context.Background(), f.org, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).StartExportPush(ctx, f.org, r.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	u := f.svc.newUploadFor(p)
	if err := u.write(ctx, packBody[:40]); err != nil {
		t.Fatal(err)
	}
	cancel()
	f.svc.abortUpload(ctx, p)
	if f.sim.abortCount() != 1 || f.sim.openUploads() != 0 {
		t.Fatalf("%d aborts, %d open", f.sim.abortCount(), f.sim.openUploads())
	}
}

// TestHR516_TheSweepFinishesWhatAnAbortLeft: an abort the destination
// refused stays pending and the sweep ends it; so does an upload a crash
// left behind.
// Covers: F517
func TestHR516_TheSweepFinishesWhatAnAbortLeft(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	f.sim.failPart, f.sim.failAborts = 2, abortAttempts
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: f.pack(t, packBody, false)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.AbortState != "PENDING" || f.sim.openUploads() != 1 {
		t.Fatalf("receipt %+v, %d open", got, f.sim.openUploads())
	}
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.AbortState != "ABORTED" || f.sim.openUploads() != 0 {
		t.Fatalf("after the sweep: %+v, %d open", got, f.sim.openUploads())
	}

	// A crash: the receipt is PUSHING with an upload and nobody is running.
	f.sim.failPart = 0
	crashed, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: f.pack(t, packBody, false)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.load(ctx, f.org, crashed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).StartExportPush(ctx, f.org, crashed.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.newUploadFor(p).write(ctx, packBody[:40]); err != nil {
		t.Fatal(err)
	}
	f.d.AdminExec(t, "UPDATE pc.export_receipts SET started_at = now() - interval '9 hours' WHERE org_id = $1 AND id = $2", f.org, crashed.ID)
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, crashed.ID); got.State != ReceiptFailed || got.FailureCode != "push_stopped" || got.AbortState != "ABORTED" || f.sim.openUploads() != 0 {
		t.Fatalf("crashed = %+v, %d open", got, f.sim.openUploads())
	}
}

// TestHR516_ARetryEndsTheOldUploadFirst: a retry after a failed abort ends
// that upload before it starts another, so its id is never lost.
// Covers: F517
func TestHR516_ARetryEndsTheOldUploadFirst(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	f.sim.failPart, f.sim.failAborts = 2, abortAttempts
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: f.pack(t, packBody, false)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.svc.Run(ctx, f.org, r.ID, false); err == nil {
		t.Fatal("a failed attempt reported success")
	}
	if got := f.receipt(t, r.ID); got.State != ReceiptQueued || got.AbortState != "PENDING" || f.sim.openUploads() != 1 {
		t.Fatalf("receipt %+v, %d open", got, f.sim.openUploads())
	}
	// The destination still refuses the abort: nothing new starts.
	f.sim.failPart, f.sim.failAborts = 0, abortAttempts
	if err := f.svc.Run(ctx, f.org, r.ID, false); err == nil {
		t.Fatal("started with an abort pending")
	}
	if f.sim.openUploads() != 1 {
		t.Fatalf("%d open", f.sim.openUploads())
	}
	if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	got := f.receipt(t, r.ID)
	if got.State != ReceiptDelivered || got.AbortState != "NONE" || f.sim.abortCount() != 1 || f.sim.openUploads() != 0 {
		t.Fatalf("receipt %+v, %d aborts, %d open", got, f.sim.abortCount(), f.sim.openUploads())
	}
}

// TestHR516_AHangingDestinationStopsOnlyItsOrg: each org sweeps in its own
// job, so a destination that never answers uses up its own org's job and
// nothing else; the dispatcher still gives every org a job.
// Covers: F517
func TestHR516_AHangingDestinationStopsOnlyItsOrg(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	pack := f.pack(t, []byte("a short evidence pack, one part"), false)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	f.d.AdminExec(t, "UPDATE pc.evidence_packs SET state = 'EXPIRED', content = NULL WHERE org_id = $1 AND id = $2", f.org, pack)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.sim.mu.Lock()
	f.sim.hangBucket, f.sim.release = "bkt", release
	f.sim.mu.Unlock()

	other := ids.New[ids.Org]()
	f.d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other)
	short, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := f.svc.Sweep(short, f.org); err == nil {
		t.Fatal("a hanging destination reported success")
	}
	if err := f.svc.Sweep(ctx, other); err != nil {
		t.Fatalf("the second org: %v", err)
	}
	jobs, err := sweepJobs(ctx, f.p)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[ids.OrgID]bool{}
	for _, j := range jobs {
		seen[j.Args.(SweepOrgArgs).Org] = true
	}
	if !seen[f.org] || !seen[other] {
		t.Fatalf("jobs for %v", seen)
	}
	if got := f.receipt(t, r.ID); got.NoticeState != "PENDING" {
		t.Fatalf("hung notice: %+v", got)
	}
}

// TestHR516_ATimeoutEndsTheStepNotTheOrg: a target that stops answering
// costs one request of each step, and aborts that time out never keep the
// notices from their turn.
// Covers: F517
func TestHR516_ATimeoutEndsTheStepNotTheOrg(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	ctx := context.Background()
	for range 2 {
		pack := f.pack(t, []byte("a short evidence pack, one part"), false)
		r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
			t.Fatal(err)
		}
		f.d.AdminExec(t, "UPDATE pc.evidence_packs SET state = 'EXPIRED', content = NULL WHERE org_id = $1 AND id = $2", f.org, pack)
	}
	f.sim.failPart, f.sim.failAborts = 2, 2*abortAttempts
	for range 2 {
		r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: f.pack(t, packBody, false)})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	f.d.AdminExec(t, "UPDATE pc.export_receipts SET abort_tried_at = NULL WHERE org_id = $1", f.org)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.sim.mu.Lock()
	f.sim.hangBucket, f.sim.release = "bkt", release
	f.sim.mu.Unlock()
	f.svc.internal.Timeout = 200 * time.Millisecond
	if err := f.svc.Sweep(ctx, f.org); err == nil {
		t.Fatal("a hanging destination reported success")
	}
	if n := f.count(t, "SELECT count(*) FROM pc.export_receipts WHERE org_id = $1 AND abort_tried_at IS NOT NULL", f.org); n != 1 {
		t.Fatalf("%d aborts tried, want the one that timed out", n)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.export_receipts WHERE org_id = $1 AND notice_attempts > 0", f.org); n != 1 {
		t.Fatalf("%d notices tried, want the one that timed out", n)
	}
	// The next hour takes the abort that was not tried, then the oldest try.
	var turns []ids.UUID
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		turns, err = dbq.New(tx).ListExportAborts(ctx, f.org, 0, 2)
		return err
	}, db.ReadOnly()); err != nil {
		t.Fatal(err)
	}
	if len(turns) != 2 {
		t.Fatalf("aborts %v", turns)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.export_receipts WHERE org_id = $1 AND id = $2 AND abort_tried_at IS NULL", f.org, turns[0]); n != 1 {
		t.Fatal("a tried abort came before the untried one")
	}
}

// TestHR516_ALoadErrorLeavesTheNotices: a receipt that cannot be loaded
// takes its turn and the notices still go out.
// Covers: F517
func TestHR516_ALoadErrorLeavesTheNotices(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	broken := f.destination(t, "broken", ClassEvidencePacks)
	f.sim.failPart, f.sim.failAborts = 2, abortAttempts
	stuck, err := f.svc.Push(f.admin, PushRequest{Destination: broken, Class: ClassEvidencePacks, Artifact: f.pack(t, packBody, false)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Run(ctx, f.org, stuck.ID, true); err != nil {
		t.Fatal(err)
	}
	f.sim.failPart = 0
	dest := f.destination(t, "vault", ClassEvidencePacks)
	pack := f.pack(t, []byte("a short evidence pack, one part"), false)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	f.d.AdminExec(t, "UPDATE pc.evidence_packs SET state = 'EXPIRED', content = NULL WHERE org_id = $1 AND id = $2", f.org, pack)
	f.d.AdminExec(t, "UPDATE pc.export_destinations SET secret = decode(repeat('00', 16), 'hex') WHERE org_id = $1 AND id = $2", f.org, broken)
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.NoticeState != "SENT" {
		t.Fatalf("notice %+v", got)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.export_receipts WHERE org_id = $1 AND id = $2 AND abort_tried_at IS NOT NULL", f.org, stuck.ID); n != 1 {
		t.Fatalf("the unloadable abort took no turn: %d", n)
	}
}

// TestHR516_AFailedCompleteRemovesTheManifest: the manifest goes before
// Complete, so an upload that fails there takes it back.
// Covers: F517
func TestHR516_AFailedCompleteRemovesTheManifest(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassOrgExports)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassOrgExports, Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	request := ids.NewV7()
	f.d.AdminExec(t, `INSERT INTO pc.data_requests (org_id, id, kind, state, created_by) VALUES ($1, $2, 'EXPORT', 'BUILDING', $3)`, f.org, request, f.user)
	st, err := f.svc.Open(ctx, f.org, request, f.user)
	if err != nil || st == nil {
		t.Fatalf("open: %v %v", st, err)
	}
	keep := func(context.Context) error { return nil }
	if err := st.Write(ctx, bytes.Repeat([]byte("x"), 90), keep); err != nil {
		t.Fatal(err)
	}
	f.sim.mu.Lock()
	f.sim.completeError = true
	f.sim.mu.Unlock()
	if err := st.Finish(ctx, "signed-manifest", keep); err == nil {
		t.Fatal("a failed Complete reported success")
	}
	st.Abort()
	got := f.receipt(t, r.ID)
	if got.State != ReceiptFailed || got.AbortState != "ABORTED" || len(f.sim.keys()) != 0 || f.sim.openUploads() != 0 {
		t.Fatalf("receipt %+v, objects %v, %d open", got, f.sim.keys(), f.sim.openUploads())
	}
	f.sim.mu.Lock()
	defer f.sim.mu.Unlock()
	if len(f.sim.deletes) != 1 || f.sim.deletes[0] != "bkt/"+got.ObjectKey+ManifestSuffix {
		t.Fatalf("deleted %v", f.sim.deletes)
	}
}

// TestHR516_ALateAbortLeavesARetrysManifest: a sweep that loaded a pending
// abort before a retry ended it changes nothing: neither the retry's newer
// upload nor the manifest the retry delivered.
// Covers: F517
func TestHR516_ALateAbortLeavesARetrysManifest(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassOrgExports)
	request := ids.NewV7()
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.d.AdminExec(t, `INSERT INTO pc.data_requests (org_id, id, kind, state, created_by, ready_at, expires_at, parts, total_size, manifest)
		VALUES ($1, $2, 'EXPORT', 'READY', $3, $4, $4::timestamptz + interval '7 days', 1, 50, 'signed-manifest')`, f.org, request, f.user, now)
	part := bytes.Repeat([]byte("p"), 50)
	sum := sha256.Sum256(part)
	f.d.AdminExec(t, `INSERT INTO pc.data_request_parts (org_id, request_id, number, content, sha256) VALUES ($1, $2, 1, $3, $4)`, f.org, request, part, sum[:])
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassOrgExports, Artifact: request})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f.sim.completeError, f.sim.failAborts = true, abortAttempts
	if err := f.svc.Run(ctx, f.org, r.ID, false); err == nil {
		t.Fatal("a failed Complete reported success")
	}
	late, err := f.svc.load(ctx, f.org, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if late.uploadID == "" || !late.manifest {
		t.Fatalf("nothing pending: %+v", late)
	}
	first := late.uploadID

	// A retry's newer upload is under way.
	f.d.AdminExec(t, "UPDATE pc.export_receipts SET upload_id = 'newer' WHERE org_id = $1 AND id = $2", f.org, r.ID)
	if err := f.svc.abortUpload(ctx, late); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.AbortState != "PENDING" {
		t.Fatalf("a late abort ended the newer upload: %+v", got)
	}
	if len(f.sim.deletes) != 0 {
		t.Fatalf("deleted %v", f.sim.deletes)
	}

	// The retry has delivered.
	f.d.AdminExec(t, "UPDATE pc.export_receipts SET upload_id = $3 WHERE org_id = $1 AND id = $2", f.org, r.ID, first)
	if late, err = f.svc.load(ctx, f.org, r.ID); err != nil {
		t.Fatal(err)
	}
	f.sim.completeError = false
	if err := f.svc.Run(ctx, f.org, r.ID, false); err != nil {
		t.Fatal(err)
	}
	got := f.receipt(t, r.ID)
	if got.State != ReceiptDelivered {
		t.Fatalf("receipt %+v", got)
	}
	f.sim.deletes = nil
	if err := f.svc.abortUpload(ctx, late); err != nil {
		t.Fatal(err)
	}
	if b, _ := f.sim.object("bkt/" + got.ObjectKey + ManifestSuffix); string(b) != "signed-manifest" || len(f.sim.deletes) != 0 {
		t.Fatalf("manifest %q, deleted %v", b, f.sim.deletes)
	}
}

// TestHR516_ALateAbortLeavesARetrysChunks: on an HTTPS PUT destination too,
// a sweep that loaded a pending abort touches only the attempt it loaded:
// the retry overlapping it delivers every chunk its index names, and its
// manifest.
// Covers: F517
func TestHR516_ALateAbortLeavesARetrysChunks(t *testing.T) {
	f := newPushFixture(t)
	sim := &putSim{objects: map[string][]byte{}}
	srv := httptest.NewTLSServer(sim) // the same test certificate as f's
	t.Cleanup(srv.Close)
	d, err := f.svc.Create(f.admin, NewDestination{
		Name: "vault", DataClasses: []string{ClassOrgExports}, Credential: Credential{BearerToken: "token-1234"},
		Target: Target{Kind: KindHTTPSPut, URL: srv.URL + "/in", Internal: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Activate(f.admin, d.ID, stepup.StepUp{Credential: f.key, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	request := ids.NewV7()
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.d.AdminExec(t, `INSERT INTO pc.data_requests (org_id, id, kind, state, created_by, ready_at, expires_at, parts, total_size, manifest)
		VALUES ($1, $2, 'EXPORT', 'READY', $3, $4, $4::timestamptz + interval '7 days', 1, 100, 'signed-manifest')`, f.org, request, f.user, now)
	part := make([]byte, 100)
	for i := range part {
		part[i] = byte(i)
	}
	sum := sha256.Sum256(part)
	f.d.AdminExec(t, `INSERT INTO pc.data_request_parts (org_id, request_id, number, content, sha256) VALUES ($1, $2, 1, $3, $4)`, f.org, request, part, sum[:])
	r, err := f.svc.Push(f.admin, PushRequest{Destination: d.ID, Class: ClassOrgExports, Artifact: request})
	if err != nil {
		t.Fatal(err)
	}

	// Attempt 1 fails at chunk 2 and its abort is refused.
	ctx := context.Background()
	sim.failAfter, sim.failDeletesFrom = 2, 1
	if err := f.svc.Run(ctx, f.org, r.ID, false); err == nil {
		t.Fatal("a failed attempt reported success")
	}
	if got := f.receipt(t, r.ID); got.AbortState != "PENDING" {
		t.Fatalf("receipt %+v", got)
	}
	// A sweep loads that abort.
	late, err := f.svc.load(ctx, f.org, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if late.uploadID == "" || late.parts != 2 {
		t.Fatalf("nothing pending: %+v", late)
	}

	// The retry ends the abort and re-sends; the loaded abort runs under it.
	sim.failAfter, sim.failDeletesFrom = 0, 0
	ran := false
	sim.onPut = func(key string) {
		if !ran && strings.HasSuffix(key, "-000002") {
			ran = true
			if err := f.svc.abortUpload(ctx, late); err != nil {
				t.Errorf("late abort: %v", err)
			}
		}
	}
	if err := f.svc.Run(ctx, f.org, r.ID, false); err != nil {
		t.Fatal(err)
	}
	got := f.receipt(t, r.ID)
	if !ran || got.State != ReceiptDelivered || got.AbortState != "NONE" {
		t.Fatalf("ran %v, receipt %+v", ran, got)
	}
	var index struct {
		Chunks []chunkEntry `json:"chunks"`
	}
	if err := json.Unmarshal(sim.objects["in/"+got.ObjectKey], &index); err != nil {
		t.Fatal(err)
	}
	var whole []byte
	for _, c := range index.Chunks {
		b, ok := sim.objects["in/"+c.Key]
		if !ok {
			t.Fatalf("the index lists %s and it is gone", c.Key)
		}
		whole = append(whole, b...)
	}
	if !bytes.Equal(whole, part) {
		t.Fatalf("the chunks hold %d bytes", len(whole))
	}
	if string(sim.objects["in/"+got.ObjectKey+ManifestSuffix]) != "signed-manifest" {
		t.Fatalf("objects %v", sim.objects)
	}
}

// TestF517_AnExpiredArtifactNeverLeaves: past its expiry by the database
// clock an artifact is gone, whether or not the expiry job has run yet, at
// the request and again when the push starts.
// Covers: F517
func TestF517_AnExpiredArtifactNeverLeaves(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	lapse := func(pack ids.UUID) {
		f.d.AdminExec(t, `UPDATE pc.evidence_packs SET ready_at = now() - interval '8 days', expires_at = now() - interval '1 day'
			WHERE org_id = $1 AND id = $2`, f.org, pack)
	}
	expired := f.pack(t, packBody, false)
	lapse(expired)
	if _, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: expired}); !errors.Is(err, ErrArtifact) {
		t.Fatalf("expired: %v", err)
	}
	queued := f.pack(t, packBody, false)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: queued})
	if err != nil {
		t.Fatal(err)
	}
	lapse(queued)
	if err := f.svc.Run(context.Background(), f.org, r.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.State != ReceiptFailed || got.FailureCode != "artifact_gone" || len(f.sim.keys()) != 0 {
		t.Fatalf("receipt %+v, objects %v", got, f.sim.keys())
	}
}

// TestHR514_AClaimedStreamNeverStaysQueued: a claimed streamed receipt is
// PUSHING from that moment, so a crash right after the claim still ends in
// a failed receipt.
// Covers: F517
func TestHR514_AClaimedStreamNeverStaysQueued(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassOrgExports)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassOrgExports, Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	request := ids.NewV7()
	f.d.AdminExec(t, `INSERT INTO pc.data_requests (org_id, id, kind, state, created_by) VALUES ($1, $2, 'EXPORT', 'BUILDING', $3)`, f.org, request, f.user)
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).ClaimStreamedExportReceipt(ctx, dbq.ClaimStreamedExportReceiptParams{
			RequestID: &request, OrgID: f.org, RequestedBy: f.user, WaitSeconds: int32(StreamWait / time.Second),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.State != ReceiptPushing || got.Attempts != 1 {
		t.Fatalf("claimed = %+v", got)
	}
	f.d.AdminExec(t, "UPDATE pc.export_receipts SET started_at = now() - interval '9 hours' WHERE org_id = $1 AND id = $2", f.org, r.ID)
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.State != ReceiptFailed || got.FailureCode != "push_stopped" {
		t.Fatalf("after the sweep: %+v", got)
	}
}

// TestHR516_AFailedManifestLeavesNothingWhole: the manifest goes first, so
// when it fails no whole object sits behind a failed receipt.
// Covers: F517
func TestHR516_AFailedManifestLeavesNothingWhole(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassOrgExports)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassOrgExports, Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	request := ids.NewV7()
	f.d.AdminExec(t, `INSERT INTO pc.data_requests (org_id, id, kind, state, created_by) VALUES ($1, $2, 'EXPORT', 'BUILDING', $3)`, f.org, request, f.user)
	st, err := f.svc.Open(ctx, f.org, request, f.user)
	if err != nil || st == nil {
		t.Fatalf("open: %v %v", st, err)
	}
	keep := func(context.Context) error { return nil }
	if err := st.Write(ctx, bytes.Repeat([]byte("x"), 90), keep); err != nil {
		t.Fatal(err)
	}
	f.sim.mu.Lock()
	f.sim.failSuffix = ManifestSuffix
	f.sim.mu.Unlock()
	if err := st.Finish(ctx, "signed-manifest", keep); err == nil {
		t.Fatal("a failed manifest reported success")
	}
	st.Abort()
	got := f.receipt(t, r.ID)
	if got.State != ReceiptFailed || got.AbortState != "ABORTED" || len(f.sim.keys()) != 0 || f.sim.openUploads() != 0 {
		t.Fatalf("receipt %+v, objects %v, %d open", got, f.sim.keys(), f.sim.openUploads())
	}
}

// TestHR515_ARemovalSendsASignedNotice: when a pushed pack is removed here
// the destination gets a signed notice next to the object, the object
// stays, nothing is deleted there, and the receipt says only that a copy
// exists there.
// Covers: F517
func TestHR515_ARemovalSendsASignedNotice(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	pack := f.pack(t, packBody, false)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	// Nothing was removed: the sweep sends nothing.
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.NoticeState != "NONE" || got.RemovedHereAt != nil {
		t.Fatalf("before removal: %+v", got)
	}
	f.d.AdminExec(t, "UPDATE pc.evidence_packs SET state = 'EXPIRED', content = NULL WHERE org_id = $1 AND id = $2", f.org, pack)
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	got := f.receipt(t, r.ID)
	if got.NoticeState != "SENT" || got.RemovedHereAt == nil || got.Status != "removed here; a copy exists at vault" {
		t.Fatalf("after removal: %+v", got)
	}
	notice, ok := f.sim.object("bkt/" + got.NoticeKey)
	if !ok || got.NoticeKey != got.ObjectKey+NoticeSuffix {
		t.Fatalf("notice %q of %v", got.NoticeKey, f.sim.keys())
	}
	v, err := f.reg.Verifier(keys.PurposeEvidencePacks, NoticeJWSType)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := v.Verify(string(notice))
	if err != nil {
		t.Fatal(err)
	}
	var n RemovalNotice
	if err := json.Unmarshal(payload, &n); err != nil {
		t.Fatal(err)
	}
	if n.Format != NoticeFormat || n.Statement != NoticeStatement || n.ObjectKey != got.ObjectKey || n.SHA256 != got.SHA256 || n.Artifact != pack.String() {
		t.Fatalf("notice = %+v", n)
	}
	if b, ok := f.sim.object("bkt/" + got.ObjectKey); !ok || !bytes.Equal(b, packBody) {
		t.Fatal("the pushed object changed")
	}
	if len(f.sim.deletes) != 0 {
		t.Fatalf("deleted at the destination: %v", f.sim.deletes)
	}
	// One notice, however often the sweep runs.
	before := len(f.sim.keys())
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if len(f.sim.keys()) != before {
		t.Fatal("a second notice")
	}
}

// TestHR515_ANoticeWaitsOrStaysUndeliverable: a failing destination gets
// the notice later, a disabled one never, and the receipt still does not
// say the copy is gone.
// Covers: F517
func TestHR515_ANoticeWaitsOrStaysUndeliverable(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	pack := f.pack(t, []byte("a short evidence pack, one part"), false)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	f.d.AdminExec(t, "UPDATE pc.evidence_packs SET state = 'EXPIRED', content = NULL WHERE org_id = $1 AND id = $2", f.org, pack)
	f.sim.failPut = true
	if err := f.svc.Sweep(ctx, f.org); err == nil {
		t.Fatal("a failed notice reported success")
	}
	if got := f.receipt(t, r.ID); got.NoticeState != "PENDING" {
		t.Fatalf("after a failure: %+v", got)
	}
	f.sim.failPut = false
	if _, err := f.svc.SetState(f.admin, dest, StateDisabled); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.NoticeState != "UNDELIVERABLE" || got.Status != "removed here; a copy exists at vault" {
		t.Fatalf("disabled: %+v", got)
	}
}

// TestT223_TheDataClassFilterHolds: a destination receives only its
// classes, a pack with opened captures needs payload_captures as well, and
// a refusal sends nothing and leaves an audit entry.
// Covers: F517
func TestT223_TheDataClassFilterHolds(t *testing.T) {
	f := newPushFixture(t)
	packs := f.destination(t, "packs", ClassEvidencePacks)
	if _, err := f.svc.Push(f.admin, PushRequest{Destination: packs, Class: ClassOrgExports, Stream: true}); !errors.Is(err, ErrClass) {
		t.Fatalf("org export to a packs destination: %v", err)
	}
	withCaptures := f.pack(t, packBody, true)
	if _, err := f.svc.Push(f.admin, PushRequest{Destination: packs, Class: ClassEvidencePacks, Artifact: withCaptures}); !errors.Is(err, ErrClass) {
		t.Fatalf("pack with captures: %v", err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.export_receipts WHERE org_id = $1", f.org); n != 0 {
		t.Fatalf("%d receipts", n)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.export.push_refused'", f.org); n != 2 {
		t.Fatalf("%d refusals audited", n)
	}
	both := f.destination(t, "both", ClassEvidencePacks, ClassPayloadCaptures)
	if _, err := f.svc.Push(f.admin, PushRequest{Destination: both, Class: ClassEvidencePacks, Artifact: withCaptures}); err != nil {
		t.Fatal(err)
	}
}

// TestT223_NothingLeavesWithoutAnActiveDestinationOrAuthority: a pushed
// artifact needs an ACTIVE destination when it is asked for and when it
// goes, and a person who still may: what is queued stops otherwise.
// Covers: F517
func TestT223_NothingLeavesWithoutAnActiveDestinationOrAuthority(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	pack := f.pack(t, packBody, false)
	ctx := context.Background()
	push := func() Receipt {
		t.Helper()
		r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if _, err := f.svc.Push(f.as(td.KindUser, td.RoleSecurityAdmin), PushRequest{Destination: dest, Class: ClassOrgExports, Stream: true}); err == nil {
		t.Fatal("pushed an org export without data.export")
	}
	queued := push()
	if _, err := f.svc.SetState(f.admin, dest, StatePaused); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack}); !errors.Is(err, ErrState) {
		t.Fatalf("push to a paused destination: %v", err)
	}
	if err := f.svc.Run(ctx, f.org, queued.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, queued.ID); got.State != ReceiptFailed || got.FailureCode != "destination_not_active" {
		t.Fatalf("paused: %+v", got)
	}
	if _, err := f.svc.SetState(f.admin, dest, StateActive); err != nil {
		t.Fatal(err)
	}
	lost := push()
	f.d.AdminExec(t, "DELETE FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2", f.org, f.user)
	if err := f.svc.Run(ctx, f.org, lost.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, lost.ID); got.State != ReceiptFailed || got.FailureCode != "authority_lost" {
		t.Fatalf("authority: %+v", got)
	}
	if len(f.sim.keys()) != 0 {
		t.Fatalf("objects %v", f.sim.keys())
	}
}

// TestT223_AHoldNeverBlocksAPush: a legal hold keeps data here; it does not
// stop a copy leaving, and it is not bypassed by one (a hold's data stays).
// Covers: F517
func TestT223_AHoldNeverBlocksAPush(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassEvidencePacks)
	f.d.AdminExec(t, `INSERT INTO pc.legal_holds (org_id, id, scope, reason, created_by) VALUES ($1, $2, 'org', 'litigation', $3)`, f.org, ids.NewV7(), f.user)
	pack := f.pack(t, packBody, false)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassEvidencePacks, Artifact: pack})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Run(context.Background(), f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.State != ReceiptDelivered {
		t.Fatalf("held = %+v", got)
	}
}

// TestHR516_AStreamedExportAbortsWhenItsBuildFails: a waiting push claims
// the build; parts go out as they come, and a build that fails aborts the
// upload and fails the receipt.
// Covers: F517
func TestHR516_AStreamedExportAbortsWhenItsBuildFails(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassOrgExports)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassOrgExports, Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	request := ids.NewV7()
	f.d.AdminExec(t, `INSERT INTO pc.data_requests (org_id, id, kind, state, created_by) VALUES ($1, $2, 'EXPORT', 'BUILDING', $3)`, f.org, request, f.user)
	// Someone else's export never takes it.
	if st, err := f.svc.Open(ctx, f.org, request, ids.NewV7()); err != nil || st != nil {
		t.Fatalf("another person: %v %v", st, err)
	}
	st, err := f.svc.Open(ctx, f.org, request, f.user)
	if err != nil || st == nil {
		t.Fatalf("open: %v %v", st, err)
	}
	keep := func(context.Context) error { return nil }
	if err := st.Write(ctx, bytes.Repeat([]byte("x"), 40), keep); err != nil {
		t.Fatal(err)
	}
	st.Abort()
	got := f.receipt(t, r.ID)
	if got.State != ReceiptFailed || got.FailureCode != "build_failed" || got.AbortState != "ABORTED" || f.sim.openUploads() != 0 {
		t.Fatalf("receipt %+v, %d open", got, f.sim.openUploads())
	}
}

// TestF517_AStreamedExportArrivesWhole: the parts arrive as one object with
// the signed manifest next to it, and Abort after Finish does nothing.
// Covers: F517
func TestF517_AStreamedExportArrivesWhole(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassOrgExports)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassOrgExports, Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	request := ids.NewV7()
	f.d.AdminExec(t, `INSERT INTO pc.data_requests (org_id, id, kind, state, created_by) VALUES ($1, $2, 'EXPORT', 'BUILDING', $3)`, f.org, request, f.user)
	st, err := f.svc.Open(ctx, f.org, request, f.user)
	if err != nil || st == nil {
		t.Fatalf("open: %v %v", st, err)
	}
	keep := func(context.Context) error { return nil }
	var want bytes.Buffer
	for i := range 3 {
		b := bytes.Repeat([]byte{byte('a' + i)}, 30)
		want.Write(b)
		if err := st.Write(ctx, b, keep); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Finish(ctx, "signed-manifest", keep); err != nil {
		t.Fatal(err)
	}
	st.Abort()
	got := f.receipt(t, r.ID)
	if got.State != ReceiptDelivered || got.SizeBytes != 90 || got.Artifact == nil || *got.Artifact != request || f.sim.abortCount() != 0 {
		t.Fatalf("receipt %+v, %d aborts", got, f.sim.abortCount())
	}
	if b, _ := f.sim.object("bkt/" + got.ObjectKey); !bytes.Equal(b, want.Bytes()) {
		t.Fatalf("object %q", b)
	}
	if b, _ := f.sim.object("bkt/" + got.ObjectKey + ManifestSuffix); string(b) != "signed-manifest" {
		t.Fatalf("manifest %q", b)
	}
}

// TestF517_AStoredExportPushesPartByPart: a ready export's parts go out in
// order as one object, with its manifest; a streamed push nobody started
// ends on its own.
// Covers: F517
func TestF517_AStoredExportPushesPartByPart(t *testing.T) {
	f := newPushFixture(t)
	dest := f.destination(t, "vault", ClassOrgExports)
	request := ids.NewV7()
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.d.AdminExec(t, `INSERT INTO pc.data_requests (org_id, id, kind, state, created_by, ready_at, expires_at, parts, total_size, manifest)
		VALUES ($1, $2, 'EXPORT', 'READY', $3, $4, $4::timestamptz + interval '7 days', 2, 50, 'signed-manifest')`, f.org, request, f.user, now)
	first, second := bytes.Repeat([]byte("p"), 25), bytes.Repeat([]byte("q"), 25)
	for n, part := range [][]byte{first, second} {
		sum := sha256.Sum256(part)
		f.d.AdminExec(t, `INSERT INTO pc.data_request_parts (org_id, request_id, number, content, sha256) VALUES ($1, $2, $3, $4, $5)`, f.org, request, n+1, part, sum[:])
	}
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassOrgExports, Artifact: request})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	got := f.receipt(t, r.ID)
	if got.State != ReceiptDelivered || got.SizeBytes != 50 {
		t.Fatalf("receipt %+v", got)
	}
	if b, _ := f.sim.object("bkt/" + got.ObjectKey); !bytes.Equal(b, append(first, second...)) {
		t.Fatalf("object %q", b)
	}
	if b, _ := f.sim.object("bkt/" + got.ObjectKey + ManifestSuffix); string(b) != "signed-manifest" {
		t.Fatalf("manifest %q", b)
	}
	waiting, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassOrgExports, Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	f.d.AdminExec(t, "UPDATE pc.export_receipts SET created_at = now() - interval '2 hours' WHERE org_id = $1 AND id = $2", f.org, waiting.ID)
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, waiting.ID); got.State != ReceiptFailed || got.FailureCode != "no_export_started" {
		t.Fatalf("waiting = %+v", got)
	}
}
