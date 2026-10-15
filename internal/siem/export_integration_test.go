// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package siem

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
)

// fakeFeed serves fixed events (the D2 feed reader's contract).
type fakeFeed struct{ events []ocsf.Event }

func (f *fakeFeed) After(_ context.Context, _ db.TenantTx, after int64, limit int) ([]ocsf.Event, error) {
	var out []ocsf.Event
	for _, e := range f.events {
		if e.Seq > after && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeFeed) Head(context.Context, db.TenantTx) (int64, error) {
	if len(f.events) == 0 {
		return 0, nil
	}
	return f.events[len(f.events)-1].Seq, nil
}

type request struct {
	header http.Header
	body   []byte
}

// receiver is a SIEM endpoint on 127.0.0.1 answering with status.
type receiver struct {
	mu     sync.Mutex
	status int
	got    []request
	srv    *httptest.Server
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{status: http.StatusOK}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.got = append(r.got, request{header: req.Header.Clone(), body: b})
		w.WriteHeader(r.status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) set(status int) {
	r.mu.Lock()
	r.status = status
	r.mu.Unlock()
}

func (r *receiver) requests() []request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]request(nil), r.got...)
}

type sinkCalls struct{ got []DeliveryFailure }

func (s *sinkCalls) DeliveryFailing(_ context.Context, _ db.TenantTx, f DeliveryFailure) error {
	s.got = append(s.got, f)
	return nil
}

type exportFixture struct {
	d      *dbtest.DB
	p      *db.Pool
	org    ids.OrgID
	user   ids.UUID
	cred   ids.UUID
	feed   *fakeFeed
	svc    *Service
	clk    *clock.Fake
	sink   *sinkCalls
	recv   *receiver
	secret []byte
}

func newExportFixture(t *testing.T) *exportFixture {
	t.Helper()
	d := dbtest.New(t)
	f := &exportFixture{
		d: d, p: d.AppPool(t), org: ids.New[ids.Org](), user: ids.NewV7(), cred: ids.NewV7(), feed: &fakeFeed{},
		clk: clock.NewFake(time.Now()), sink: &sinkCalls{}, recv: newReceiver(t),
	}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	env := pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(f.p, kp), time.Minute, clock.System{}))
	roots := x509.NewCertPool()
	roots.AddCert(f.recv.srv.Certificate())
	f.svc, err = New(f.p, env, f.feed, Config{PublicURL: "https://pc.example.com", RootCAs: roots, ProductVersion: "test"}, f.clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.WithHealthSink(f.sink)
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'siem')", f.org)
	f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.user)
	f.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, f.cred, f.user, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
	return f
}

func (f *exportFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// destination stores an ACTIVE destination as Create and Activate would,
// with its cursor at from.
func (f *exportFixture) destination(t *testing.T, url string, internal bool, classes []string, from int64) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	secret, err := ndomain.NewSigningSecret()
	if err != nil {
		t.Fatal(err)
	}
	f.secret = secret
	ctx := context.Background()
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		blob, err := f.svc.envelope.Encrypt(ctx, f.svc.field(f.org, id, secretColumn), SecretPurpose, secret)
		if err != nil {
			return err
		}
		q := dbq.New(tx)
		if err := q.InsertSIEMDestination(ctx, dbq.InsertSIEMDestinationParams{
			OrgID: f.org, ID: id, Name: "siem-" + strconv.Itoa(int(from)) + "-" + id.String()[:8], Url: url, Internal: internal,
			DataClasses: classes, Secret: blob, CreatedBy: f.user.String(),
		}); err != nil {
			return err
		}
		if _, err := q.ActivateSIEMDestination(ctx, dbq.ActivateSIEMDestinationParams{
			ActivatedBy: &f.user, ActivatedCredential: &f.cred, OrgID: f.org, ID: id,
		}); err != nil {
			return err
		}
		return q.InsertSIEMCursor(ctx, f.org, id, from)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *exportFixture) state(t *testing.T, id ids.UUID) Destination {
	t.Helper()
	var d Destination
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		d, err = get(ctx, dbq.New(tx), f.org, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return d
}

// due makes the destination's open batch due now.
func (f *exportFixture) due(t *testing.T, id ids.UUID) {
	t.Helper()
	f.d.AdminExec(t, "UPDATE pc.siem_batches SET next_attempt_at = now() - interval '1 second' WHERE destination_id = $1 AND state <> 'DELIVERED'", id)
}

func ev(seq int64, kind string) ocsf.Event {
	return ocsf.Event{
		Seq: seq, ID: ids.NewV7(), Kind: kind, OccurredAt: time.Unix(1_760_000_000+seq, 0), ActorType: "agent", ActorID: "a1",
		Attrs: map[string]string{ocsf.AttrSeverity: "HIGH", ocsf.AttrTitle: "t" + strconv.FormatInt(seq, 10)},
	}
}

type sentBatch struct {
	Type string `json:"type"`
	Data struct {
		Batch   string `json:"batch"`
		FromSeq int64  `json:"from_seq"`
		ToSeq   int64  `json:"to_seq"`
		Events  []struct {
			ClassUID int `json:"class_uid"`
			Metadata struct {
				UID      string `json:"uid"`
				Sequence int64  `json:"sequence"`
			} `json:"metadata"`
		} `json:"events"`
	} `json:"data"`
}

// TestHR260_ExportIsCursorBasedSignedAndStable: a batch carries only the
// destination's data classes with stable ids, is signed with Standard
// Webhooks, is re-sent identically after a failure (same webhook-id, same
// body), and the cursor moves only after a 2xx; the first 2xx confirms
// delivery; ten failures in a row make the destination FAILING and tell
// the health sink once.
func TestHR260_ExportIsCursorBasedSignedAndStable(t *testing.T) {
	f := newExportFixture(t)
	ctx := context.Background()
	f.feed.events = []ocsf.Event{
		ev(1, "receipt.decision"), ev(2, "reflex.alert"), ev(3, "audit.grant.revoked"), ev(4, "reflex.alert"), ev(5, "reflex.live"),
	}
	id := f.destination(t, f.recv.srv.URL+"/ingest", true, []string{"alerts"}, 0)
	if d := f.state(t, id); d.Health != HealthNotConfirmed || d.ConfirmedAt != nil {
		t.Fatalf("before delivery: %+v", d)
	}

	// The receiver fails: the batch stays open and the cursor does not move.
	f.recv.set(http.StatusInternalServerError)
	step, err := f.svc.ExportOnce(ctx, f.org, id)
	if err != nil || !step.Sent || step.Delivered || step.Code != "http_500" {
		t.Fatalf("first attempt: %+v %v", step, err)
	}
	if d := f.state(t, id); d.CursorSeq != 0 || d.ConsecutiveFailures != 1 || d.Health != HealthDegraded {
		t.Fatalf("after a failure: %+v", d)
	}
	// Not due yet: nothing is sent.
	if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || step.Sent {
		t.Fatalf("an undue batch was sent: %+v %v", step, err)
	}

	f.recv.set(http.StatusNoContent)
	f.due(t, id)
	step, err = f.svc.ExportOnce(ctx, f.org, id)
	if err != nil || !step.Delivered {
		t.Fatalf("retry: %+v %v", step, err)
	}
	reqs := f.recv.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d", len(reqs))
	}
	if !bytes.Equal(reqs[0].body, reqs[1].body) || reqs[0].header.Get("webhook-id") != reqs[1].header.Get("webhook-id") {
		t.Fatal("the retry is not the same batch")
	}
	r := reqs[1]
	ts, _ := strconv.ParseInt(r.header.Get("webhook-timestamp"), 10, 64)
	if want := ndomain.Sign(f.secret, r.header.Get("webhook-id"), ts, r.body); r.header.Get("webhook-signature") != want {
		t.Fatalf("signature %q, want %q", r.header.Get("webhook-signature"), want)
	}
	var b sentBatch
	if err := json.Unmarshal(r.body, &b); err != nil {
		t.Fatal(err)
	}
	if b.Type != ocsf.BatchType || b.Data.Batch != r.header.Get("webhook-id") || b.Data.FromSeq != 0 || b.Data.ToSeq != 5 || len(b.Data.Events) != 2 ||
		b.Data.Events[0].Metadata.UID != f.feed.events[1].ID.String() || b.Data.Events[1].Metadata.Sequence != 4 || b.Data.Events[0].ClassUID != 2004 {
		t.Fatalf("batch = %+v", b)
	}
	d := f.state(t, id)
	if d.CursorSeq != 5 || d.ConfirmedAt == nil || d.Health != HealthHealthy || d.LastDeliveredSeq != 5 || d.DeliveredBatches != 1 || d.Retries != 1 {
		t.Fatalf("after delivery: %+v", d)
	}

	// Entries none of the destination's classes select move the cursor
	// without a request.
	f.feed.events = append(f.feed.events, ev(6, "receipt.decision"), ev(7, "coverage.snapshot"))
	step, err = f.svc.ExportOnce(ctx, f.org, id)
	if err != nil || step.Sent || f.state(t, id).CursorSeq != 7 || len(f.recv.requests()) != 2 {
		t.Fatalf("unselected range: %+v %v", step, err)
	}

	// Ten failures in a row: FAILING, the sink is told once, and the
	// batch is still retried after the schedule (the cursor never skips).
	f.feed.events = append(f.feed.events, ev(8, "reflex.alert"))
	f.recv.set(http.StatusServiceUnavailable)
	for i := range 12 {
		if i > 0 {
			f.due(t, id)
		}
		if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || !step.Sent || step.Delivered {
			t.Fatalf("attempt %d: %+v %v", i, step, err)
		}
	}
	d = f.state(t, id)
	if d.Health != HealthFailing || d.CursorSeq != 7 || d.FailedBatches != 1 || len(f.sink.got) != 1 || f.sink.got[0].Destination != id {
		t.Fatalf("failing: %+v, sink %+v", d, f.sink.got)
	}
	if d.WaitingSince == nil {
		t.Fatal("a held destination does not say since when events wait")
	}
	// RetryDestination's storage step: a fresh schedule, due now (D46).
	f.recv.set(http.StatusOK)
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).RetrySIEMBatchNow(ctx, f.org, id)
		if err == nil && n != 1 {
			t.Errorf("retried %d batches", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || !step.Delivered {
		t.Fatalf("recovery: %+v %v", step, err)
	}
	if d := f.state(t, id); d.CursorSeq != 8 || d.Health != HealthHealthy || d.WaitingSince != nil || len(f.sink.got) != 1 {
		t.Fatalf("after recovery: %+v", d)
	}

	// A paused destination sends nothing.
	f.feed.events = append(f.feed.events, ev(9, "reflex.alert"))
	f.exec(t, "UPDATE pc.siem_destinations SET state = 'PAUSED' WHERE id = $1", id)
	if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || step.Sent {
		t.Fatalf("paused: %+v %v", step, err)
	}
}

// TestT114_PublicDestinationNeverReachesLoopback: a destination that is not
// marked internal never reaches a private or loopback address, even when
// its stored URL names one: the egress client refuses at dial time.
func TestT114_PublicDestinationNeverReachesLoopback(t *testing.T) {
	f := newExportFixture(t)
	f.feed.events = []ocsf.Event{ev(1, "reflex.alert")}
	id := f.destination(t, f.recv.srv.URL+"/ingest", false, []string{"alerts"}, 0)
	step, err := f.svc.ExportOnce(context.Background(), f.org, id)
	if err != nil || step.Delivered || step.Code != "destination_denied" {
		t.Fatalf("step = %+v, %v", step, err)
	}
	if n := len(f.recv.requests()); n != 0 {
		t.Fatalf("the loopback receiver got %d requests", n)
	}
}

// TestHR259_RotationSignsWithBothSecrets: during the overlap a batch
// carries a signature with the new and the old secret.
func TestHR259_RotationSignsWithBothSecrets(t *testing.T) {
	f := newExportFixture(t)
	f.feed.events = []ocsf.Event{ev(1, "reflex.alert")}
	id := f.destination(t, f.recv.srv.URL+"/ingest", true, []string{"alerts"}, 0)
	old := f.secret
	ctx := context.Background()
	// RotateSecret's storage step, without the caller check.
	next, err := ndomain.NewSigningSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LoadSIEMSecrets(ctx, f.org, id)
		if err != nil {
			return err
		}
		cur, err := f.svc.envelope.Decrypt(ctx, f.svc.field(f.org, id, secretColumn), SecretPurpose, row.Secret)
		if err != nil {
			return err
		}
		prev, err := f.svc.envelope.Encrypt(ctx, f.svc.field(f.org, id, prevSecretColumn), SecretPurpose, cur)
		if err != nil {
			return err
		}
		blob, err := f.svc.envelope.Encrypt(ctx, f.svc.field(f.org, id, secretColumn), SecretPurpose, next)
		if err != nil {
			return err
		}
		_, err = q.RotateSIEMSecret(ctx, dbq.RotateSIEMSecretParams{Secret: blob, PrevSecret: prev, OverlapSeconds: 86400, OrgID: f.org, ID: id})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || !step.Delivered {
		t.Fatalf("%+v %v", step, err)
	}
	r := f.recv.requests()[0]
	ts, _ := strconv.ParseInt(r.header.Get("webhook-timestamp"), 10, 64)
	want := ndomain.Signatures([][]byte{next, old}, r.header.Get("webhook-id"), ts, r.body)
	if got := r.header.Get("webhook-signature"); got != want {
		t.Fatalf("signature %q, want %q", got, want)
	}
}

// TestHR260_AnOversizedEntryIsRecordedNotSilentlySkipped: an entry too
// large for any batch moves export on but is listed on its batch and
// raised as an owned failure naming it (D64 L5).
func TestHR260_AnOversizedEntryIsRecordedNotSilentlySkipped(t *testing.T) {
	f := newExportFixture(t)
	f.svc.WithFailures(&failures.Sink{})
	huge := ev(2, "reflex.alert")
	huge.Attrs["blob"] = strings.Repeat("x", ocsf.MaxBatchBytes)
	f.feed.events = []ocsf.Event{ev(1, "reflex.alert"), huge, ev(3, "reflex.alert")}
	id := f.destination(t, f.recv.srv.URL+"/ingest", true, []string{"alerts"}, 0)
	if st, err := f.svc.ExportOnce(context.Background(), f.org, id); err != nil || !st.Delivered {
		t.Fatalf("export: %+v %v", st, err)
	}
	var b sentBatch
	if err := json.Unmarshal(f.recv.requests()[0].body, &b); err != nil || len(b.Data.Events) != 2 || b.Data.ToSeq != 3 {
		t.Fatalf("batch = %+v (%v)", b, err)
	}
	var skipped int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.siem_batches WHERE $1 = ANY (skipped_uids)", huge.ID).Scan(&skipped)
	}); err != nil || skipped != 1 {
		t.Fatalf("batches listing the skipped entry = %d (%v)", skipped, err)
	}
	var failed int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.operational_failures WHERE kind = 'siem.event_skipped' AND summary LIKE '%' || $1 || '%'",
			huge.ID.String()).Scan(&failed)
	}); err != nil || failed != 1 {
		t.Fatalf("skipped failures = %d (%v)", failed, err)
	}
}
