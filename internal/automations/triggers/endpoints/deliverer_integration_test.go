// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package endpoints

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/inbound"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// receiver is a TLS webhook receiver that verifies Standard Webhooks
// signatures with the secrets it is given.
type receiver struct {
	srv     *httptest.Server
	mu      sync.Mutex
	secrets [][]byte
	status  int
	got     []http.Header
	bodies  []string
	badSigs int
	// hold, when set, keeps each request open until it is closed; arrived
	// is told of each held request.
	hold    chan struct{}
	arrived chan struct{}
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{status: http.StatusOK}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		hold, arrived := r.hold, r.arrived
		r.mu.Unlock()
		if hold != nil {
			arrived <- struct{}{}
			<-hold
		}
		h, err := inbound.ReadHeaders(req.Header)
		r.mu.Lock()
		defer r.mu.Unlock()
		if err != nil || inbound.VerifySignature(r.secrets, h, body) != nil {
			r.badSigs++
		}
		r.got = append(r.got, req.Header.Clone())
		r.bodies = append(r.bodies, string(body))
		w.WriteHeader(r.status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

type fixture struct {
	*triggerstest.Fixture
	svc  *Service
	clk  *clock.Fake
	recv *receiver
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{Fixture: triggerstest.New(t), clk: clock.NewFake(time.Now()), recv: newReceiver(t)}
	roots := x509.NewCertPool()
	roots.AddCert(f.recv.srv.Certificate())
	trig := triggers.New(triggers.Deps{Pool: f.Pool, Editions: triggerstest.Team})
	var err error
	f.svc, err = New(f.Pool, f.Envelope, trig, triggerstest.Team, Config{PublicURL: "https://pc.example.com", RootCAs: roots}, f.clk, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) author() context.Context { return f.As(td.KindUser, td.RoleAutomationAuthor) }

func (f *fixture) stepUp() *stepup.StepUp { return &stepup.StepUp{Credential: f.Cred, At: time.Now()} }

func decodeSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "whsec_"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// activeDestination creates and activates a destination for the receiver.
func (f *fixture) activeDestination(t *testing.T, name string, purposes ...string) (Destination, []byte) {
	t.Helper()
	c, err := f.svc.CreateDestination(f.author(), NewDestination{Name: name, URL: f.recv.srv.URL + "/hook", Internal: true, Purposes: purposes})
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.svc.ActivateDestination(f.author(), c.Destination.ID, f.stepUp())
	if err != nil {
		t.Fatal(err)
	}
	secret := decodeSecret(t, c.Secret)
	f.recv.mu.Lock()
	f.recv.secrets = append(f.recv.secrets, secret)
	f.recv.mu.Unlock()
	return d, secret
}

func (f *fixture) deliver(t *testing.T, d autodomain.Delivery) (ids.UUID, error) {
	t.Helper()
	var id ids.UUID
	err := f.Pool.InTenantTx(context.Background(), f.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = f.svc.Deliverer().Deliver(ctx, tx.Pgx(), d)
		return err
	})
	return id, err
}

func (f *fixture) status(t *testing.T, id ids.UUID) autodomain.DeliveryStatus {
	t.Helper()
	var st autodomain.DeliveryStatus
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		st, err = f.svc.Deliverer().Status(ctx, tx.Pgx(), id)
		return err
	})
	return st
}

// TestDeliverer_SignsDeliversAndConfirms: a delivery to an ACTIVE
// destination is posted with a valid Standard Webhooks signature and
// becomes DELIVERED on a 2xx (the DELIVERY_CONFIRMED evidence); its body is
// then dropped. A destination of another purpose, an inactive one or a
// non-object body is refused at Deliver.
func TestDeliverer_SignsDeliversAndConfirms(t *testing.T) {
	f := newFixture(t)
	d, _ := f.activeDestination(t, "launches", "LAUNCH")
	exec := ids.NewV7()
	id, err := f.deliver(t, autodomain.Delivery{Org: f.Org, Destination: d.ID, Execution: exec, Kind: autodomain.DeliveryLaunch, Body: []byte(`{"task":"T-1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if st := f.status(t, id); st.State != autodomain.DeliveryPending {
		t.Fatalf("before sending: %+v", st)
	}
	n, err := f.svc.SendDue(context.Background(), f.Org)
	if err != nil || n != 1 {
		t.Fatalf("SendDue: %d %v", n, err)
	}
	st := f.status(t, id)
	if st.State != autodomain.DeliveryDelivered || st.LastStatus != 200 || st.Attempts != 1 || st.DeliveredAt.IsZero() {
		t.Fatalf("after sending: %+v", st)
	}
	if f.recv.badSigs != 0 || len(f.recv.bodies) != 1 || !strings.Contains(f.recv.bodies[0], `"T-1"`) {
		t.Fatalf("receiver: %d bad signatures, bodies %q", f.recv.badSigs, f.recv.bodies)
	}
	if !strings.HasPrefix(f.recv.got[0].Get(inbound.HeaderID), "msg_") {
		t.Fatalf("webhook-id %q", f.recv.got[0].Get(inbound.HeaderID))
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_deliveries WHERE org_id = $1 AND body IS NOT NULL"); n != 0 {
		t.Fatal("a delivered body was kept")
	}
	// Sending again sends nothing.
	if n, _ := f.svc.SendDue(context.Background(), f.Org); n != 0 {
		t.Fatalf("resent %d", n)
	}
	for name, del := range map[string]autodomain.Delivery{
		"other purpose": {Org: f.Org, Destination: d.ID, Execution: exec, Kind: autodomain.DeliveryDigest, Body: []byte(`{}`)},
		"array body":    {Org: f.Org, Destination: d.ID, Execution: exec, Kind: autodomain.DeliveryLaunch, Body: []byte(`[1]`)},
		"broken body":   {Org: f.Org, Destination: d.ID, Execution: exec, Kind: autodomain.DeliveryLaunch, Body: []byte(`{"a":`)},
		"huge body":     {Org: f.Org, Destination: d.ID, Execution: exec, Kind: autodomain.DeliveryLaunch, Body: []byte(`{"a":"` + strings.Repeat("x", MaxDeliveryBody) + `"}`)},
		"no execution":  {Org: f.Org, Destination: d.ID, Kind: autodomain.DeliveryLaunch, Body: []byte(`{}`)},
		"unknown":       {Org: f.Org, Destination: ids.NewV7(), Execution: exec, Kind: autodomain.DeliveryLaunch, Body: []byte(`{}`)},
	} {
		if _, err := f.deliver(t, del); err == nil {
			t.Errorf("%s: delivered", name)
		}
	}
	// Readers without automation.endpoints.manage see scheme and host only
	// (D87 P4): a webhook URL's path often carries its credential.
	if got, err := f.svc.GetDestination(f.As(td.KindUser, td.RoleAutomationOperator), d.ID); err != nil || got.URL != RedactURL(d.URL) || strings.Contains(got.URL, "/hook") {
		t.Fatalf("reader: %q %v", got.URL, err)
	}
	if got, err := f.svc.GetDestination(f.author(), d.ID); err != nil || got.URL != d.URL {
		t.Fatalf("manager: %q %v", got.URL, err)
	}
	// A PENDING destination receives nothing.
	c, err := f.svc.CreateDestination(f.author(), NewDestination{Name: "pending", URL: f.recv.srv.URL, Internal: true, Purposes: []string{"NOTICE"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.deliver(t, autodomain.Delivery{Org: f.Org, Destination: c.Destination.ID, Execution: exec, Kind: autodomain.DeliveryNotice, Body: []byte(`{}`)}); !errors.Is(err, ErrDestinationInactive) {
		t.Fatalf("pending destination: %v", err)
	}
}

// TestDeliverer_RetriesWithBackoffThenFails: a failing receiver is retried
// with bounded backoff, at most eight attempts, then FAILED; a paused
// destination keeps deliveries waiting without spending attempts.
func TestDeliverer_RetriesWithBackoffThenFails(t *testing.T) {
	f := newFixture(t)
	d, _ := f.activeDestination(t, "notices", "NOTICE")
	f.recv.status = http.StatusServiceUnavailable
	id, err := f.deliver(t, autodomain.Delivery{Org: f.Org, Destination: d.ID, Execution: ids.NewV7(), Kind: autodomain.DeliveryNotice, Body: []byte(`{"n":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	due := func() {
		f.Exec(t, "UPDATE pc.automation_deliveries SET next_attempt_at = now() WHERE org_id = $1 AND state = 'PENDING'", f.Org)
		if _, err := f.svc.SendDue(context.Background(), f.Org); err != nil {
			t.Fatal(err)
		}
	}
	due()
	st := f.status(t, id)
	if st.State != autodomain.DeliveryPending || st.Attempts != 1 || st.LastStatus != 503 || st.LastError != "http_503" {
		t.Fatalf("first failure: %+v", st)
	}
	// Paused: no attempt is spent.
	if _, err := f.svc.SetDestinationState(f.author(), d.ID, StatePaused); err != nil {
		t.Fatal(err)
	}
	due()
	if st := f.status(t, id); st.Attempts != 1 || len(f.recv.bodies) != 1 {
		t.Fatalf("paused destination was sent to: %+v", st)
	}
	if _, err := f.svc.SetDestinationState(f.author(), d.ID, StateActive); err != nil {
		t.Fatal(err)
	}
	for range MaxAttempts {
		due()
	}
	st = f.status(t, id)
	if st.State != autodomain.DeliveryFailed || st.Attempts != MaxAttempts || len(f.recv.bodies) != MaxAttempts {
		t.Fatalf("after %d attempts: %+v (%d posts)", MaxAttempts, st, len(f.recv.bodies))
	}
	if f.recv.badSigs != 0 {
		t.Fatal("bad signature")
	}
	if Backoff(1) != 30*time.Second || Backoff(2) != time.Minute || Backoff(20) != time.Hour {
		t.Fatalf("backoff %v %v %v", Backoff(1), Backoff(2), Backoff(20))
	}
}

// TestDeliverer_RotationOverlapSignsWithBoth: during the 24 h overlap a
// delivery carries signatures for the new and the previous secret.
func TestDeliverer_RotationOverlapSignsWithBoth(t *testing.T) {
	f := newFixture(t)
	d, old := f.activeDestination(t, "digests", "DIGEST")
	if _, err := f.svc.RotateDestinationSecret(f.author(), d.ID, nil); !stepup.Is(err) {
		t.Fatalf("rotation without a step-up: %v", err)
	}
	fresh, err := f.svc.RotateDestinationSecret(f.author(), d.ID, f.stepUp())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RotateDestinationSecret(f.author(), d.ID, f.stepUp()); !errors.Is(err, ErrRotating) {
		t.Fatalf("second rotation during the overlap: %v", err)
	}
	// The receiver now knows only the new secret, then only the old one:
	// both verify, because both signatures are sent.
	for _, secret := range [][]byte{decodeSecret(t, fresh), old} {
		f.recv.mu.Lock()
		f.recv.secrets = [][]byte{secret}
		f.recv.mu.Unlock()
		if _, err := f.deliver(t, autodomain.Delivery{Org: f.Org, Destination: d.ID, Execution: ids.NewV7(), Kind: autodomain.DeliveryDigest, Body: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.SendDue(context.Background(), f.Org); err != nil {
			t.Fatal(err)
		}
	}
	if f.recv.badSigs != 0 || len(f.recv.bodies) != 2 {
		t.Fatalf("%d bad signatures of %d", f.recv.badSigs, len(f.recv.bodies))
	}
	if sigs := strings.Fields(f.recv.got[0].Get(inbound.HeaderSignature)); len(sigs) != 2 {
		t.Fatalf("signatures during the overlap: %v", sigs)
	}
}

// TestDeliverer_CancelStopsOnlyPendingDeliveries (D89): a pending
// delivery is cancelled (FAILED, "cancelled", body dropped) and never
// sent; a delivered one stays as it is.
func TestDeliverer_CancelStopsOnlyPendingDeliveries(t *testing.T) {
	f := newFixture(t)
	d, _ := f.activeDestination(t, "cancel", "NOTICE")
	pending, err := f.deliver(t, autodomain.Delivery{Org: f.Org, Destination: d.ID, Execution: ids.NewV7(), Kind: autodomain.DeliveryNotice, Body: []byte(`{"n":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	cancel := func(id ids.UUID) error {
		return f.Pool.InTenantTx(context.Background(), f.Org, func(ctx context.Context, tx db.TenantTx) error {
			return f.svc.Deliverer().Cancel(ctx, tx.Pgx(), id)
		})
	}
	if err := cancel(pending); err != nil {
		t.Fatal(err)
	}
	st := f.status(t, pending)
	if st.State != autodomain.DeliveryFailed || st.LastError != "cancelled" {
		t.Fatalf("cancelled: %+v", st)
	}
	if n, _ := f.svc.SendDue(context.Background(), f.Org); n != 0 || len(f.recv.bodies) != 0 {
		t.Fatal("a cancelled delivery was sent")
	}
	if err := cancel(pending); !errors.Is(err, ErrDeliveryNotPending) {
		t.Fatalf("second cancel: %v", err)
	}
	sent, err := f.deliver(t, autodomain.Delivery{Org: f.Org, Destination: d.ID, Execution: ids.NewV7(), Kind: autodomain.DeliveryNotice, Body: []byte(`{"n":2}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SendDue(context.Background(), f.Org); err != nil {
		t.Fatal(err)
	}
	if err := cancel(sent); !errors.Is(err, ErrDeliveryMayHaveBeenSent) || f.status(t, sent).State != autodomain.DeliveryDelivered {
		t.Fatalf("a delivered delivery: %v", err)
	}
	if err := cancel(ids.NewV7()); !errors.Is(err, ErrDeliveryNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}

// TestDeliverer_ALeasedSendIsNeitherCancelledNorSentTwice (D97 N1, D87
// L11): the lease counts the attempt before the POST, so Cancel during the
// send is refused (the delivery may have been sent) and a second sender
// skips the leased row; the first sender then records the outcome.
func TestDeliverer_ALeasedSendIsNeitherCancelledNorSentTwice(t *testing.T) {
	f := newFixture(t)
	d, _ := f.activeDestination(t, "leased", "NOTICE")
	id, err := f.deliver(t, autodomain.Delivery{Org: f.Org, Destination: d.ID, Execution: ids.NewV7(), Kind: autodomain.DeliveryNotice, Body: []byte(`{"n":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	f.recv.mu.Lock()
	f.recv.hold, f.recv.arrived = hold, make(chan struct{}, 4)
	f.recv.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := f.svc.SendDue(context.Background(), f.Org)
		done <- err
	}()
	<-f.recv.arrived
	released := false
	t.Cleanup(func() {
		if !released {
			close(hold)
		}
	})

	if st := f.status(t, id); st.State != autodomain.DeliveryPending || st.Attempts != 1 {
		t.Fatalf("leased: %+v", st)
	}
	err = f.Pool.InTenantTx(context.Background(), f.Org, func(ctx context.Context, tx db.TenantTx) error {
		return f.svc.Deliverer().Cancel(ctx, tx.Pgx(), id)
	})
	if !errors.Is(err, ErrDeliveryMayHaveBeenSent) {
		t.Fatalf("cancel during a leased send: %v", err)
	}
	if n, err := f.svc.SendDue(context.Background(), f.Org); err != nil || n != 0 {
		t.Fatalf("second sender: %d %v", n, err)
	}
	f.recv.mu.Lock()
	posts := len(f.recv.bodies)
	f.recv.mu.Unlock()
	if posts != 0 {
		t.Fatal("a leased delivery was posted twice")
	}

	close(hold)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if st := f.status(t, id); st.State != autodomain.DeliveryDelivered || st.Attempts != 1 {
		t.Fatalf("after the send: %+v", st)
	}
	if len(f.recv.bodies) != 1 {
		t.Fatalf("posts: %d", len(f.recv.bodies))
	}
}
