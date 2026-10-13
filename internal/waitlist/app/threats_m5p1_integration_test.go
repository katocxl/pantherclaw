// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/keystore"
	notifapp "github.com/katocxl/pantherclaw/internal/notifications/app"
	notifdomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// p1tRefusingMailer refuses every recipient for good, as a relay
// answering 550 would.
type p1tRefusingMailer struct{}

func (p1tRefusingMailer) Send(context.Context, notifapp.Mail) error {
	return fmt.Errorf("550 mailbox unavailable: %w", notifapp.ErrPermanent)
}

// p1tNotifications is the real notification service for f's org, with a
// webhook channel for approval notices at srv (an operator-allowed
// loopback address) and a mail relay that refuses everything.
func p1tNotifications(t *testing.T, f *rfx, srv *httptest.Server) *notifapp.Service {
	t.Helper()
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	jc, err := jobs.NewClient(f.p, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	svc, err := notifapp.New(f.p, jc, pccrypto.NewEnvelope(keystore.NewDEKStore(f.p, kp)),
		notifapp.Config{PublicURL: "https://pc.example.test", AllowedPrivateRanges: local}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	svc.SetHTTPClient(httpx.NewEgressClient(httpx.EgressConfig{AllowedPrefixes: local, RootCAs: roots, Timeout: 5 * time.Second}))
	svc.SetMailer(p1tRefusingMailer{})
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		_, err := svc.CreateChannelTx(ctx, tx, notifapp.NewChannel{
			Org: f.org, Name: "approvals", Kind: notifdomain.KindWebhook, EventTypes: []string{"approval.*"},
			URL: srv.URL + "/pc", CreatedBy: "test",
		})
		return err
	})
	return svc
}

// TestT054_AFailedOrAcknowledgedNoticeDecidesNothing: T-054, HR-039 — a
// hold's approval notice goes out through the real notification service:
// the webhook receiver acknowledges it with a body that says "approve", and
// the relay refuses the approver's email for good. The entry is then
// DELIVERY_FAILING and still OPEN, its request still PENDING, no response
// is recorded and the transaction's decision is unchanged.
// TestHR039_AFailedDeliveryMarksTheEntryAndDecidesNothing proves the
// marking with a fake notifier.
func TestT054_AFailedOrAcknowledgedNoticeDecidesNothing(t *testing.T) {
	var acks atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		acks.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision":"approve","approved":true}`)
	}))
	t.Cleanup(srv.Close)
	f := newRFx(t)
	approver := f.person("approver", "TEAM")
	f.d.AdminExec(t, "UPDATE pc.users SET email = 'approver@example.test' WHERE id = $1", approver)
	svc := p1tNotifications(t, f, srv)
	f.router = &waitlist.Router{Pool: f.p, Notify: svc}
	var before string
	f.d.AdminQueryRow(t, "SELECT decision FROM pc.transactions WHERE id = $1", []any{f.txn}, &before)

	entry, request := f.hold()
	f.route()
	var pending []ids.UUID
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT id FROM pc.deliveries WHERE state = 'PENDING'")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id ids.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			pending = append(pending, id)
		}
		return rows.Err()
	})
	if len(pending) != 2 {
		t.Fatalf("%d pending deliveries, want the approver's email and the webhook", len(pending))
	}
	for _, id := range pending {
		_ = svc.Deliver(context.Background(), f.org, id)
	}
	var delivered, failed int
	f.d.AdminQueryRow(t, `SELECT count(*) FILTER (WHERE state = 'DELIVERED' AND kind = 'webhook'),
		count(*) FILTER (WHERE state = 'FAILED' AND kind = 'email') FROM pc.deliveries WHERE org_id = $1`, []any{f.org}, &delivered, &failed)
	if acks.Load() != 1 || delivered != 1 || failed != 1 {
		t.Fatalf("acknowledgements %d, webhook delivered %d, email failed %d", acks.Load(), delivered, failed)
	}

	f.route()
	var health, state, requestState, after string
	var responses int
	f.d.AdminQueryRow(t, "SELECT routing_health, state FROM pc.waitlist_entries WHERE id = $1", []any{entry}, &health, &state)
	f.d.AdminQueryRow(t, "SELECT state FROM pc.approval_requests WHERE id = $1", []any{request}, &requestState)
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.approval_responses WHERE request_id = $1", []any{request}, &responses)
	f.d.AdminQueryRow(t, "SELECT decision FROM pc.transactions WHERE id = $1", []any{f.txn}, &after)
	if health != "DELIVERY_FAILING" || state != "OPEN" || requestState != "PENDING" || responses != 0 || after != before {
		t.Fatalf("entry %s %s, request %s, %d responses, decision %s -> %s", health, state, requestState, responses, before, after)
	}
}
