// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package siem

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strconv"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeWebhookKeys is one org's webhooks key, as the keystore keeps it.
type fakeWebhookKeys struct {
	org     ids.OrgID
	priv    ed25519.PrivateKey
	ensured int
	fail    bool
}

func (k *fakeWebhookKeys) SignWebhook(_ context.Context, org ids.OrgID, content []byte) ([]byte, error) {
	if k.fail || org != k.org {
		return nil, errors.New("no webhooks key for this org")
	}
	return ed25519.Sign(k.priv, content), nil
}

func (k *fakeWebhookKeys) EnsureWebhookKey(_ context.Context, org ids.OrgID) (string, error) {
	if org != k.org {
		return "", errors.New("wrong org")
	}
	k.ensured++
	return "webhooks-test", nil
}

// TestHR510_SIEMOptInSendsV1aNextToHMAC: a destination sends HMAC only
// until a person opts it in (audited, Business); then every batch carries
// the same `v1,` signature and a `v1a,` one by the org's key, and a batch
// whose Ed25519 signature cannot be made is not sent (G0 M20 D251).
// Covers: PN-018
func TestHR510_SIEMOptInSendsV1aNextToHMAC(t *testing.T) {
	f := newExportFixture(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := &fakeWebhookKeys{org: f.org, priv: priv}
	ed := &edition{e: billing.Business}
	f.svc.WithEditions(ed).WithWebhookKeys(keys)
	f.feed.events = []ocsf.Event{ev(1, "reflex.alert")}
	id := f.destination(t, f.recv.srv.URL+"/ingest", true, []string{"alerts"}, 0)
	ctx := context.Background()

	check := func(r request, ed25519Want bool) {
		t.Helper()
		ts, _ := strconv.ParseInt(r.header.Get("webhook-timestamp"), 10, 64)
		msgID := r.header.Get("webhook-id")
		hmacOnly := ndomain.Signatures([][]byte{f.secret}, msgID, ts, r.body)
		got := r.header.Get("webhook-signature")
		if !ed25519Want {
			if got != hmacOnly {
				t.Fatalf("signature %q, want HMAC only %q", got, hmacOnly)
			}
			return
		}
		v1, v1a, ok := strings.Cut(got, " ")
		if !ok || v1 != hmacOnly || !ndomain.VerifyV1a(pub, v1a, msgID, ts, r.body) {
			t.Fatalf("signature %q: want %q and a v1a, by the org's key", got, hmacOnly)
		}
	}

	if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || !step.Delivered {
		t.Fatalf("%+v %v", step, err)
	}
	check(f.recv.requests()[0], false)
	if d := f.state(t, id); d.SignatureScheme != string(ndomain.SchemeHMAC) {
		t.Fatalf("default scheme %q", d.SignatureScheme)
	}

	admin := f.as(td.KindUser, td.RoleSecurityAdmin)
	if _, _, err := f.svc.SetSignatureScheme(admin, id, "ed25519"); !errors.Is(err, ErrInvalidScheme) {
		t.Fatalf("unknown scheme: %v", err)
	}
	if _, _, err := f.svc.SetSignatureScheme(f.as(td.KindUser, td.RoleAuditor), id, "hmac+ed25519"); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("auditor: %v", err)
	}
	ed.e = billing.Team
	if _, _, err := f.svc.SetSignatureScheme(admin, id, "hmac+ed25519"); !errors.Is(err, ErrEdition) {
		t.Fatalf("Team edition: %v", err)
	}
	ed.e = billing.Business
	if _, _, err := f.svc.SetSignatureScheme(admin, ids.NewV7(), "hmac+ed25519"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown destination: %v", err)
	}
	d, jwks, err := f.svc.SetSignatureScheme(admin, id, "hmac+ed25519")
	if err != nil || d.SignatureScheme != "hmac+ed25519" || keys.ensured == 0 {
		t.Fatalf("opt in: %+v %v (ensured %d)", d, err, keys.ensured)
	}
	if jwks != "https://pc.example.com"+ndomain.WebhookJWKSPath(f.org) {
		t.Fatalf("JWKS URL %s", jwks)
	}
	var n int
	f.d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.siem.destination_signature_scheme_set'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'scheme' = 'hmac+ed25519'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'previous' = 'hmac'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'kid' = 'webhooks-test'`, []any{f.org}, &n)
	if n != 1 {
		t.Fatalf("audit entries %d", n)
	}

	f.feed.events = append(f.feed.events, ev(2, "reflex.alert"))
	if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || !step.Delivered {
		t.Fatalf("%+v %v", step, err)
	}
	check(f.recv.requests()[1], true)

	// No Ed25519 signature, no batch: it waits and is retried.
	keys.fail = true
	f.feed.events = append(f.feed.events, ev(3, "reflex.alert"))
	if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || step.Delivered || step.Code != "signing_key_unavailable" {
		t.Fatalf("%+v %v", step, err)
	}
	if n := len(f.recv.requests()); n != 2 {
		t.Fatalf("%d requests: a batch went out without its v1a, signature", n)
	}

	// Back to HMAC only.
	keys.fail = false
	if d, _, err := f.svc.SetSignatureScheme(admin, id, "hmac"); err != nil || d.SignatureScheme != "hmac" {
		t.Fatalf("opt out: %+v %v", d, err)
	}
	f.due(t, id)
	if step, err := f.svc.ExportOnce(ctx, f.org, id); err != nil || !step.Delivered {
		t.Fatalf("%+v %v", step, err)
	}
	check(f.recv.requests()[2], false)
}
