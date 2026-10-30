// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strconv"
	"strings"
	"testing"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// webhookKeys is one org's webhooks key, as the keystore keeps it.
type webhookKeys struct {
	org  ids.OrgID
	priv ed25519.PrivateKey
}

func (k webhookKeys) SignWebhook(_ context.Context, org ids.OrgID, content []byte) ([]byte, error) {
	if org != k.org {
		return nil, errors.New("no webhooks key for this org")
	}
	return ed25519.Sign(k.priv, content), nil
}

func (k webhookKeys) EnsureWebhookKey(_ context.Context, org ids.OrgID) (string, error) {
	if org != k.org {
		return "", errors.New("wrong org")
	}
	return "webhooks-test", nil
}

// TestHR510_WebhookChannelOptInSendsV1aNextToHMAC: a webhook channel sends
// HMAC only until a notification.manage holder opts it in (audited); then
// a delivery carries the same verifiable `v1,` signature and a `v1a,` one
// by the org's key. Only webhook channels take a scheme (G0 M20 D251).
// Covers: PN-018
func TestHR510_WebhookChannelOptInSendsV1aNextToHMAC(t *testing.T) {
	r := newReceiver(t)
	e := webhookEnv(t, r)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	admin := e.as(td.KindUser, e.alice, td.RoleOrgAdmin)
	hook := e.channel(t, napp.NewChannel{Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: r.URL + "/pc"})
	logs := e.channel(t, napp.NewChannel{Name: "logs", Kind: domain.KindLog, EventTypes: []string{"security.*"}})

	// Without keys wired, opting in is refused; HMAC stays.
	if _, _, err := e.svc.SetChannelSignatureScheme(admin, hook.ID, "hmac+ed25519"); !errors.Is(err, napp.ErrSigningUnavailable) {
		t.Fatalf("no keys: %v", err)
	}
	e.svc.SetWebhookKeys(webhookKeys{org: e.org, priv: priv})
	if _, _, err := e.svc.SetChannelSignatureScheme(e.as(td.KindUser, e.carol, td.RoleViewer), hook.ID, "hmac+ed25519"); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("viewer: %v", err)
	}
	if _, _, err := e.svc.SetChannelSignatureScheme(admin, logs.ID, "hmac+ed25519"); !errors.Is(err, napp.ErrNotAWebhook) {
		t.Fatalf("log channel: %v", err)
	}
	if _, _, err := e.svc.SetChannelSignatureScheme(admin, ids.NewV7(), "hmac+ed25519"); !errors.Is(err, napp.ErrChannelNotFound) {
		t.Fatalf("unknown channel: %v", err)
	}
	if _, _, err := e.svc.SetChannelSignatureScheme(admin, hook.ID, "v1a"); !errors.Is(err, napp.ErrInvalidScheme) {
		t.Fatalf("bad scheme: %v", err)
	}

	send := func() *recorded {
		t.Helper()
		e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("alice@example.test")})
		if err := e.svc.Deliver(context.Background(), e.org, e.delivery(t)); err != nil {
			t.Fatal(err)
		}
		got := r.got()
		return got[len(got)-1]
	}
	q := send()
	if !verify(t, hook.Secret, q.header, q.body) || strings.Contains(q.header.Get("webhook-signature"), "v1a,") {
		t.Fatalf("default: %q", q.header.Get("webhook-signature"))
	}

	ch, jwks, err := e.svc.SetChannelSignatureScheme(admin, hook.ID, "hmac+ed25519")
	if err != nil || ch.SignatureScheme != domain.SchemeHMACEd25519 || jwks != "https://pc.example.test"+domain.WebhookJWKSPath(e.org) {
		t.Fatalf("opt in: %+v %s %v", ch, jwks, err)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.notification.channel_signature_scheme_set'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'scheme' = 'hmac+ed25519'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'previous' = 'hmac'`); n != 1 {
		t.Fatalf("audit entries %d", n)
	}
	q = send()
	ts, _ := strconv.ParseInt(q.header.Get("webhook-timestamp"), 10, 64)
	sigs := strings.Fields(q.header.Get("webhook-signature"))
	if !verify(t, hook.Secret, q.header, q.body) || len(sigs) != 2 ||
		!domain.VerifyV1a(pub, sigs[1], q.header.Get("webhook-id"), ts, q.body) {
		t.Fatalf("opted in: %q", q.header.Get("webhook-signature"))
	}
}
