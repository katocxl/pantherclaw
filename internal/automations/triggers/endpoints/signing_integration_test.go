// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package endpoints

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/inbound"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// orgKey is one org's webhooks key, as the keystore keeps it.
type orgKey struct {
	org  ids.OrgID
	priv ed25519.PrivateKey
}

func (k orgKey) SignWebhook(_ context.Context, org ids.OrgID, content []byte) ([]byte, error) {
	if org != k.org {
		return nil, errors.New("no webhooks key for this org")
	}
	return ed25519.Sign(k.priv, content), nil
}

func (k orgKey) EnsureWebhookKey(_ context.Context, org ids.OrgID) (string, error) {
	if org != k.org {
		return "", errors.New("wrong org")
	}
	return "webhooks-test", nil
}

// TestHR510_EndpointOptInSendsV1aNextToHMAC: an automation destination
// sends HMAC only until an automation.endpoints.manage holder opts it in
// (audited); then deliveries carry the same valid `v1,` signature, which
// the inbound verifier still accepts, and a `v1a,` one by the org's key
// (G0 M20 D251).
// Covers: PN-018
func TestHR510_EndpointOptInSendsV1aNextToHMAC(t *testing.T) {
	f := newFixture(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := f.activeDestination(t, "notices", "NOTICE")
	if d.SignatureScheme != string(ndomain.SchemeHMAC) {
		t.Fatalf("default scheme %q", d.SignatureScheme)
	}
	if _, _, err := f.svc.SetDestinationSignatureScheme(f.author(), d.ID, "hmac+ed25519"); !errors.Is(err, ErrSigningUnavailable) {
		t.Fatalf("no keys: %v", err)
	}
	f.svc.WithWebhookKeys(orgKey{org: f.Org, priv: priv})
	if _, _, err := f.svc.SetDestinationSignatureScheme(f.As(td.KindUser, td.RoleAutomationOperator), d.ID, "hmac+ed25519"); err == nil {
		t.Fatal("an operator opted a destination in")
	}
	if _, _, err := f.svc.SetDestinationSignatureScheme(f.author(), d.ID, "ed25519"); !errors.Is(err, ErrInvalidScheme) {
		t.Fatalf("bad scheme: %v", err)
	}
	send := func() sent {
		t.Helper()
		if _, err := f.deliver(t, autodomain.Delivery{Org: f.Org, Destination: d.ID, Execution: f.execution(t), Kind: autodomain.DeliveryNotice, Body: []byte(`{"n":1}`)}); err != nil {
			t.Fatal(err)
		}
		if n, err := f.svc.SendDue(context.Background(), f.Org); err != nil || n != 1 {
			t.Fatalf("SendDue: %d %v", n, err)
		}
		f.recv.mu.Lock()
		defer f.recv.mu.Unlock()
		return sent{h: f.recv.got[len(f.recv.got)-1].Clone(), body: f.recv.bodies[len(f.recv.bodies)-1]}
	}
	if r := send(); strings.Contains(r.h.Get(inbound.HeaderSignature), "v1a,") {
		t.Fatalf("default sent %q", r.h.Get(inbound.HeaderSignature))
	}
	got, jwks, err := f.svc.SetDestinationSignatureScheme(f.author(), d.ID, "hmac+ed25519")
	if err != nil || got.SignatureScheme != "hmac+ed25519" || jwks != "https://pc.example.com"+ndomain.WebhookJWKSPath(f.Org) {
		t.Fatalf("opt in: %+v %s %v", got, jwks, err)
	}
	if n := f.Count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.automation.destination_signature_scheme_set'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'scheme' = 'hmac+ed25519'`); n != 1 {
		t.Fatalf("audit entries %d", n)
	}
	r := send()
	ts, _ := strconv.ParseInt(r.h.Get(inbound.HeaderTimestamp), 10, 64)
	sigs := strings.Fields(r.h.Get(inbound.HeaderSignature))
	if len(sigs) != 2 || !strings.HasPrefix(sigs[0], "v1,") || !ndomain.VerifyV1a(pub, sigs[1], r.h.Get(inbound.HeaderID), ts, []byte(r.body)) {
		t.Fatalf("opted in: %q", r.h.Get(inbound.HeaderSignature))
	}
	if f.recv.badSigs != 0 {
		t.Fatalf("%d deliveries failed HMAC verification", f.recv.badSigs)
	}
}

// sent is one request the receiver got.
type sent struct {
	h    http.Header
	body string
}
