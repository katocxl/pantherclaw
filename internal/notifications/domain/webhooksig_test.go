// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// orgKeys signs with one Ed25519 key per org, as the keystore does.
type orgKeys struct {
	keys map[ids.OrgID]ed25519.PrivateKey
	err  error
}

func (k orgKeys) SignWebhook(_ context.Context, org ids.OrgID, content []byte) ([]byte, error) {
	if k.err != nil {
		return nil, k.err
	}
	priv, ok := k.keys[org]
	if !ok {
		return nil, errors.New("no key")
	}
	return ed25519.Sign(priv, content), nil
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestHR510_Ed25519IsOptInAndHMACIsAlwaysSent: the default scheme sends
// the HMAC `v1,` signatures only; an opted-in destination receives the
// same `v1,` signatures and a `v1a,` one that verifies with its org's key
// (G0 M20 D251).
// Covers: PN-018
func TestHR510_Ed25519IsOptInAndHMACIsAlwaysSent(t *testing.T) {
	ctx := context.Background()
	org := ids.New[ids.Org]()
	pub, priv := newKey(t)
	signer := orgKeys{keys: map[ids.OrgID]ed25519.PrivateKey{org: priv}}
	secrets := [][]byte{[]byte("current secret of thirty-two by!"), []byte("previous secret of thirty-two b!")}
	body := []byte(`{"type":"test"}`)
	hmacOnly := domain.Signatures(secrets, "msg_1", 1700000000, body)

	got, err := domain.SignatureHeader(ctx, signer, org, domain.SchemeHMAC, secrets, "msg_1", 1700000000, body)
	if err != nil || got != hmacOnly || strings.Contains(got, "v1a,") {
		t.Fatalf("default scheme header %q (%v), want the HMAC signatures only", got, err)
	}
	// The default is HMAC even with no signer wired.
	if got, err := domain.SignatureHeader(ctx, nil, org, domain.SchemeHMAC, secrets, "msg_1", 1700000000, body); err != nil || got != hmacOnly {
		t.Fatalf("default scheme without a signer: %q (%v)", got, err)
	}

	got, err = domain.SignatureHeader(ctx, signer, org, domain.SchemeHMACEd25519, secrets, "msg_1", 1700000000, body)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(got, " ")
	if len(parts) != 3 || strings.Join(parts[:2], " ") != hmacOnly || !strings.HasPrefix(parts[2], "v1a,") {
		t.Fatalf("opted-in header %q, want both v1, signatures then v1a,", got)
	}
	if !domain.VerifyV1a(pub, parts[2], "msg_1", 1700000000, body) {
		t.Fatal("the v1a, signature does not verify with the org's key")
	}
	// It signs exactly "msgID.timestamp.body".
	for _, c := range []struct {
		id   string
		ts   int64
		body string
	}{{"msg_2", 1700000000, `{"type":"test"}`}, {"msg_1", 1700000001, `{"type":"test"}`}, {"msg_1", 1700000000, `{"type":"tesT"}`}} {
		if domain.VerifyV1a(pub, parts[2], c.id, c.ts, []byte(c.body)) {
			t.Fatalf("the v1a, signature verifies for %+v", c)
		}
	}

	// An opted-in destination never goes out without its v1a, signature.
	if _, err := domain.SignatureHeader(ctx, nil, org, domain.SchemeHMACEd25519, secrets, "msg_1", 1, body); !errors.Is(err, domain.ErrNoWebhookSigner) {
		t.Fatalf("opted in without a signer: %v", err)
	}
	if _, err := domain.SignatureHeader(ctx, orgKeys{err: errors.New("down")}, org, domain.SchemeHMACEd25519, secrets, "msg_1", 1, body); err == nil {
		t.Fatal("opted in with a failing signer: no error")
	}
	if domain.SignatureScheme("ed25519").Valid() || !domain.SchemeHMAC.Valid() || !domain.SchemeHMACEd25519.Valid() {
		t.Fatal("scheme validation")
	}
}

// TestHR511_AnOrgsWebhookIsSignedByItsOwnKey: the signer is asked for the
// destination's org, so another org's key never verifies it, and the JWKS
// path names that org (G0 M20 D251).
// Covers: PN-018
func TestHR511_AnOrgsWebhookIsSignedByItsOwnKey(t *testing.T) {
	ctx := context.Background()
	a, b := ids.New[ids.Org](), ids.New[ids.Org]()
	pubA, privA := newKey(t)
	pubB, privB := newKey(t)
	signer := orgKeys{keys: map[ids.OrgID]ed25519.PrivateKey{a: privA, b: privB}}
	got, err := domain.SignatureHeader(ctx, signer, b, domain.SchemeHMACEd25519, [][]byte{[]byte("s")}, "msg_1", 1, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	v1a := got[strings.LastIndex(got, " ")+1:]
	if !domain.VerifyV1a(pubB, v1a, "msg_1", 1, []byte("{}")) || domain.VerifyV1a(pubA, v1a, "msg_1", 1, []byte("{}")) {
		t.Fatal("org b's webhook is not signed by org b's key alone")
	}
	if p := domain.WebhookJWKSPath(a); p != "/.well-known/pantherclaw/orgs/"+a.String()+"/webhook-jwks.json" {
		t.Fatalf("JWKS path %s", p)
	}
	if u := domain.WebhookJWKSURL("https://pc.example/", a); u != "https://pc.example"+domain.WebhookJWKSPath(a) {
		t.Fatalf("JWKS URL %s", u)
	}
}
