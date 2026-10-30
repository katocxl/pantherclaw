// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package keystore_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

type webhookFixture struct {
	d    *dbtest.DB
	p    *db.Pool
	kp   keys.KeyProvider
	a, b ids.OrgID
}

func newWebhookFixture(t *testing.T) *webhookFixture {
	t.Helper()
	d := dbtest.New(t)
	f := &webhookFixture{d: d, p: d.AppPool(t), kp: provider(t), a: ids.New[ids.Org](), b: ids.New[ids.Org]()}
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'a'), ($2, 'b')", f.a, f.b)
	return f
}

func (f *webhookFixture) count(t *testing.T, org ids.OrgID, query string) int {
	t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, query).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// jwks parses an org's webhook JWKS into kid → public key.
func jwks(t *testing.T, w *keystore.WebhookKeys, org ids.OrgID) map[string]ed25519.PublicKey {
	t.Helper()
	b, err := w.WebhookJWKS(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]ed25519.PublicKey{}
	for _, k := range doc.Keys {
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" {
			t.Fatalf("JWK %+v", k)
		}
		out[k.Kid] = x
	}
	return out
}

var person = domain.Actor{Type: "user", ID: "alice"}

// TestHR511_AWebhookKeySignsOnlyItsOrgAndItsJWKSListsOnlyItsKeys: each org
// gets its own webhooks key (created once, audited in that org's ledger);
// a signature for org b verifies with b's JWKS and with nothing in a's;
// neither JWKS lists the other's key, pc_app sees only its own org's rows,
// and the platform org has no webhook key (G0 M20 D251).
// Covers: PN-018
func TestHR511_AWebhookKeySignsOnlyItsOrgAndItsJWKSListsOnlyItsKeys(t *testing.T) {
	f := newWebhookFixture(t)
	ctx := context.Background()
	w := keystore.NewWebhookKeys(f.p, f.kp)
	if b, err := w.WebhookJWKS(ctx, f.a); err != nil || string(b) != `{"keys":[]}` {
		t.Fatalf("JWKS before any key: %s %v", b, err)
	}
	if _, err := w.SignWebhook(ctx, f.a, []byte("x")); !errors.Is(err, keystore.ErrNoWebhookKey) {
		t.Fatalf("sign without a key: %v", err)
	}
	ka, err := w.EnsureWebhookKey(ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := w.EnsureWebhookKey(ctx, f.a); err != nil || again != ka {
		t.Fatalf("second ensure: %s %v, want %s", again, err, ka)
	}
	kb, err := w.EnsureWebhookKey(ctx, f.b)
	if err != nil || kb == ka {
		t.Fatalf("org b key %s %v", kb, err)
	}
	ja, jb := jwks(t, w, f.a), jwks(t, w, f.b)
	if len(ja) != 1 || ja[ka] == nil || len(jb) != 1 || jb[kb] == nil {
		t.Fatalf("JWKS a %v, b %v", ja, jb)
	}
	sig, err := w.SignWebhook(ctx, f.b, []byte("msg_1.1.{}"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(jb[kb], []byte("msg_1.1.{}"), sig) || ed25519.Verify(ja[ka], []byte("msg_1.1.{}"), sig) {
		t.Fatal("org b's webhook is not signed by org b's key alone")
	}
	for _, org := range []ids.OrgID{f.a, f.b} {
		if n := f.count(t, org, "SELECT count(*) FROM pc.keys WHERE purpose = 'webhooks'"); n != 1 {
			t.Fatalf("org %s sees %d webhook keys, want its own 1", org, n)
		}
		if n := f.count(t, org, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.signing_key.created'"); n != 1 {
			t.Fatalf("org %s has %d creation audits", org, n)
		}
	}
	for _, call := range []func() error{
		func() error { _, err := w.EnsureWebhookKey(ctx, ids.PlatformOrg); return err },
		func() error { _, err := w.SignWebhook(ctx, ids.PlatformOrg, nil); return err },
		func() error { _, err := w.WebhookJWKS(ctx, ids.PlatformOrg); return err },
		func() error { _, _, err := w.RotateWebhookKey(ctx, ids.PlatformOrg, person, nil); return err },
	} {
		if call() == nil {
			t.Fatal("the platform org got a webhook key operation")
		}
	}
	// The platform registry never holds or creates webhooks keys.
	if err := keystore.LoadSigningKeys(ctx, f.p, f.kp, keys.NewRegistry(), keys.PurposeWebhooks); err == nil {
		t.Fatal("LoadSigningKeys accepted the webhooks purpose")
	}
	if _, err := keystore.RotateSigningKey(ctx, f.p, f.kp, keys.PurposeWebhooks, person); err == nil {
		t.Fatal("RotateSigningKey accepted the webhooks purpose")
	}
}

// TestHR512_ARotatedWebhookKeyVerifiesFor24HoursThenIsGone: a rotation
// keeps the old key in the JWKS as RETIRING (what it signed still
// verifies), signs with the new key from then on, and refuses a second
// rotation during the overlap; after 24 hours the old key is gone from the
// JWKS and the next rotation revokes it, each step audited (D251, D261).
// Covers: PN-018
func TestHR512_ARotatedWebhookKeyVerifiesFor24HoursThenIsGone(t *testing.T) {
	f := newWebhookFixture(t)
	ctx := context.Background()
	w := keystore.NewWebhookKeys(f.p, f.kp)
	old, err := w.EnsureWebhookKey(ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("msg_1.1700000000.{}")
	oldSig, err := w.SignWebhook(ctx, f.a, msg)
	if err != nil {
		t.Fatal(err)
	}
	hookRan := false
	next, retiring, err := w.RotateWebhookKey(ctx, f.a, person, func(context.Context, db.TenantTx, string, string) error {
		hookRan = true
		return nil
	})
	if err != nil || retiring != old || next == old || !hookRan {
		t.Fatalf("rotate: %s %s %v (hook %v)", next, retiring, err, hookRan)
	}
	set := jwks(t, w, f.a)
	if len(set) != 2 || !ed25519.Verify(set[old], msg, oldSig) || set[next] == nil {
		t.Fatalf("JWKS during the overlap %v", set)
	}
	newSig, err := w.SignWebhook(ctx, f.a, msg)
	if err != nil || !ed25519.Verify(set[next], msg, newSig) {
		t.Fatalf("after the rotation it does not sign with the new key: %v", err)
	}
	ks, err := w.ListWebhookKeys(ctx, f.a)
	if err != nil || len(ks) != 2 || ks[0].KID != next || ks[0].State != keys.StateActive || ks[1].State != keys.StateRetiring ||
		ks[1].RetiresAt.Sub(ks[0].CreatedAt) < keystore.WebhookKeyOverlap-time.Minute || ks[1].RetiresAt.Sub(ks[0].CreatedAt) > keystore.WebhookKeyOverlap+time.Minute {
		t.Fatalf("keys %+v %v", ks, err)
	}
	if _, _, err := w.RotateWebhookKey(ctx, f.a, person, nil); !errors.Is(err, keystore.ErrWebhookKeyRotating) {
		t.Fatalf("second rotation during the overlap: %v", err)
	}
	// A failing hook (a refused step-up) undoes the rotation.
	f.d.AdminExec(t, "UPDATE pc.keys SET state_changed_at = now() - interval '25 hours' WHERE kid = $1", old)
	if _, _, err := w.RotateWebhookKey(ctx, f.a, person, func(context.Context, db.TenantTx, string, string) error {
		return errors.New("step-up refused")
	}); err == nil {
		t.Fatal("rotation with a failing hook succeeded")
	}
	if n := f.count(t, f.a, "SELECT count(*) FROM pc.keys WHERE purpose = 'webhooks'"); n != 2 {
		t.Fatalf("a refused rotation left %d keys", n)
	}

	// After the overlap the old key is gone from the JWKS and the list.
	set = jwks(t, w, f.a)
	if _, ok := set[old]; ok || len(set) != 1 {
		t.Fatalf("JWKS after the overlap %v", set)
	}
	if ks, _ := w.ListWebhookKeys(ctx, f.a); len(ks) != 1 || ks[0].KID != next {
		t.Fatalf("keys after the overlap %+v", ks)
	}
	third, retiring, err := w.RotateWebhookKey(ctx, f.a, person, nil)
	if err != nil || retiring != next {
		t.Fatalf("rotation after the overlap: %s %s %v", third, retiring, err)
	}
	if n := f.count(t, f.a, "SELECT count(*) FROM pc.keys WHERE purpose = 'webhooks' AND state = 'REVOKED' AND kid = '"+old+"'"); n != 1 {
		t.Fatal("the expired key was not revoked")
	}
	if set := jwks(t, w, f.a); len(set) != 2 || set[third] == nil || set[next] == nil {
		t.Fatalf("JWKS after the second rotation %v", set)
	}
	for kind, want := range map[string]int{
		"audit.signing_key.created": 3, "audit.signing_key.retiring": 2, "audit.signing_key.revoked": 1,
	} {
		if n := f.count(t, f.a, "SELECT count(*) FROM pc.ledger_entries WHERE kind = '"+kind+"'"); n != want {
			t.Errorf("%s: %d, want %d", kind, n, want)
		}
	}
}

// TestT222_WebhookKeyMisuseAcrossOrgs: an insider who copies one org's
// wrapped webhook key onto another org's row, or the whole row into
// another org, gets nothing that signs: the wrap binds the org (HR-062),
// so the load fails closed and the other org is untouched (G0 M20 D251,
// HR-511).
func TestT222_WebhookKeyMisuseAcrossOrgs(t *testing.T) {
	f := newWebhookFixture(t)
	ctx := context.Background()
	w := keystore.NewWebhookKeys(f.p, f.kp)
	ka, err := w.EnsureWebhookKey(ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := w.EnsureWebhookKey(ctx, f.b)
	if err != nil {
		t.Fatal(err)
	}
	// a's wrapped key on b's row (b's public key kept).
	f.d.AdminExec(t, `UPDATE pc.keys k SET wrapped_private_key = s.wrapped_private_key, kek_id = s.kek_id
		FROM pc.keys s WHERE k.kid = $1 AND s.kid = $2`, kb, ka)
	if _, err := keystore.NewWebhookKeys(f.p, f.kp).SignWebhook(ctx, f.b, []byte("x")); !errors.Is(err, keys.ErrUnwrap) {
		t.Fatalf("b signed with a's wrapped key: %v", err)
	}
	// a's whole row copied into b as b's only ACTIVE key.
	f.d.AdminExec(t, "UPDATE pc.keys SET state = 'REVOKED' WHERE kid = $1", kb)
	f.d.AdminExec(t, `INSERT INTO pc.keys (org_id, id, kid, purpose, algorithm, public_key, wrapped_private_key, kek_id, state)
		SELECT $1, gen_random_uuid(), kid, purpose, algorithm, public_key, wrapped_private_key, kek_id, 'ACTIVE'
		FROM pc.keys WHERE kid = $2`, f.b, ka)
	if _, err := keystore.NewWebhookKeys(f.p, f.kp).SignWebhook(ctx, f.b, []byte("x")); !errors.Is(err, keys.ErrUnwrap) {
		t.Fatalf("b signed with a's copied row: %v", err)
	}
	// a is untouched and still signs with its own key.
	sig, err := keystore.NewWebhookKeys(f.p, f.kp).SignWebhook(ctx, f.a, []byte("x"))
	if err != nil || !ed25519.Verify(jwks(t, w, f.a)[ka], []byte("x"), sig) {
		t.Fatalf("org a after the tampering: %v", err)
	}
}
