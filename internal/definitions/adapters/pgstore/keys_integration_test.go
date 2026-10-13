// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Org package-signing keys in PostgreSQL (HR-162, T-056).

func orgSigner(t *testing.T) *jws.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.NewSigner(trust.OrgKID(pub), priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var admin = evdomain.Actor{Type: "user", ID: ids.NewV7().String()}

func (f *fixture) registerKey(org ids.OrgID, s *jws.Signer) error {
	return f.store.RegisterSigningKey(context.Background(), org, app.SigningKey{
		ID: ids.NewV7(), KID: s.KeyID(), Name: "release", Public: s.Public(), State: app.KeyActive, CreatedBy: "user:test",
	}, &audit.Event{
		Name: "package.signing_key.registered", Actor: admin, Outcome: audit.Success,
		Object: &audit.Object{Type: "package_signing_key", ID: s.KeyID()},
	})
}

// orgPackage renames the reference package into the org's namespace; with
// ownOps its operations too.
func (f *fixture) orgPackage(version string, ownOps bool) []byte {
	raw := bytes.Replace(f.files["1.0.0"], []byte("name: pc.mock-payments"), []byte("name: acme.payments"), 1)
	raw = bytes.Replace(raw, []byte("version: 1.0.0"), []byte("version: "+version), 1)
	if ownOps {
		raw = bytes.ReplaceAll(raw, []byte("payments.refund."), []byte("acmepay.refund."))
		raw = bytes.ReplaceAll(raw, []byte("payments.account."), []byte("acmepay.account."))
	}
	return raw
}

func (f *fixture) importOrg(org ids.OrgID, s *jws.Signer, v int64, version string, raw []byte) error {
	sum := sha256.Sum256(raw)
	doc, err := trust.Sign(trust.Targets{Version: v, Expires: "2027-04-08T00:00:00Z", Targets: map[string]trust.Target{
		trust.Key("acme.payments", version): {Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
	}}, s)
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = f.im.Import(context.Background(), org, "acme.payments", version, doc, raw, nil)
	return err
}

func (f *fixture) count(org ids.OrgID, sql string, args ...any) int {
	var n int
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestIntHR162_KeysRegisterOncePerOrgAndKeepTheirOwnRollbackState(t *testing.T) {
	f := setup(t)
	f.im.Keys = f.store
	ctx := context.Background()
	org, other := newOrg(t, f.pool), newOrg(t, f.pool)
	key := orgSigner(t)
	if err := f.registerKey(org, key); err != nil {
		t.Fatal(err)
	}
	k, err := f.store.SigningKey(ctx, org, key.KeyID())
	if err != nil || !k.Public.Equal(key.Public()) || k.State != app.KeyActive || k.Metadata != nil || k.CreatedAt.IsZero() {
		t.Fatalf("stored key %+v %v", k, err)
	}
	if err := f.registerKey(org, key); !errors.Is(err, app.ErrKeyRegistered) {
		t.Fatalf("same kid again: %v", err)
	}
	// Tenancy: the other org does not see the key, and may register the
	// same public key for itself.
	if _, err := f.store.SigningKey(ctx, other, key.KeyID()); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatalf("other org reads the key: %v", err)
	}
	if err := f.registerKey(other, key); err != nil {
		t.Fatal(err)
	}

	if err := f.importOrg(org, key, 3, "1.0.0", f.orgPackage("1.0.0", true)); err != nil {
		t.Fatal(err)
	}
	if k, _ := f.store.SigningKey(ctx, org, key.KeyID()); k.Metadata == nil || k.Metadata.Version != 3 {
		t.Fatalf("key metadata %+v", k.Metadata)
	}
	if root, _ := f.store.TrustedMetadata(ctx, org); root != nil {
		t.Fatalf("an org-signed import moved the root state to %+v", root)
	}
	if k, _ := f.store.SigningKey(ctx, other, key.KeyID()); k.Metadata != nil {
		t.Fatal("anti-rollback state leaked into another org")
	}
	if err := f.importOrg(org, key, 2, "1.1.0", f.orgPackage("1.1.0", true)); !errors.Is(err, trust.ErrRollback) {
		t.Fatalf("older org metadata: %v", err)
	}
	vs, err := f.store.ListVersions(ctx, org, "acme.payments")
	if err != nil || len(vs) != 1 || vs[0].SigningKey != key.KeyID() || vs[0].State != domain.StateReviewed {
		t.Fatalf("versions %+v %v", vs, err)
	}
	if signer, err := f.store.VersionSigner(ctx, org, "acme.payments", "1.0.0"); err != nil || signer == nil || signer.KID != key.KeyID() {
		t.Fatalf("VersionSigner = %+v %v", signer, err)
	}
	// The key itself never changes (column grants).
	err = f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.package_signing_keys SET public_key = $2 WHERE org_id = $1", org, make([]byte, 32))
		return err
	})
	if err == nil {
		t.Fatal("pc_app rewrote a registered public key")
	}
}

func TestIntHR162_ActiveKeyLimitHoldsUnderConcurrency(t *testing.T) {
	f := setup(t)
	org := newOrg(t, f.pool)
	var wg sync.WaitGroup
	errs := make([]error, 3*app.MaxActiveSigningKeys)
	signers := make([]*jws.Signer, len(errs))
	for i := range signers {
		signers[i] = orgSigner(t)
	}
	for i := range errs {
		wg.Go(func() { errs[i] = f.registerKey(org, signers[i]) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, app.ErrKeyLimit):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != app.MaxActiveSigningKeys {
		t.Fatalf("%d keys registered concurrently, want %d", ok, app.MaxActiveSigningKeys)
	}
}

func TestIntT056_AnOperationHasOneKindOfSigner(t *testing.T) {
	f := setup(t)
	f.im.Keys = f.store
	ctx := context.Background()
	org, other := newOrg(t, f.pool), newOrg(t, f.pool)
	key := orgSigner(t)
	for _, o := range []ids.OrgID{org, other} {
		if err := f.registerKey(o, key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.im.Import(ctx, org, "pc.mock-payments", "1.0.0", f.targets(1, "1.0.0"), f.files["1.0.0"], nil); err != nil {
		t.Fatal(err)
	}
	if err := f.importOrg(org, key, 1, "1.0.0", f.orgPackage("1.0.0", false)); !errors.Is(err, app.ErrOperationTaken) {
		t.Fatalf("org package redefining PantherClaw operations: %v", err)
	}
	if n := f.count(org, "SELECT count(*) FROM pc.package_versions"); n != 1 {
		t.Fatalf("%d versions stored after a refused import", n)
	}
	// The reverse, in another org: the org package first.
	if err := f.importOrg(other, key, 1, "1.0.0", f.orgPackage("1.0.0", false)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.im.Import(ctx, other, "pc.mock-payments", "1.0.0", f.targets(1, "1.0.0"), f.files["1.0.0"], nil); !errors.Is(err, app.ErrOperationTaken) {
		t.Fatalf("PantherClaw package after an org package with its operations: %v", err)
	}
	if err := f.im.Transition(ctx, other, "acme.payments", "1.0.0", domain.StateRetired, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.im.Import(ctx, other, "pc.mock-payments", "1.0.0", f.targets(1, "1.0.0"), f.files["1.0.0"], nil); err != nil {
		t.Fatalf("after retiring the org version: %v", err)
	}
}

func TestIntT056_RevokingACompromisedKeyWithdrawsItsVersionsAtOnce(t *testing.T) {
	f := setup(t)
	f.im.Keys = f.store
	ctx := context.Background()
	org := newOrg(t, f.pool)
	key := orgSigner(t)
	if err := f.registerKey(org, key); err != nil {
		t.Fatal(err)
	}
	for i, v := range []string{"1.0.0", "1.1.0"} {
		if err := f.importOrg(org, key, int64(i+1), v, f.orgPackage(v, true)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.im.Transition(ctx, org, "acme.payments", "1.0.0", domain.StateActive, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.im.Import(ctx, org, "pc.mock-payments", "1.0.0", f.targets(1, "1.0.0"), f.files["1.0.0"], nil); err != nil {
		t.Fatal(err)
	}
	before := f.epoch(org)
	ev := &audit.Event{
		Name: "package.signing_key.revoked", Actor: admin, Outcome: audit.Success,
		Object: &audit.Object{Type: "package_signing_key", ID: key.KeyID()},
	}
	moved, err := f.store.RevokeSigningKey(ctx, org, key.KeyID(), app.RevokeCompromised, "user:test", ev)
	if err != nil {
		t.Fatal(err)
	}
	want := []app.VersionChange{
		{Name: "acme.payments", Version: "1.0.0", From: domain.StateActive, To: domain.StateQuarantined},
		{Name: "acme.payments", Version: "1.1.0", From: domain.StateReviewed, To: domain.StateRetired},
	}
	if len(moved) != len(want) || moved[0] != want[0] || moved[1] != want[1] {
		t.Fatalf("moved %+v, want %+v", moved, want)
	}
	if f.epoch(org) != before+1 {
		t.Fatal("a compromised key must raise the containment epoch (HR-002)")
	}
	if s, _ := f.store.State(ctx, org, "pc.mock-payments", "1.0.0"); s != domain.StateReviewed {
		t.Fatalf("a root-signed version moved to %s", s)
	}
	k, _ := f.store.SigningKey(ctx, org, key.KeyID())
	if k.State != app.KeyRevoked || k.Reason != app.RevokeCompromised || k.RevokedBy != "user:test" || k.RevokedAt.IsZero() {
		t.Fatalf("revoked key %+v", k)
	}
	if n := f.count(org, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.package.transitioned'"); n != 2 {
		t.Fatalf("%d package.transitioned audit events, want one per withdrawn version", n)
	}
	if n := f.count(org, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.package.signing_key.revoked'"); n != 1 {
		t.Fatalf("%d revocation audit events", n)
	}
	if _, err := f.store.RevokeSigningKey(ctx, org, key.KeyID(), app.RevokeRotated, "user:test", nil); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("revoking twice: %v", err)
	}
	if err := f.importOrg(org, key, 3, "1.2.0", f.orgPackage("1.2.0", true)); !errors.Is(err, trust.ErrUntrusted) {
		t.Fatalf("import with a revoked key: %v", err)
	}
	if err := f.im.Transition(ctx, org, "acme.payments", "1.0.0", domain.StateReviewed, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.im.Transition(ctx, org, "acme.payments", "1.0.0", domain.StateActive, nil); !errors.Is(err, app.ErrKeyCompromised) {
		t.Fatalf("re-activating a compromised key's version: %v", err)
	}
}

func TestIntHR162_ARevokedKeyAdvancesNoMetadata(t *testing.T) {
	f := setup(t)
	f.im.Keys = f.store
	ctx := context.Background()
	org := newOrg(t, f.pool)
	key := orgSigner(t)
	if err := f.registerKey(org, key); err != nil {
		t.Fatal(err)
	}
	k, _ := f.store.SigningKey(ctx, org, key.KeyID())
	before := f.epoch(org)
	if _, err := f.store.RevokeSigningKey(ctx, org, key.KeyID(), app.RevokeRotated, "user:test", nil); err != nil {
		t.Fatal(err)
	}
	if f.epoch(org) != before {
		t.Fatal("a rotation raised the containment epoch")
	}
	// An import that verified the key before the revocation loses the race.
	raw := f.orgPackage("1.0.0", true)
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	err = f.store.Import(ctx, org, app.Record{
		Metadata: trust.State{Version: 1, PayloadDigest: hex.EncodeToString(make([]byte, 32))}, MetadataExpiry: f.im.Clock.Now().AddDate(0, 6, 0),
		SigningKey: &k.ID, Package: p, Raw: raw, FileDigest: "sha256:" + hex.EncodeToString(sha(raw)),
		Pin: domain.Pin{Package: p.Name, Version: p.Version, Digest: "sha256:" + hex.EncodeToString(sha(raw))}, State: domain.StateReviewed,
	})
	if !errors.Is(err, app.ErrConflict) {
		t.Fatalf("import under a revoked key: %v", err)
	}
	if n := f.count(org, "SELECT count(*) FROM pc.package_versions"); n != 0 {
		t.Fatal("a version was stored under a revoked key")
	}
}

func sha(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
