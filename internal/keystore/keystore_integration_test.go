// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package keystore_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func provider(t *testing.T) keys.KeyProvider {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(p); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func platformCount(t *testing.T, p *db.Pool, query string) int {
	t.Helper()
	var n int
	err := p.InTenantTx(context.Background(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, query).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntSigningKeysAreCreatedOnceAndAudited(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	kp := provider(t)
	ctx := context.Background()
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	if n := platformCount(t, p, "SELECT count(*) FROM pc.keys WHERE state = 'ACTIVE'"); n != len(keys.Purposes())+1 {
		t.Fatalf("active keys = %d, want %d (every Ed25519 purpose and the anchors key)", n, len(keys.Purposes())+1)
	}
	if n := platformCount(t, p, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.signing_key.created'"); n != len(keys.Purposes())+1 {
		t.Fatalf("audit entries = %d, want %d", n, len(keys.Purposes())+1)
	}
	s1, _ := reg.Signer(keys.PurposePermits)
	tok, _ := s1.Sign("pap-permit+jwt", []byte(`{}`))

	// A second load (server restart) reuses the stored keys.
	reg2 := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg2); err != nil {
		t.Fatal(err)
	}
	s2, _ := reg2.Signer(keys.PurposePermits)
	if s2.KeyID() != s1.KeyID() {
		t.Fatalf("restart created a new key: %s vs %s", s2.KeyID(), s1.KeyID())
	}
	v, _ := reg2.Verifier(keys.PurposePermits, "pap-permit+jwt")
	if _, _, err := v.Verify(tok); err != nil {
		t.Fatalf("token from before restart does not verify: %v", err)
	}
	if n := platformCount(t, p, "SELECT count(*) FROM pc.keys"); n != len(keys.Purposes())+1 {
		t.Fatalf("keys after restart = %d", n)
	}
}

func TestIntWrongKEKFailsClosed(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	if err := keystore.LoadSigningKeys(ctx, p, provider(t), keys.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	err := keystore.LoadSigningKeys(ctx, p, provider(t), keys.NewRegistry())
	if !errors.Is(err, keys.ErrUnwrap) {
		t.Fatalf("load with a different KEK: %v, want ErrUnwrap", err)
	}
}

func TestHR062_WrappedKeysCannotBeSwappedBetweenRows(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	kp := provider(t)
	ctx := context.Background()
	if err := keystore.LoadSigningKeys(ctx, p, kp, keys.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	// An insider copies the receipts key's wrapped material onto the permits
	// row (keeping the permits public key): unwrap must fail.
	d.AdminExec(t, `UPDATE pc.keys k SET wrapped_private_key = r.wrapped_private_key
		FROM pc.keys r WHERE k.purpose = 'permits' AND r.purpose = 'receipts' AND k.org_id = r.org_id`)
	if err := keystore.LoadSigningKeys(ctx, p, kp, keys.NewRegistry()); !errors.Is(err, keys.ErrUnwrap) {
		t.Fatalf("swapped wrapped key accepted: %v", err)
	}
}

func TestHR055_KeyMaterialIsImmutableForApp(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	if err := keystore.LoadSigningKeys(ctx, p, provider(t), keys.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"UPDATE pc.keys SET public_key = public_key",
		"UPDATE pc.keys SET wrapped_private_key = wrapped_private_key",
		"UPDATE pc.keys SET kid = kid",
		"DELETE FROM pc.keys",
		"UPDATE pc.deks SET wrapped_key = wrapped_key",
		"DELETE FROM pc.deks",
	} {
		err := p.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Errorf("%q: err = %v, want permission denied", stmt, err)
		}
	}
}

func TestIntRotationKeepsOldSignaturesVerifiable(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	kp := provider(t)
	ctx := context.Background()
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	old, _ := reg.Signer(keys.PurposeReceipts)
	tok, _ := old.Sign("pap-decision+jwt", []byte(`{"n":1}`))
	admin := domain.Actor{Type: "user", ID: "founder"}
	newKID, err := keystore.RotateSigningKey(ctx, p, kp, keys.PurposeReceipts, admin)
	if err != nil {
		t.Fatal(err)
	}
	reg = keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	cur, _ := reg.Signer(keys.PurposeReceipts)
	if cur.KeyID() != newKID || newKID == old.KeyID() {
		t.Fatalf("active kid = %s, want new %s", cur.KeyID(), newKID)
	}
	v, _ := reg.Verifier(keys.PurposeReceipts, "pap-decision+jwt")
	if _, _, err := v.Verify(tok); err != nil {
		t.Fatalf("retiring key no longer verifies: %v", err)
	}
	if err := keystore.RevokeSigningKey(ctx, p, newKID, admin); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("revoking the active key: %v, want ErrNotFound (rotate first)", err)
	}
	if err := keystore.RevokeSigningKey(ctx, p, old.KeyID(), admin); err != nil {
		t.Fatal(err)
	}
	reg = keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	v, _ = reg.Verifier(keys.PurposeReceipts, "pap-decision+jwt")
	if _, _, err := v.Verify(tok); !errors.Is(err, jws.ErrInvalid) {
		t.Fatalf("revoked key still verifies: %v", err)
	}
	for _, kind := range []string{"audit.signing_key.retiring", "audit.signing_key.revoked"} {
		if n := platformCount(t, p, "SELECT count(*) FROM pc.ledger_entries WHERE kind = '"+kind+"'"); n != 1 {
			t.Errorf("%s audit entries = %d, want 1", kind, n)
		}
	}
}

func TestIntDEKStoreWithEnvelope(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	kp := provider(t)
	ctx := context.Background()
	orgA, orgB := ids.New[ids.Org](), ids.New[ids.Org]()
	for _, o := range []ids.OrgID{orgA, orgB} {
		err := p.InTenantTx(ctx, o, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'o')", o)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	store := keystore.NewDEKStore(p, kp)
	// Concurrent first use creates exactly one version.
	var wg sync.WaitGroup
	versions := make(chan uint32, 10)
	for range 10 {
		wg.Go(func() {
			v, _, err := store.CurrentDEK(ctx, orgA, "connections")
			if err != nil {
				t.Error(err)
			}
			versions <- v
		})
	}
	wg.Wait()
	close(versions)
	for v := range versions {
		if v != 1 {
			t.Fatalf("concurrent first use produced version %d", v)
		}
	}
	env := pccrypto.NewEnvelope(store)
	fc := pccrypto.FieldContext{Org: orgA, Table: "connections", Column: "credential", RowID: "r1"}
	blob, err := env.Encrypt(ctx, fc, "connections", []byte("sk_test_not_real"))
	if err != nil {
		t.Fatal(err)
	}
	// A fresh store (another process) decrypts via the database.
	pt, err := pccrypto.NewEnvelope(keystore.NewDEKStore(p, kp)).Decrypt(ctx, fc, "connections", blob)
	if err != nil || string(pt) != "sk_test_not_real" {
		t.Fatalf("decrypt = %q, %v", pt, err)
	}
	// Org B has no DEK for this purpose and cannot read org A's.
	fcB := fc
	fcB.Org = orgB
	if _, err := pccrypto.NewEnvelope(keystore.NewDEKStore(p, kp)).Decrypt(ctx, fcB, "connections", blob); !errors.Is(err, pccrypto.ErrDecrypt) {
		t.Fatalf("org B decrypted org A's value: %v", err)
	}
	var n int
	err = p.InTenantTx(ctx, orgA, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.dek.created'").Scan(&n)
	})
	if err != nil || n != 1 {
		t.Fatalf("dek.created audit entries = %d, %v", n, err)
	}
}
