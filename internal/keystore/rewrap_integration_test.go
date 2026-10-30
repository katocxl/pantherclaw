// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package keystore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/keys/keystest"
)

func fileProvider(t *testing.T) *keys.FileProvider {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(p); err != nil {
		t.Fatal(err)
	}
	fp, err := keys.NewFileProvider([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func baoProvider(t *testing.T, f *keystest.Transit) *keys.OpenBaoProvider {
	t.Helper()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte(f.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := keys.NewTransitClient(keys.OpenBaoConfig{
		Address: f.Srv.URL, KeyName: keystest.KeyName,
		Auth: keys.OpenBaoAuth{Kind: keys.AuthToken, TokenFile: token},
	})
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewOpenBaoProvider(c)
}

func kekIDs(t *testing.T, p *db.Pool, org ids.OrgID, query string) []string {
	t.Helper()
	var out []string
	err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	}, db.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func execAs(ctx context.Context, p *db.Pool, org ids.OrgID, stmt string) error {
	return p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, stmt)
		return err
	})
}

// Covers: HR-487, T-210
// TestHR487_RewrapMovesKeysToOpenBaoAndVerifies (D157, D171): with the
// router's current KEK on OpenBao (the Transit fake), the job re-wraps the
// file-wrapped signing keys and DEKs through pc_keystore, each one audited,
// and every key still unwraps; a second run finds nothing to do; with the
// key service down it fails closed and writes nothing.
func TestHR487_RewrapMovesKeysToOpenBaoAndVerifies(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	app := d.AppPool(t)
	ks := d.Pool(t, d.Keystore)
	fp := fileProvider(t)
	fileRouter, _ := keys.NewRouter(keys.PrefixFile, fp, nil)
	before := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, app, fileRouter, before); err != nil {
		t.Fatal(err)
	}
	deks := keystore.NewDEKStore(app, fileRouter)
	_, dek, err := deks.CurrentDEK(ctx, ids.PlatformOrg, "test_purpose")
	if err != nil {
		t.Fatal(err)
	}

	f := keystest.NewTransit(t)
	r, _ := keys.NewRouter(keys.PrefixOpenBao, fp, baoProvider(t, f))
	res, err := keystore.RewrapOrg(ctx, app, ks, r, ids.PlatformOrg)
	if err != nil {
		t.Fatal(err)
	}
	if res.DEKs != 1 || res.SigningKeys != len(kekIDs(t, app, ids.PlatformOrg, "SELECT kek_id FROM pc.keys WHERE state <> 'REVOKED'")) {
		t.Fatalf("re-wrapped %+v", res)
	}
	for _, id := range slices.Concat(
		kekIDs(t, app, ids.PlatformOrg, "SELECT kek_id FROM pc.keys"),
		kekIDs(t, app, ids.PlatformOrg, "SELECT kek_id FROM pc.deks")) {
		if id != "bao:"+keystest.KeyName {
			t.Fatalf("a key is still under %q", id)
		}
	}
	if n := platformCount(t, app, "SELECT count(*) FROM pc.ledger_entries WHERE kind IN ('audit.dek.rewrapped', 'audit.signing_key.rewrapped')"); n != res.DEKs+res.SigningKeys {
		t.Fatalf("rewrap audit entries = %d, want %d", n, res.DEKs+res.SigningKeys)
	}
	// Everything still unwraps, through OpenBao alone.
	baoOnly, _ := keys.NewRouter(keys.PrefixOpenBao, nil, baoProvider(t, f))
	if err := keystore.LoadSigningKeys(ctx, app, baoOnly, keys.NewRegistry()); err != nil {
		t.Fatalf("load after re-wrap: %v", err)
	}
	got, err := keystore.NewDEKStore(app, baoOnly).DEK(ctx, ids.PlatformOrg, "test_purpose", 1)
	if err != nil || string(got.Reveal()) != string(dek.Reveal()) {
		t.Fatalf("DEK after re-wrap: %v", err)
	}
	if again, err := keystore.RewrapOrg(ctx, app, ks, r, ids.PlatformOrg); err != nil || again.DEKs+again.SigningKeys != 0 {
		t.Fatalf("second run = %+v, %v", again, err)
	}

	// Back to file while OpenBao is down: nothing is written.
	f.Down.Store(true)
	back, _ := keys.NewRouter(keys.PrefixFile, fp, baoProvider(t, f))
	if res, err := keystore.RewrapOrg(ctx, app, ks, back, ids.PlatformOrg); err == nil || res.DEKs+res.SigningKeys != 0 {
		t.Fatalf("re-wrap during an outage = %+v, %v", res, err)
	}
	if ids := kekIDs(t, app, ids.PlatformOrg, "SELECT DISTINCT kek_id FROM pc.deks"); len(ids) != 1 || ids[0] != "bao:"+keystest.KeyName {
		t.Fatalf("an outage changed a DEK: %v", ids)
	}
}

// Covers: HR-487, HR-055, T-210
// TestHR487_OnlyKeystoreRewrapsAndOnlyBothColumns (D171): pc_keystore may
// change the wrapped key only together with its kek_id (the 00224
// trigger); pc_app still may change neither.
func TestHR487_OnlyKeystoreRewrapsAndOnlyBothColumns(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	app := d.AppPool(t)
	ks := d.Pool(t, d.Keystore)
	if err := keystore.LoadSigningKeys(ctx, app, provider(t), keys.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keystore.NewDEKStore(app, provider(t)).CurrentDEK(ctx, ids.PlatformOrg, "test_purpose"); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"UPDATE pc.keys SET wrapped_private_key = wrapped_private_key || '\\x00'::bytea",
		"UPDATE pc.keys SET kek_id = 'bao:other'",
		"UPDATE pc.deks SET wrapped_key = wrapped_key || '\\x00'::bytea",
		"UPDATE pc.deks SET kek_id = 'bao:other'",
	} {
		if err := execAs(ctx, ks, ids.PlatformOrg, stmt); !db.IsCheckViolation(err) {
			t.Errorf("pc_keystore %q: %v, want the both-columns trigger", stmt, err)
		}
	}
	for _, stmt := range []string{
		"UPDATE pc.deks SET wrapped_key = wrapped_key || '\\x00'::bytea, kek_id = 'bao:other'",
		"UPDATE pc.keys SET wrapped_private_key = wrapped_private_key || '\\x00'::bytea, kek_id = 'bao:other'",
	} {
		if err := execAs(ctx, ks, ids.PlatformOrg, stmt); err != nil {
			t.Errorf("pc_keystore %q: %v", stmt, err)
		}
	}
	for _, stmt := range []string{
		"UPDATE pc.keys SET public_key = public_key",
		"UPDATE pc.keys SET state = state",
		"UPDATE pc.deks SET state = state",
		"DELETE FROM pc.deks",
		"INSERT INTO pc.deks (org_id, purpose, version, wrapped_key, kek_id) SELECT org_id, purpose, version + 1, wrapped_key, kek_id FROM pc.deks",
	} {
		if err := execAs(ctx, ks, ids.PlatformOrg, stmt); !db.IsPermissionDenied(err) {
			t.Errorf("pc_keystore %q: %v, want permission denied", stmt, err)
		}
	}
	for _, stmt := range []string{
		"UPDATE pc.deks SET wrapped_key = wrapped_key || '\\x00'::bytea, kek_id = 'bao:x'",
		"UPDATE pc.keys SET wrapped_private_key = wrapped_private_key || '\\x00'::bytea, kek_id = 'bao:x'",
	} {
		if err := execAs(ctx, app, ids.PlatformOrg, stmt); !db.IsPermissionDenied(err) {
			t.Errorf("pc_app %q: %v, want permission denied", stmt, err)
		}
	}
	// RLS binds pc_keystore: another org's rows are invisible to it.
	if n := len(kekIDs(t, ks, ids.New[ids.Org](), "SELECT kek_id FROM pc.deks")); n != 0 {
		t.Fatalf("pc_keystore saw %d DEKs of another org", n)
	}
}

// Covers: HR-486, T-210
// TestHR486_RewrapReportsUnroutableKEKsAndUnconfigured (D170, D171): a
// stored kek_id no provider holds is logged by the job and audited as
// keys.kek_unroutable, its keys are skipped, and the others still move;
// without pc_keystore nothing is written and the run says so.
func TestHR486_RewrapReportsUnroutableKEKsAndUnconfigured(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	app := d.AppPool(t)
	ks := d.Pool(t, d.Keystore)
	lost, kept := fileProvider(t), fileProvider(t)
	lostRouter, _ := keys.NewRouter(keys.PrefixFile, lost, nil)
	keptRouter, _ := keys.NewRouter(keys.PrefixFile, kept, nil)
	if _, _, err := keystore.NewDEKStore(app, lostRouter).CurrentDEK(ctx, ids.PlatformOrg, "lost_purpose"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keystore.NewDEKStore(app, keptRouter).CurrentDEK(ctx, ids.PlatformOrg, "kept_purpose"); err != nil {
		t.Fatal(err)
	}
	f := keystest.NewTransit(t)
	r, _ := keys.NewRouter(keys.PrefixOpenBao, kept, baoProvider(t, f)) // the lost KEK file is gone

	// Without pc_keystore: reported, nothing written.
	res, err := keystore.RewrapOrg(ctx, app, nil, r, ids.PlatformOrg)
	if !errors.Is(err, keystore.ErrRewrapNotConfigured) || res.DEKs != 0 {
		t.Fatalf("unconfigured = %+v, %v", res, err)
	}
	if len(res.Unroutable) != 1 || res.Unroutable[0] != lostRouter.CurrentKEK() {
		t.Fatalf("unroutable = %v, want [%s]", res.Unroutable, lostRouter.CurrentKEK())
	}

	res, err = keystore.RewrapOrg(ctx, app, ks, r, ids.PlatformOrg)
	if err != nil || res.DEKs != 1 || len(res.Unroutable) != 1 {
		t.Fatalf("with an unroutable KEK = %+v, %v; want the other DEK moved", res, err)
	}
	if n := platformCount(t, app, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.keys.kek_unroutable'"); n != 2 {
		t.Fatalf("kek_unroutable audit entries = %d, want one per run", n)
	}
	got := kekIDs(t, app, ids.PlatformOrg, "SELECT kek_id FROM pc.deks ORDER BY purpose")
	if len(got) != 2 || got[0] != "bao:"+keystest.KeyName || got[1] != lostRouter.CurrentKEK() {
		t.Fatalf("kek_ids after the run = %v", got)
	}
}
