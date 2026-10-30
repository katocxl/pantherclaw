// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/keys/keystest"
)

func loadTestConfig(t *testing.T, path string) *Config {
	t.Helper()
	cfg := DefaultConfig()
	if err := config.Load(&cfg, path, noEnv); err != nil {
		t.Fatal(err)
	}
	return &cfg
}

// openbaoConfig is a config over the same database whose key service is
// the Transit fake; kekFiles are kept for the keys they wrapped (or nil).
func openbaoConfig(t *testing.T, d *dbtest.DB, f *keystest.Transit, kekFiles []string) string {
	t.Helper()
	token := secretFile(t, t.TempDir(), "bao-token", []byte(f.Token))
	return testConfig(t, d, RoleAPI, func(m map[string]any) {
		m["kek_files"] = kekFiles
		m["key_service"] = map[string]any{
			"kind": "openbao",
			"openbao": map[string]any{
				"address": f.Srv.URL, "key_name": keystest.KeyName,
				"auth": map[string]any{"kind": "token", "token_file": token},
			},
		}
	})
}

func platformKEKIDs(t *testing.T, pool *db.Pool) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := pool.InTenantTx(context.Background(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSigningKeys(ctx, ids.PlatformOrg)
		for _, r := range rows {
			out[r.Kid] = r.KekID
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHR486_OperatorCommandsUseTheKeyService (D165 M3, L1): with
// key_service.kind openbao, `keys rotate-*` wraps the new keys with
// OpenBao while the file KEK still unwraps the older ones; restore builds
// its registry through the same router; start-up refuses, with a
// configuration error, a key service that cannot unwrap the stored keys;
// and an OpenBao outage fails the load closed.
func TestHR486_OperatorCommandsUseTheKeyService(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	pool := d.AppPool(t)
	filePath := testConfig(t, d, RoleAPI)
	fileCfg := loadTestConfig(t, filePath)
	before := loadRegistry(t, d, filePath) // creates the keys under the file KEK
	oldReceipts := activeKID(t, before, keys.PurposeReceipts)

	f := keystest.NewTransit(t)
	baoPath := openbaoConfig(t, d, f, fileCfg.KEKFiles)
	if code, out, errs := runKeys(t, baoPath, "rotate-receipts", "--confirm"); code != 0 {
		t.Fatalf("rotate-receipts with kind openbao = %d %s %s", code, out, errs)
	}
	baoCfg := loadTestConfig(t, baoPath)
	kp, err := newCheckedKeyProvider(ctx, baoCfg, pool)
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, reg); err != nil {
		t.Fatalf("load with mixed providers: %v", err)
	}
	newReceipts := activeKID(t, reg, keys.PurposeReceipts)
	kek := platformKEKIDs(t, pool)
	if newReceipts == oldReceipts || kek[newReceipts] != "bao:"+keystest.KeyName {
		t.Fatalf("new receipts key %s has kek_id %q", newReceipts, kek[newReceipts])
	}
	if !strings.HasPrefix(kek[oldReceipts], keys.PrefixFile) && !strings.HasPrefix(kek[oldReceipts], "kek-") {
		t.Fatalf("old receipts key kek_id %q", kek[oldReceipts])
	}
	if _, err := newRestoreRegistry(ctx, baoCfg, pool); err != nil {
		t.Fatalf("restore registry with kind openbao: %v", err)
	}

	// Dropping the KEK files while file-wrapped keys remain is a start-up
	// configuration error, not a later unwrap failure.
	noFiles := loadTestConfig(t, openbaoConfig(t, d, f, nil))
	if _, err := newCheckedKeyProvider(ctx, noFiles, pool); err == nil || !strings.Contains(err.Error(), "kek_files") {
		t.Fatalf("start without the file KEK: %v", err)
	}
	// Another file KEK only does not hold the stored keys either.
	other := loadTestConfig(t, testConfig(t, d, RoleAPI))
	if _, err := newCheckedKeyProvider(ctx, other, pool); err == nil {
		t.Fatal("start with an unrelated KEK file accepted")
	}

	// An outage fails closed: nothing loads.
	f.Down.Store(true)
	if err := keystore.LoadSigningKeys(ctx, pool, kp, keys.NewRegistry()); err == nil {
		t.Fatal("signing keys loaded during an OpenBao outage")
	}
}
