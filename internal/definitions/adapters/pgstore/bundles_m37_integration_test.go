// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR796_ExtPackageImportNeedsADraftedItem: importing an ext.* package
// is refused unless the org has a DRAFTED tool_package item with the same
// name, version and bytes (G0 M37 D1082b).
func TestHR796_ExtPackageImportNeedsADraftedItem(t *testing.T) {
	raw, err := os.ReadFile("../../../../examples/bundles/ext.example.starter/items/tool_package/tickets.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	rec := app.Record{Package: pkg, Raw: raw}
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := ids.New[ids.Org]()
	user := ids.NewV7()
	d.AdminExec(t, `INSERT INTO pc.orgs (id, name) VALUES ($1, 'bundles')`, org)
	d.AdminExec(t, `INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'ada')`, org, user)
	store := &Store{Pool: p}
	ctx := context.Background()
	if err := store.Import(ctx, org, rec); !errors.Is(err, domain.ErrBundleItemMismatch) {
		t.Fatalf("no drafted item: %v", err)
	}

	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	target := pkg.Name + "@" + pkg.Version
	other := "abababababababababababababababababababababababababababababababab"
	insertItem(t, d, org, user, digest, pkg.Name, target, "REVOKED")
	if err := store.Import(ctx, org, rec); !errors.Is(err, domain.ErrBundleItemMismatch) {
		t.Fatalf("revoked item: %v", err)
	}
	insertItem(t, d, org, user, other, pkg.Name, target, "DRAFTED")
	if err := store.Import(ctx, org, rec); !errors.Is(err, domain.ErrBundleItemMismatch) {
		t.Fatalf("different bytes: %v", err)
	}
	insertItem(t, d, org, user, digest, pkg.Name, target, "DRAFTED")
	err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return checkBundlePackage(ctx, dbq.New(tx), org, rec)
	})
	if err != nil {
		t.Fatalf("a drafted item with the same bytes: %v", err)
	}
}

func insertItem(t *testing.T, d *dbtest.DB, org ids.OrgID, user ids.UUID, sha, name, target, state string) {
	t.Helper()
	install := ids.NewV7()
	d.AdminExec(t, `INSERT INTO pc.bundle_installs (org_id, id, publisher, name, version, bundle_sha256, installed_by)
		VALUES ($1, $2, 'example', 'ext.example.starter', '1.0.0', $3, $4)`,
		org, install, sha, user)
	d.AdminExec(t, `INSERT INTO pc.bundle_items (org_id, install_id, kind, name, sha256, target_type, target_id, state)
		VALUES ($1, $2, 'tool_package', $3, $4, 'package_draft', $5, $6)`,
		org, install, name, sha, target, state)
}
