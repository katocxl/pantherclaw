// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

type fixture struct {
	t      *testing.T
	pool   *db.Pool
	store  *pgstore.Store
	im     *app.Importer
	signer *jws.Signer
	files  map[string][]byte
}

func newOrg(t *testing.T, p *db.Pool) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org); err != nil {
			return err
		}
		return dbq.New(tx).InsertContainment(ctx, org)
	})
	if err != nil {
		t.Fatal(err)
	}
	return org
}

func setup(t *testing.T) *fixture {
	t.Helper()
	p := dbtest.New(t).AppPool(t)
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := jws.NewSigner(kid, priv)
	raw, err := os.ReadFile("../../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	store := &pgstore.Store{Pool: p}
	return &fixture{
		t: t, pool: p, store: store, signer: s,
		im:    &app.Importer{Roots: trust.Roots{kid: s.Public()}, Repo: store, Clock: clock.NewFake(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))},
		files: map[string][]byte{"1.0.0": raw, "1.1.0": bytes.Replace(raw, []byte("version: 1.0.0"), []byte("version: 1.1.0"), 1)},
	}
}

func (f *fixture) targets(v int64, versions ...string) string {
	tg := trust.Targets{Version: v, Expires: "2027-04-08T00:00:00Z", Targets: map[string]trust.Target{}}
	for _, ver := range versions {
		sum := sha256.Sum256(f.files[ver])
		tg.Targets[trust.Key("pc.mock-payments", ver)] = trust.Target{
			Length: int64(len(f.files[ver])), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])},
		}
	}
	doc, err := trust.Sign(tg, f.signer)
	if err != nil {
		f.t.Fatal(err)
	}
	return doc
}

func (f *fixture) epoch(org ids.OrgID) int64 {
	var e int64
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", org).Scan(&e)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return e
}

func TestIntImportStoresPackagesDefinitionsAndPins(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	org := newOrg(t, f.pool)
	res, err := f.im.Import(ctx, org, "pc.mock-payments", "1.0.0", f.targets(1, "1.0.0"), f.files["1.0.0"], nil)
	if err != nil {
		t.Fatal(err)
	}
	refund, _ := res.Package.Definition("payments.refund.create")
	pin := actionir.Definition{Package: "pc.mock-payments", Version: "1.0.0", Digest: refund.Digest}
	d, state, err := f.store.Pinned(ctx, org, pin)
	if err != nil || d.Digest != refund.Digest || state != domain.StateReviewed {
		t.Fatalf("Pinned = %v %s %v", d, state, err)
	}
	if a, err := f.store.Active(ctx, org, "payments.refund.create"); err != nil || a != nil {
		t.Fatalf("a REVIEWED version is not active: %v %v", a, err)
	}
	if err := f.im.Transition(ctx, org, "pc.mock-payments", "1.0.0", domain.StateActive, nil); err != nil {
		t.Fatal(err)
	}
	if a, err := f.store.Active(ctx, org, "payments.refund.create"); err != nil || a == nil || a.Digest != refund.Digest {
		t.Fatalf("Active = %v %v", a, err)
	}
	if defs, err := f.store.ActiveDefinitions(ctx, org); err != nil || len(defs) != len(res.Package.Definitions) {
		t.Fatalf("ActiveDefinitions = %d %v", len(defs), err)
	}

	// A newer version moves the pin; the older one stays usable until it
	// is retired, and retiring it raises the containment epoch.
	if _, err := f.im.Import(ctx, org, "pc.mock-payments", "1.1.0", f.targets(2, "1.0.0", "1.1.0"), f.files["1.1.0"], nil); err != nil {
		t.Fatal(err)
	}
	if p, err := f.store.CurrentPin(ctx, org, "pc.mock-payments"); err != nil || p.Version != "1.1.0" {
		t.Fatalf("pin %+v %v", p, err)
	}
	if _, state, err := f.store.Pinned(ctx, org, pin); err != nil || state != domain.StateActive {
		t.Fatalf("the older version: %s %v", state, err)
	}
	before := f.epoch(org)
	if err := f.im.Transition(ctx, org, "pc.mock-payments", "1.0.0", domain.StateQuarantined, nil); err != nil {
		t.Fatal(err)
	}
	if f.epoch(org) != before+1 {
		t.Fatal("quarantining a version must raise the containment epoch (HR-002)")
	}

	// Another org sees nothing (T-003).
	other := newOrg(t, f.pool)
	if _, _, err := f.store.Pinned(ctx, other, pin); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatalf("another org's definition was found: %v", err)
	}
}

func TestHR123_StoredPinsAndMetadataOnlyMoveForward(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	org := newOrg(t, f.pool)
	if _, err := f.im.Import(ctx, org, "pc.mock-payments", "1.1.0", f.targets(2, "1.0.0", "1.1.0"), f.files["1.1.0"], nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.im.Import(ctx, org, "pc.mock-payments", "1.0.0", f.targets(2, "1.0.0", "1.1.0"), f.files["1.0.0"], nil); err == nil {
		t.Fatal("the pin moved backwards")
	}
	if _, err := f.im.Import(ctx, org, "pc.mock-payments", "1.1.0", f.targets(1, "1.1.0"), f.files["1.1.0"], nil); err == nil {
		t.Fatal("older targets metadata was accepted")
	}

	// Concurrent imports of the next version: at most one writes; the
	// other conflicts or finds it unchanged (HR-004).
	f.files["1.2.0"] = bytes.Replace(f.files["1.0.0"], []byte("version: 1.0.0"), []byte("version: 1.2.0"), 1)
	doc := f.targets(3, "1.2.0")
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Go(func() { _, results[i] = f.im.Import(ctx, org, "pc.mock-payments", "1.2.0", doc, f.files["1.2.0"], nil) })
	}
	wg.Wait()
	ok := 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, app.ErrConflict):
		default:
			t.Fatalf("unexpected error %v", err)
		}
	}
	if ok == 0 {
		t.Fatal("neither concurrent import succeeded")
	}
	if p, _ := f.store.CurrentPin(ctx, org, "pc.mock-payments"); p.Version != "1.2.0" {
		t.Fatalf("pin %+v", p)
	}
}

// reviews lists the org's TOOL_REVIEW entries as "version state priority",
// oldest first.
func (f *fixture) reviews(org ids.OrgID) []string {
	f.t.Helper()
	var out []string
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, `SELECT v.version || ' ' || e.state || ' ' || e.priority FROM pc.waitlist_entries e
			JOIN pc.package_versions v ON v.org_id = e.org_id AND v.id = e.subject_id
			WHERE e.org_id = $1 AND e.kind = 'TOOL_REVIEW' AND e.subject_type = 'package_version'
			  AND e.deadline_at BETWEEN now() + interval '29 days' AND now() + interval '31 days'
			ORDER BY e.created_at, e.id`, org)
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
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

// TestHR177_AnImportedVersionWaitsForReview: importing a version that is
// not active opens a low-priority TOOL_REVIEW entry with a 30-day
// deadline; activating the version approves it and retiring one rejects it.
func TestHR177_AnImportedVersionWaitsForReview(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	org := newOrg(t, f.pool)
	if _, err := f.im.Import(ctx, org, "pc.mock-payments", "1.0.0", f.targets(1, "1.0.0"), f.files["1.0.0"], nil); err != nil {
		t.Fatal(err)
	}
	if got := f.reviews(org); !slices.Equal(got, []string{"1.0.0 OPEN 4"}) {
		t.Fatalf("after the import: %v", got)
	}
	if err := f.im.Transition(ctx, org, "pc.mock-payments", "1.0.0", domain.StateActive, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.im.Import(ctx, org, "pc.mock-payments", "1.1.0", f.targets(2, "1.0.0", "1.1.0"), f.files["1.1.0"], nil); err != nil {
		t.Fatal(err)
	}
	if err := f.im.Transition(ctx, org, "pc.mock-payments", "1.1.0", domain.StateRetired, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.reviews(org); !slices.Equal(got, []string{"1.0.0 APPROVED 4", "1.1.0 REJECTED 4"}) {
		t.Fatalf("after activating 1.0.0 and retiring 1.1.0: %v", got)
	}
}
