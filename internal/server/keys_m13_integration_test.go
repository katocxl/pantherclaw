// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func runKeys(t *testing.T, cfgPath string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), append(append([]string{"keys"}, args...), "--config", cfgPath), &out, &errb, noEnv)
	return code, out.String(), errb.String()
}

// loadRegistry loads the platform signing keys with the test config's KEK.
func loadRegistry(t *testing.T, d *dbtest.DB, cfgPath string) *keys.Registry {
	t.Helper()
	cfg := DefaultConfig()
	if err := config.Load(&cfg, cfgPath, noEnv); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(context.Background(), d.AppPool(t), kp, reg); err != nil {
		t.Fatal(err)
	}
	return reg
}

func activeKID(t *testing.T, reg *keys.Registry, p keys.Purpose) string {
	t.Helper()
	ks := reg.Keys(p)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		t.Fatalf("%s has no active key", p)
	}
	return ks[0].KID
}

// TestHR372_RotateReceiptsAndEvidenceKeepEarlierKeysVerifying: both rotate
// commands change nothing without --confirm; with it each purpose gets a
// new active key, the previous one retires (state changed now), stays in
// the JWKS or evidence-keys document and still verifies what it signed;
// the anchors key is never rotated; every change is audited with the
// operator as the actor.
func TestHR372_RotateReceiptsAndEvidenceKeepEarlierKeysVerifying(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI)
	ctx := context.Background()
	before := loadRegistry(t, d, cfgPath)
	oldKIDs := map[keys.Purpose]string{}
	for _, p := range []keys.Purpose{keys.PurposeReceipts, keys.PurposeCheckpoints, keys.PurposeEvidencePacks} {
		oldKIDs[p] = activeKID(t, before, p)
	}
	anchors, err := keystore.PublishedKeys(ctx, d.AppPool(t), []keys.Purpose{keys.PurposeAnchors})
	if err != nil || len(anchors) != 1 {
		t.Fatalf("anchors keys = %v, %v", anchors, err)
	}
	oldKIDs[keys.PurposeAnchors] = anchors[0].KID
	signer, err := before.Signer(keys.PurposeReceipts)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signer.Sign("pap-decision+jwt", []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}

	for _, cmd := range []string{"rotate-receipts", "rotate-evidence"} {
		if code, _, errs := runKeys(t, cfgPath, cmd); code != 1 || !strings.Contains(errs, "--confirm") {
			t.Fatalf("%s without --confirm = %d %s", cmd, code, errs)
		}
	}
	if after := loadRegistry(t, d, cfgPath); activeKID(t, after, keys.PurposeReceipts) != oldKIDs[keys.PurposeReceipts] {
		t.Fatal("a rotation without --confirm changed the receipts key")
	}

	start := time.Now().Add(-time.Minute)
	for _, cmd := range []string{"rotate-receipts", "rotate-evidence"} {
		if code, out, errs := runKeys(t, cfgPath, cmd, "--confirm"); code != 0 || !strings.Contains(out, "restart every server instance") {
			t.Fatalf("%s = %d %s %s", cmd, code, out, errs)
		}
	}
	after := loadRegistry(t, d, cfgPath)
	published, err := keystore.PublishedKeys(ctx, d.AppPool(t), []keys.Purpose{
		keys.PurposeReceipts, keys.PurposeCheckpoints, keys.PurposeEvidencePacks, keys.PurposeAnchors,
	})
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]keystore.PublishedKey{}
	for _, k := range published {
		state[k.KID] = k
	}
	for p, old := range oldKIDs {
		if p == keys.PurposeAnchors {
			if state[old].State != keys.StateActive {
				t.Errorf("the anchors key was rotated: %s is %s", old, state[old].State)
			}
			continue
		}
		if now := activeKID(t, after, p); now == old {
			t.Errorf("%s: active key unchanged", p)
		}
		k := state[old]
		if k.State != keys.StateRetiring || k.Changed.Before(start) {
			t.Errorf("%s: previous key %s is %s since %v, want RETIRING from now", p, old, k.State, k.Changed)
		}
		if !slices.ContainsFunc(after.Keys(p), func(s keys.SigningKey) bool { return s.KID == old }) {
			t.Errorf("%s: previous key no longer loaded for verification", p)
		}
	}
	v, err := after.Verifier(keys.PurposeReceipts, "pap-decision+jwt")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Verify(receipt); err != nil {
		t.Errorf("a receipt signed by the retired key no longer verifies: %v", err)
	}
	jwks, err := after.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jwks), oldKIDs[keys.PurposeReceipts]) || !strings.Contains(string(jwks), activeKID(t, after, keys.PurposeReceipts)) {
		t.Errorf("JWKS lacks the old or the new receipts key: %s", jwks)
	}
	mux := http.NewServeMux()
	pool := d.AppPool(t)
	keydocs.New(func(ctx context.Context, ps []keys.Purpose) ([]keystore.PublishedKey, error) {
		return keystore.PublishedKeys(ctx, pool, ps)
	}, "https://pc.example", "pc.example/log", clock.System{}, pclog.Discard()).Mount(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, keydocs.EvidenceKeysPath, nil))
	doc, _ := io.ReadAll(rec.Body)
	for _, p := range []keys.Purpose{keys.PurposeCheckpoints, keys.PurposeEvidencePacks} {
		if !strings.Contains(string(doc), oldKIDs[p]) || !strings.Contains(string(doc), activeKID(t, after, p)) {
			t.Errorf("evidence-keys.json lacks the old or the new %s key: %s", p, doc)
		}
	}

	var retiring, operator int
	d.AdminQueryRow(t, `SELECT count(*), count(*) FILTER (WHERE actor_type = 'operator' AND actor_id LIKE 'cli:%')
		FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.signing_key.retiring'`, []any{ids.PlatformOrg}, &retiring, &operator)
	if retiring != 3 || operator != 3 {
		t.Errorf("retiring audits = %d (%d by the operator), want 3", retiring, operator)
	}
}
