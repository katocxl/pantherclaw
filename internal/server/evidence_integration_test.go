// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// serveForTest starts cmdServe with cfgPath and returns its base URL; the
// server stops when the test ends.
func serveForTest(t *testing.T, cfgPath string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() {
		done <- cmdServe(ctx, []string{"--config", cfgPath}, &logs, noEnv, func(a string) { addrCh <- a })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	})
	select {
	case a := <-addrCh:
		return "http://" + a
	case err := <-done:
		t.Fatalf("serve exited early: %v\n%s", err, logs.String())
	case <-time.After(60 * time.Second):
		t.Fatal("server did not start")
	}
	return ""
}

func getBody(t *testing.T, url string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// TestHR194_ServerPublishesItsEvidenceKeys: a running server publishes the
// receipts, checkpoints, anchors and evidence-pack keys it created, in a
// document that pins as a trust file, and an empty revocation list.
func TestHR194_ServerPublishesItsEvidenceKeys(t *testing.T) {
	d := dbtest.New(t)
	base := serveForTest(t, testConfig(t, d, RoleAPI))
	code, b := getBody(t, base+keydocs.EvidenceKeysPath)
	if code != http.StatusOK {
		t.Fatalf("evidence-keys.json = %d %s", code, b)
	}
	trust, err := bundle.ParseEvidenceKeys(b)
	if err != nil {
		t.Fatal(err)
	}
	if trust.LogOrigin != "127.0.0.1:8080" || trust.Issuer != "http://127.0.0.1:8080" {
		t.Fatalf("log origin %q, issuer %q: want both from auth.public_url", trust.LogOrigin, trust.Issuer)
	}
	count := map[string]int{}
	for _, k := range trust.Keys {
		if k.State != bundle.StateActive {
			t.Errorf("key %s is %s", k.KID, k.State)
		}
		count[k.Purpose]++
	}
	want := map[string]int{
		bundle.PurposeReceipts: 1, bundle.PurposeCheckpoints: 1, bundle.PurposeAnchors: 1, bundle.PurposeEvidencePacks: 1,
	}
	if len(count) != len(want) {
		t.Fatalf("published purposes %v, want %v (no ML-DSA-65 key without co-signing)", count, want)
	}
	for p, n := range want {
		if count[p] != n {
			t.Errorf("%s: %d keys, want %d", p, count[p], n)
		}
	}
	code, b = getBody(t, base+keydocs.RevokedKeysPath)
	var revoked struct {
		Format string `json:"format"`
		Keys   []any  `json:"keys"`
	}
	if code != http.StatusOK || json.Unmarshal(b, &revoked) != nil || revoked.Format != keydocs.RevokedKeysFormat || len(revoked.Keys) != 0 {
		t.Fatalf("revoked-keys.json = %d %s", code, b)
	}
}

// TestIntMLDSACosignNeedsEnterprise: without an Enterprise licence the
// server refuses to start with co-signing on.
func TestIntMLDSACosignNeedsEnterprise(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI, func(c map[string]any) {
		c["evidence"] = map[string]any{"mldsa_cosign": true}
	})
	var logs bytes.Buffer
	err := cmdServe(context.Background(), []string{"--config", cfgPath}, &logs, noEnv, nil)
	if !errors.Is(err, errMLDSAEdition) {
		t.Fatalf("serve with co-signing on a Community licence: %v", err)
	}
}

// TestHR194_WorkersCheckpointEveryOrgWithTheirPublishedKey: the worker role
// checkpoints the platform org's chain (its key-creation audit entries),
// and the checkpoint verifies with the key evidence-keys.json publishes.
func TestHR194_WorkersCheckpointEveryOrgWithTheirPublishedKey(t *testing.T) {
	d := dbtest.New(t)
	base := serveForTest(t, testConfig(t, d, RoleAll, func(c map[string]any) {
		c["evidence"] = map[string]any{"log_origin": "pc.test", "checkpoint_interval": "1m"}
	}))
	p := d.AppPool(t)
	// The dispatcher ran at start, before the chainer linked the start-up
	// entries, and runs again only after a minute: once they are chained,
	// ask for a dispatch now.
	for deadline := time.Now().Add(30 * time.Second); ; {
		var n int
		if err := p.InTenantTx(context.Background(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_chain").Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the start-up entries were not chained")
		}
		time.Sleep(100 * time.Millisecond)
	}
	insert, err := jobs.NewClient(p, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insert.Insert(context.Background(), checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
		t.Fatal(err)
	}
	var signed []byte
	for deadline := time.Now().Add(30 * time.Second); signed == nil; {
		err := p.InTenantTx(context.Background(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
			row, err := dbq.New(tx).LatestCheckpoint(ctx, ids.PlatformOrg)
			if db.IsNoRows(err) {
				return nil
			}
			signed = row.Note
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if signed == nil && time.Now().After(deadline) {
			t.Fatal("no checkpoint of the platform org within 30 seconds")
		}
		time.Sleep(200 * time.Millisecond)
	}
	_, b := getBody(t, base+keydocs.EvidenceKeysPath)
	trust, err := bundle.ParseEvidenceKeys(b)
	if err != nil {
		t.Fatal(err)
	}
	origin := trust.LogOrigin + "/org/" + ids.PlatformOrg.String()
	var vs []note.Verifier
	for _, k := range trust.Keys {
		if k.Purpose == bundle.PurposeCheckpoints {
			v, err := note.NewEd25519Verifier(origin, k.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			vs = append(vs, v)
		}
	}
	if c, _, err := note.OpenCheckpoint(signed, origin, vs...); err != nil || c.Size == 0 {
		t.Fatalf("the platform org's checkpoint does not verify with the published key: %v", err)
	}
}
