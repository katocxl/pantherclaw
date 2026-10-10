// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keydocs

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

var created = time.Date(2026, 10, 10, 12, 0, 0, 600_000_000, time.UTC)

func published(t *testing.T) []keystore.PublishedKey {
	t.Helper()
	var out []keystore.PublishedKey
	ed := func(p keys.Purpose, state keys.State, changed time.Time) {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, keystore.PublishedKey{
			KID: k.KID, Purpose: p, Algorithm: keys.AlgEdDSA, Public: k.Public, State: state, Created: created, Changed: changed,
		})
	}
	alt := func(p keys.Purpose) {
		k, _, err := keys.GenerateAltKey(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, keystore.PublishedKey{
			KID: k.KID, Purpose: p, Algorithm: p.Algorithm(), Public: k.Public, State: keys.StateActive, Created: created, Changed: created,
		})
	}
	ed(keys.PurposeReceipts, keys.StateRetiring, created.Add(90*24*time.Hour+300*time.Millisecond))
	ed(keys.PurposeReceipts, keys.StateActive, created)
	ed(keys.PurposeCheckpoints, keys.StateRevoked, created.Add(time.Hour))
	ed(keys.PurposeEvidencePacks, keys.StateActive, created)
	ed(keys.PurposePermits, keys.StateRevoked, created.Add(time.Hour))
	ed(keys.PurposeAccessTokens, keys.StateRevoked, created.Add(time.Hour))
	alt(keys.PurposeAnchors)
	alt(keys.PurposeCheckpointsPQ)
	return out
}

// TestHR194_EvidenceKeysArePublishedWithValidityAndRevocation: the document
// lists every evidence key, revoked ones included, with its validity, and
// pins as a trust file without any change but its format (G0 M7 design
// decision 13).
func TestHR194_EvidenceKeysArePublishedWithValidityAndRevocation(t *testing.T) {
	ks := published(t)
	b, err := EvidenceKeys("https://pc.example.com", "pc.example.com", ks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ParseTrust(b); err == nil {
		t.Fatal("evidence-keys.json parses as a trust file: its format must differ")
	}
	trust, err := bundle.ParseEvidenceKeys(b)
	if err != nil {
		t.Fatal(err)
	}
	if trust.Format != bundle.TrustFormat || trust.LogOrigin != "pc.example.com" || trust.Issuer != "https://pc.example.com" {
		t.Fatalf("trust = %+v", trust)
	}
	if len(trust.Keys) != 6 {
		t.Fatalf("published %d keys, want the 6 evidence keys (no permits or access-token keys)", len(trust.Keys))
	}
	byKID := map[string]bundle.TrustedKey{}
	for _, k := range trust.Keys {
		byKID[k.KID] = k
	}
	for _, k := range ks {
		got, ok := byKID[k.KID]
		if ok != (k.Purpose != keys.PurposePermits && k.Purpose != keys.PurposeAccessTokens) {
			t.Errorf("%s (%s) published = %v", k.KID, k.Purpose, ok)
			continue
		}
		if !ok {
			continue
		}
		if got.State != string(k.State) || got.Algorithm != string(k.Purpose.Algorithm()) {
			t.Errorf("%s: state %s algorithm %s", k.KID, got.State, got.Algorithm)
		}
		if !got.NotBefore.Equal(created.Truncate(time.Second)) {
			t.Errorf("%s: not_before %s, want the creation second", k.KID, got.NotBefore)
		}
		// A receipt issued in the key's first second is within its validity.
		if k.State != keys.StateRevoked && !got.ValidAt(time.Unix(created.Unix(), 0)) {
			t.Errorf("%s is not valid in the second it was created", k.KID)
		}
		switch k.State {
		case keys.StateActive:
			if !got.NotAfter.IsZero() {
				t.Errorf("%s: an active key has not_after %s", k.KID, got.NotAfter)
			}
		case keys.StateRetiring:
			if want := k.Changed.Truncate(time.Second).Add(time.Second); !got.NotAfter.Equal(want) || got.ValidAt(want.Add(time.Second)) {
				t.Errorf("%s: not_after %s, want %s and nothing later", k.KID, got.NotAfter, want)
			}
		case keys.StateRevoked:
			if got.ValidAt(created.Add(time.Minute)) {
				t.Errorf("%s: a revoked key is valid", k.KID)
			}
		}
	}
}

func TestRevokedKeysListEveryRevokedPublishedKey(t *testing.T) {
	b, err := RevokedKeys("https://pc.example.com", published(t))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Format string `json:"format"`
		Keys   []struct {
			Purpose   string    `json:"purpose"`
			RevokedAt time.Time `json:"revoked_at"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Format != RevokedKeysFormat || len(doc.Keys) != 2 {
		t.Fatalf("revoked-keys.json = %s, want the revoked checkpoints and permits keys", b)
	}
	for _, k := range doc.Keys {
		if k.Purpose == string(keys.PurposeAccessTokens) || !k.RevokedAt.Equal(created.Truncate(time.Second).Add(time.Hour+time.Second)) {
			t.Errorf("revoked key %+v", k)
		}
	}
}

func TestHandlerCachesAndFailsClosed(t *testing.T) {
	ks := published(t)
	clk := clock.NewFake(created)
	calls := 0
	var fail error
	h := New(func(_ context.Context, ps []keys.Purpose) ([]keystore.PublishedKey, error) {
		calls++
		return ks, fail
	}, "https://pc.example.com", "pc.example.com", clk, nil)
	mux := http.NewServeMux()
	h.Mount(mux)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	for range 3 {
		if rec := get(EvidenceKeysPath); rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("GET %s = %d", EvidenceKeysPath, rec.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("the key list was read %d times within the cache period", calls)
	}
	if rec := get(RevokedKeysPath); rec.Code != http.StatusOK || calls != 2 {
		t.Fatalf("GET %s = %d after %d reads", RevokedKeysPath, rec.Code, calls)
	}
	clk.Advance(cacheTTL)
	fail = errors.New("database down")
	if rec := get(EvidenceKeysPath); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET with the database down = %d, want 503", rec.Code)
	}
	fail = nil
	if rec := get(EvidenceKeysPath); rec.Code != http.StatusOK || calls != 4 {
		t.Fatalf("a failed read was cached: %d reads", calls)
	}
}
