// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHR802_TheMarketplaceListsAndVouchesForNobody: a build is static HTML
// with the notice on every page, no script, form or button, and a listing
// that is not https or whose fingerprint does not match its key is refused
// (G0 M37 D1085, T-364).
func TestHR802_TheMarketplaceListsAndVouchesForNobody(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	fp := hex.EncodeToString(sum[:])
	root := t.TempDir()
	writeListing(t, root, "acme", Listing{
		Publisher: "acme", DisplayName: "Acme Tools", Homepage: "https://acme.example/",
		Keys: []ListedKey{{PublicKey: base64.RawURLEncoding.EncodeToString(pub), Fingerprint: fp}},
		Bundles: []ListedBundle{{
			Name: "ext.acme.starter", Version: "1.0.0", URL: "https://acme.example/starter.pcbundle",
			SHA256: strings.Repeat("ab", 32), Summary: "A starter bundle.",
		}},
	})
	out := filepath.Join(t.TempDir(), "dist")
	if err := build(root, "", out); err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"index.html", filepath.Join("publishers", "acme.html")} {
		b, err := os.ReadFile(filepath.Join(out, page))
		if err != nil {
			t.Fatal(err)
		}
		html := string(b)
		for _, want := range []string{"not an endorsement", "pin that publisher's key", "takes no payment", fp} {
			if !strings.Contains(html, want) {
				t.Errorf("%s missing %q", page, want)
			}
		}
		for _, ban := range []string{"<script", "<form", "<button"} {
			if strings.Contains(strings.ToLower(html), ban) {
				t.Errorf("%s contains %s", page, ban)
			}
		}
	}
	pubFile := filepath.Join(out, "publishers", "acme-"+fp[:16]+".pub")
	got, err := os.ReadFile(pubFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), base64.RawURLEncoding.EncodeToString(pub)) {
		t.Fatalf("the .pub download is not the listing's key: %s", got)
	}
	page, err := os.ReadFile(filepath.Join(out, "publishers", "acme.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "pclaw publisher pin") || !strings.Contains(string(page), "pclaw bundle install") {
		t.Fatal("the page does not show the pclaw commands")
	}

	bad := Listing{
		Publisher: "acme", DisplayName: "Acme Tools", Homepage: "http://acme.example/",
		Keys: []ListedKey{{PublicKey: base64.RawURLEncoding.EncodeToString(pub), Fingerprint: fp}},
	}
	writeListing(t, root, "acme", bad)
	if err := build(root, "", filepath.Join(t.TempDir(), "out2")); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http homepage: %v", err)
	}
	bad.Homepage = "https://acme.example/"
	bad.Keys[0].Fingerprint = strings.Repeat("ab", 32)
	writeListing(t, root, "acme", bad)
	if err := build(root, "", filepath.Join(t.TempDir(), "out3")); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched fingerprint: %v", err)
	}
}

func TestT364_ASpoofedListingIsRefused(t *testing.T) {
	root := t.TempDir()
	writeListing(t, root, "acme", Listing{
		Publisher: "acme", DisplayName: "Acme", Homepage: "http://attacker.example/",
		Keys: []ListedKey{{PublicKey: base64.RawURLEncoding.EncodeToString(bytes32(t)), Fingerprint: strings.Repeat("aa", 32)}},
	})
	if err := build(root, "", filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("an http listing was built")
	}
}

func writeListing(t *testing.T, root, publisher string, l Listing) {
	t.Helper()
	dir := filepath.Join(root, "marketplace", "listings")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, publisher+".json"), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bytes32(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, ed25519.PublicKeySize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
