// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package format

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

const channelOK = `{"kind":"log","description":"Ops notices","event_types":["bundle.revoked"],"settings":{"room":"ops"}}`

func TestHR796_VerifyAcceptsOnlyAnActivePinnedKey(t *testing.T) {
	pub, priv := testKey(t)
	raw := signedBundle(t, "acme", priv, "1.0.0", []byte(channelOK), "ext.acme.ops", "items/channel_template/ops.json")
	b, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	pin := PinnedKey{Publisher: "acme", KID: KID("acme", pub), PublicKey: pub}
	now := time.Now()
	if err := Verify(b, []PinnedKey{pin}, now); err != nil {
		t.Fatal(err)
	}

	otherPub, _ := testKey(t)
	other := PinnedKey{Publisher: "acme", KID: KID("acme", otherPub), PublicKey: otherPub}
	if err := Verify(b, []PinnedKey{other}, now); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("a key the org did not pin: %v", err)
	}
	if err := Verify(b, nil, now); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("no pin: %v", err)
	}
	narrow := pin
	narrow.AllowedKinds = []Kind{KindDetectionRule}
	if err := Verify(b, []PinnedKey{narrow}, now); !errors.Is(err, ErrKindNotPinned) {
		t.Fatalf("a kind the pin does not allow: %v", err)
	}

	past := now.Add(-48 * time.Hour)
	expired := mustSign(t, "acme", priv, b.ManifestBytes, past, past.Add(time.Hour))
	b.Signature = expired
	if err := Verify(b, []PinnedKey{pin}, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired signature: %v", err)
	}
	future := now.Add(time.Hour)
	early := mustSign(t, "acme", priv, b.ManifestBytes, future, future.Add(time.Hour))
	b.Signature = early
	if err := Verify(b, []PinnedKey{pin}, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("signature issued in the future: %v", err)
	}
	b.Signature = expired[:len(expired)-4] + "AAAA"
	if err := Verify(b, []PinnedKey{pin}, now); !errors.Is(err, ErrSignature) && !errors.Is(err, ErrUnpinned) {
		t.Fatalf("damaged signature: %v", err)
	}
}

func TestHR797_DecodeIsDataOnly(t *testing.T) {
	b, err := Decode(exampleBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(b.Items); got != 6 {
		t.Fatalf("%d items, want the six data kinds", got)
	}
	for _, kind := range Kinds() {
		found := false
		for _, it := range b.Items {
			found = found || it.Kind == kind
		}
		if !found {
			t.Errorf("decoded bundle has no %s", kind)
		}
	}

	script := signedBundle(t, "acme", mustKey(t), "1.0.0", []byte("#!/bin/sh\necho hi\n"), "ext.acme.ops", "items/channel_template/ops.json")
	if _, err := Decode(script); !errors.Is(err, ErrExecutable) {
		t.Fatalf("script: %v", err)
	}
	if _, err := Decode(bytes.Repeat([]byte{1}, MaxFileBytes+1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("file over 960 KiB: %v", err)
	}
	if _, err := DecodeManifest(tooManyItems(t)); !errors.Is(err, ErrLimit) {
		t.Fatalf("65 items: %v", err)
	}
	good := manifestBytes(t, "acme", "1.0.0", []byte(channelOK), "ext.acme.ops", "items/channel_template/ops.json")
	var doc map[string]any
	if err := json.Unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	doc["extra"] = true
	unknown, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManifest(unknown); !errors.Is(err, ErrFormat) {
		t.Fatalf("unknown field: %v", err)
	}
	wasm := bytes.Replace(exampleManifest(t), []byte(`"kind":"openapi"`), []byte(`"kind":"wasm"`), 1)
	if _, err := DecodeManifest(wasm); !errors.Is(err, ErrSimulator) {
		t.Fatalf("simulator kind wasm: %v", err)
	}
	if _, err := Decode(zipEntry(t, map[string][]byte{
		ManifestFile: good, SignatureFile: []byte("unsigned\n"),
	}, "items/channel_template/ops.json", []byte(channelOK), os.ModeSymlink|0o777)); !errors.Is(err, ErrPath) {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := Decode(zipEntry(t, map[string][]byte{
		ManifestFile: good, SignatureFile: []byte("unsigned\n"), "../evil.json": []byte("nope"),
	}, "", nil, 0)); !errors.Is(err, ErrPath) {
		t.Fatalf("path outside the root: %v", err)
	}
	if _, err := Decode(zipEntry(t, map[string][]byte{
		ManifestFile: good, SignatureFile: []byte("unsigned\n"),
	}, "items/channel_template/ops.json", []byte(channelOK), 0o755)); !errors.Is(err, ErrExecutable) {
		t.Fatalf("executable mode: %v", err)
	}
}

func TestHR800_RevocationStatementsComeFromAPinnedKey(t *testing.T) {
	pub, priv := testKey(t)
	signer := signerFor(t, "acme", priv)
	rev := Revocation{Publisher: "acme", Scope: ScopeKey, Kid: signer.KeyID(), IssuedAt: time.Now().Unix()}
	stmt, err := SignRevocation(signer, rev)
	if err != nil {
		t.Fatal(err)
	}
	pin := PinnedKey{Publisher: "acme", KID: signer.KeyID(), PublicKey: pub}
	if _, err := VerifyRevocation(stmt, []PinnedKey{pin}, time.Now()); err != nil {
		t.Fatal(err)
	}
	otherPub, otherPriv := testKey(t)
	other := signerFor(t, "acme", otherPriv)
	if _, err := VerifyRevocation(stmt, []PinnedKey{{Publisher: "acme", KID: other.KeyID(), PublicKey: otherPub}}, time.Now()); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("a key the org never pinned: %v", err)
	}
	rev.IssuedAt = time.Now().Add(time.Hour).Unix()
	future, err := SignRevocation(signer, rev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRevocation(future, []PinnedKey{pin}, time.Now()); !errors.Is(err, ErrRevocation) {
		t.Fatalf("statement issued in the future: %v", err)
	}
}

func TestHR801_ChannelTemplatesCarryNoSecrets(t *testing.T) {
	if _, err := DecodeChannelTemplate([]byte(channelOK)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"kind":"log","event_types":["bundle.revoked"],"settings":{"api_token":"ops"}}`,
		`{"kind":"log","event_types":["bundle.revoked"],"settings":{"room":"https://hooks.example/secret"}}`,
	} {
		if _, err := DecodeChannelTemplate([]byte(raw)); !errors.Is(err, ErrSecret) {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	_, priv := testKey(t)
	raw := signedBundle(t, "acme", priv, "1.0.0", []byte(`{"kind":"log","event_types":["bundle.revoked"],"settings":{"api_token":"ops"}}`), "ext.acme.ops", "items/channel_template/ops.json")
	if _, err := Decode(raw); !errors.Is(err, ErrSecret) {
		t.Fatalf("bundle: %v", err)
	}
}

func TestT360_AMaliciousBundleNeverDecodesAsCode(t *testing.T) {
	_, priv := testKey(t)
	raw := signedBundle(t, "acme", priv, "1.0.0", []byte("#!/bin/sh\n"), "ext.acme.ops", "items/channel_template/ops.json")
	if _, err := Decode(raw); !errors.Is(err, ErrExecutable) {
		t.Fatal(err)
	}
}

func TestT361_AStolenKeyDoesNotVerify(t *testing.T) {
	_, priv := testKey(t)
	raw := signedBundle(t, "acme", priv, "1.0.0", []byte(channelOK), "ext.acme.ops", "items/channel_template/ops.json")
	b, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	stolen, _ := testKey(t)
	pin := PinnedKey{Publisher: "acme", KID: KID("acme", stolen), PublicKey: stolen}
	if err := Verify(b, []PinnedKey{pin}, time.Now()); !errors.Is(err, ErrUnpinned) {
		t.Fatal(err)
	}
}

func TestT362_AnExpiredSignatureAndAnOlderVersionAreRefused(t *testing.T) {
	if CompareVersions("1.0.0", "1.1.0") != -1 || CompareVersions("1.0.0", "1.0.0") != 0 {
		t.Fatal("version order")
	}
	pub, priv := testKey(t)
	body := manifestBytes(t, "acme", "1.0.0", []byte(channelOK), "ext.acme.ops", "items/channel_template/ops.json")
	past := time.Now().Add(-48 * time.Hour)
	sig := mustSign(t, "acme", priv, body, past, past.Add(time.Hour))
	b, err := Decode(zipBytes(t, body, sig, "items/channel_template/ops.json", []byte(channelOK)))
	if err != nil {
		t.Fatal(err)
	}
	pin := PinnedKey{Publisher: "acme", KID: KID("acme", pub), PublicKey: pub}
	if err := Verify(b, []PinnedKey{pin}, time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
}

func TestT363_AnotherPublishersNamespaceIsRefused(t *testing.T) {
	if !ValidPublisher("examp1e") {
		t.Fatal("a look-alike publisher id must still be a publisher id, so the pin is what tells them apart")
	}
	if ValidBundleName("example", "ext.examp1e.starter") {
		t.Fatal("example's bundle name accepted a look-alike publisher")
	}
	for _, name := range []string{"ext.other.ops", "pc.acme.ops"} {
		body := []byte(channelOK)
		sum := sha256.Sum256(body)
		raw, err := json.Marshal(Manifest{
			Spec: Spec, Publisher: "acme", Name: "ext.acme.starter", Version: "1.0.0",
			Title: "Ops bundle", Summary: "A channel template.",
			Items: []ManifestItem{{
				Kind: KindChannelTemplate, Name: name, Path: "items/channel_template/ops.json",
				SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(zipBytes(t, raw, "unsigned", "items/channel_template/ops.json", body)); !errors.Is(err, ErrNamespace) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv := testKey(t)
	return priv
}

func signerFor(t *testing.T, publisher string, priv ed25519.PrivateKey) *jws.Signer {
	t.Helper()
	pub, _ := priv.Public().(ed25519.PublicKey)
	s, err := jws.NewSigner(KID(publisher, pub), priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustSign(t *testing.T, publisher string, priv ed25519.PrivateKey, manifest []byte, iat, exp time.Time) string {
	t.Helper()
	sig, err := Sign(signerFor(t, publisher, priv), manifest, iat, exp)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func manifestBytes(t *testing.T, publisher, version string, body []byte, name, path string) []byte {
	t.Helper()
	sum := sha256.Sum256(body)
	raw, err := json.Marshal(Manifest{
		Spec: Spec, Publisher: publisher, Name: "ext." + publisher + ".starter", Version: version,
		Title: "Ops bundle", Summary: "A channel template.",
		Items: []ManifestItem{{
			Kind: KindChannelTemplate, Name: name, Path: path,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManifest(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func signedBundle(t *testing.T, publisher string, priv ed25519.PrivateKey, version string, body []byte, name, path string) []byte {
	t.Helper()
	manifest := manifestBytes(t, publisher, version, body, name, path)
	now := time.Now().UTC().Truncate(time.Second)
	sig := mustSign(t, publisher, priv, manifest, now, now.Add(24*time.Hour))
	return zipBytes(t, manifest, sig, path, body)
}

func zipBytes(t *testing.T, manifest []byte, sig, path string, body []byte) []byte {
	t.Helper()
	files := map[string][]byte{ManifestFile: manifest, SignatureFile: []byte(sig + "\n")}
	if path != "" {
		files[path] = body
	}
	return zipEntry(t, files, "", nil, 0)
}

func zipEntry(t *testing.T, files map[string][]byte, special string, specialBody []byte, mode os.FileMode) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		if mode != 0 {
			h.SetMode(mode)
		} else {
			h.SetMode(0o644)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if data == nil {
			data = []byte{}
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range files {
		add(name, data, 0)
	}
	if special != "" {
		add(special, specialBody, mode)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tooManyItems(t *testing.T) []byte {
	t.Helper()
	body := []byte(channelOK)
	sum := sha256.Sum256(body)
	items := make([]ManifestItem, MaxItems+1)
	for i := range items {
		n := hex.EncodeToString([]byte{byte(i)})
		items[i] = ManifestItem{
			Kind: KindChannelTemplate, Name: "ext.acme.ops" + n,
			Path:   "items/channel_template/f" + n + ".json",
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
		}
	}
	raw, err := json.Marshal(Manifest{
		Spec: Spec, Publisher: "acme", Name: "ext.acme.starter", Version: "1.0.0",
		Title: "Too many", Summary: "Over the item limit.", Items: items,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func exampleManifest(t *testing.T) []byte {
	t.Helper()
	raw, _ := exampleParts(t)
	return raw
}

func exampleBundle(t *testing.T) []byte {
	t.Helper()
	raw, files := exampleParts(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) {
		t.Helper()
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	add(ManifestFile, raw)
	add(SignatureFile, []byte("unsigned\n"))
	for name, data := range files {
		add(name, data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func exampleParts(t *testing.T) ([]byte, map[string][]byte) {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "examples", "bundles", "ext.example.starter")
	type item struct {
		kind Kind
		name string
		path string
	}
	listed := []item{
		{KindToolPackage, "ext.example.tickets", "items/tool_package/tickets.yaml"},
		{KindOpenAPISpec, "ext.example.tickets-openapi", "items/openapi_spec/tickets.yaml"},
		{KindDetectionRule, "ext.example.comment_refusals", "items/detection_rule/comment_refusals.yaml"},
		{KindPlaybook, "ext.example.review-refusals", "items/playbook/review_refusals.yaml"},
	}
	files := map[string][]byte{}
	var items []ManifestItem
	for _, it := range listed {
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(it.path)))
		if err != nil {
			t.Fatal(err)
		}
		files[it.path] = body
		sum := sha256.Sum256(body)
		mi := ManifestItem{Kind: it.kind, Name: it.name, Path: it.path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}
		if it.kind == KindToolPackage {
			mi.Simulator = &Simulator{Kind: SimulatorOpenAPI, Spec: "items/openapi_spec/tickets.yaml"}
		}
		items = append(items, mi)
	}
	facts := []byte("provider: ext.example.facts\nfacts:\n  - name: tickets.open\n    type: boolean\n    subject_type: tickets.item\n    max_lag: 1h\n")
	channel := []byte(channelOK)
	for _, extra := range []struct {
		body []byte
		kind Kind
		name string
		path string
	}{
		{facts, KindFactsDeclaration, "ext.example.facts", "items/facts_declaration/facts.yaml"},
		{channel, KindChannelTemplate, "ext.example.ops", "items/channel_template/ops.json"},
	} {
		sum := sha256.Sum256(extra.body)
		files[extra.path] = extra.body
		items = append(items, ManifestItem{
			Kind: extra.kind, Name: extra.name, Path: extra.path,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(extra.body)),
		})
	}
	raw, err := json.Marshal(Manifest{
		Spec: Spec, Publisher: "example", Name: "ext.example.starter", Version: "1.0.0",
		Title: "Example starter bundle", Summary: "The example bundle plus a facts declaration and a channel template.",
		Items: items,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManifest(raw); err != nil {
		t.Fatal(err)
	}
	return raw, files
}
