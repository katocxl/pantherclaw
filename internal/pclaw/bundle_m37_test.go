// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/bundles/format"
)

// TestHR803_BundleCommandsNeverExecuteBundleContent: lint, build, sign,
// verify and inspect only decode and sign, a symlink is not followed, a
// fingerprint without a key is refused, and the private key file is mode
// 0600 (G0 M37 D1084, T-360).
func TestHR803_BundleCommandsNeverExecuteBundleContent(t *testing.T) {
	ctx := context.Background()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	a := &app{stdout: out, stderr: errb}
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := bundleInit(ctx, a, []string{"--publisher", "acme", "--name", "ext.acme.starter", dir}); err != nil {
		t.Fatal(err)
	}
	itemDir := filepath.Join(dir, "items", "channel_template")
	if err := os.MkdirAll(itemDir, 0o750); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"kind":"log","description":"Ops notices","event_types":["bundle.revoked"],"settings":{"room":"ops"}}`)
	if err := os.WriteFile(filepath.Join(itemDir, "ops.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{
  "spec": "pc-bundle/1",
  "publisher": "acme",
  "name": "ext.acme.starter",
  "version": "0.1.0",
  "title": "Ops bundle",
  "summary": "A channel template.",
  "items": [
    {"kind": "channel_template", "name": "ext.acme.ops", "path": "items/channel_template/ops.json", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 1}
  ]
}
`
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	built := filepath.Join(t.TempDir(), "starter.pcbundle")
	out.Reset()
	if err := bundleBuild(ctx, a, []string{dir, "--out", built}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "unsigned") {
		t.Fatalf("build: %s", out.String())
	}
	out.Reset()
	if err := bundleLint(ctx, a, []string{built}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing was executed") {
		t.Fatalf("lint: %s", out.String())
	}

	key := filepath.Join(t.TempDir(), "publisher.key")
	pp := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(pp, []byte("a-long-passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := createPublisherKey(ctx, a, []string{"--publisher", "acme", "--out", key, "--passphrase-file", pp}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %o, want 0600", st.Mode().Perm())
	}
	fp := regexp.MustCompile(`fingerprint: ([0-9a-f]{64})`).FindStringSubmatch(out.String())
	if fp == nil {
		t.Fatalf("no fingerprint in %s", out.String())
	}
	signed := filepath.Join(t.TempDir(), "signed.pcbundle")
	before, err := os.ReadFile(built)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundleSign(ctx, a, []string{built, "--key", key, "--passphrase-file", pp, "--out", signed}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(built)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("sign --out replaced the input file")
	}
	out.Reset()
	if err := bundleVerify(ctx, a, []string{signed, "--public-key", key + ".pub", "--fingerprint", fp[1]}); err != nil {
		t.Fatal(err)
	}
	if err := bundleVerify(ctx, a, []string{signed, "--fingerprint", fp[1]}); err == nil || !strings.Contains(err.Error(), "fingerprint alone") {
		t.Fatalf("fingerprint without a key: %v", err)
	}
	if err := bundleVerify(ctx, a, []string{signed, "--public-key", key + ".pub", "--fingerprint", strings.Repeat("ab", 32)}); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("mismatched fingerprint: %v", err)
	}
	if err := pinPublisherKey(ctx, a, []string{"--publisher", "acme", "--fingerprint", fp[1]}); err == nil || !strings.Contains(err.Error(), "fingerprint alone") {
		t.Fatalf("pin with a fingerprint and no key: %v", err)
	}
	if err := pinPublisherKey(ctx, a, []string{"--publisher", "acme", "--key-file", key + ".pub", "--fingerprint", strings.Repeat("ab", 32)}); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("pin with a mismatched fingerprint: %v", err)
	}
	out.Reset()
	if err := bundleInspect(ctx, a, []string{signed}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ext.acme.starter") {
		t.Fatalf("inspect: %s", out.String())
	}

	if err := os.WriteFile(filepath.Join(itemDir, "ops.json"), []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := bundleLint(ctx, a, []string{dir}); err == nil || !strings.Contains(err.Error(), "BUNDLE_EXECUTABLE") {
		t.Fatalf("lint of a script: %v", err)
	}
	link := filepath.Join(itemDir, "linked.json")
	if err := os.Symlink(filepath.Join(itemDir, "ops.json"), link); err != nil {
		t.Logf("symlink not created (%v); the format test still refuses a symlink entry", err)
	} else if err := os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(strings.Replace(manifest,
		"items/channel_template/ops.json", "items/channel_template/linked.json", 1)), 0o644); err != nil {
		t.Fatal(err)
	} else if err := bundleLint(ctx, a, []string{dir}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("lint followed a symlink: %v", err)
	}

	big := filepath.Join(t.TempDir(), "big.pcbundle")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), format.MaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bundleInstall(ctx, a, []string{big}); err == nil || (!strings.Contains(err.Error(), "960") && !strings.Contains(err.Error(), "at most")) {
		t.Fatalf("install over 960 KiB: %v", err)
	}
}
