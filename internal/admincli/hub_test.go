// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package admincli

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/hub/domain"
)

// Covers: F847

func TestHubBuildOfTheSeedContent(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) }
	keys := t.TempDir()
	var out, errb bytes.Buffer
	if code := Run([]string{"keygen", "--purpose", "hub-dev", "--out-dir", keys}, &out, &errb, clock); code != exitOK {
		t.Fatalf("keygen = %d: %s", code, errb.String())
	}
	key, pub := filepath.Join(keys, "hub-dev.key"), filepath.Join(keys, "hub-dev.pub.json")
	dir := filepath.Join(t.TempDir(), "site")
	build := []string{"hub", "build", "--dir", "../../hub", "--out", dir, "--key", key, "--version", "7", "--expires-days", "30"}
	out.Reset()
	if code := Run(build, &out, &errb, clock); code != exitOK {
		t.Fatalf("build = %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "development Hub key") {
		t.Fatalf("no development notice: %s", out.String())
	}
	b, err := os.ReadFile(pub) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal(err)
	}
	roots, err := domain.ParseDevKey(b)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(dir, "index.jws")) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal(err)
	}
	v, err := domain.Verify(string(doc), roots, clock())
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != 7 || len(v.Items) == 0 || v.ExpiresAt != "2026-11-30T12:00:00Z" {
		t.Fatalf("index %+v", v.Index)
	}
	for _, e := range v.Items {
		raw, err := os.ReadFile(filepath.Join(dir, "items", e.SHA256+".json")) //nolint:gosec // G304: test path
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := v.Match(raw); err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatal(err)
		}
		if _, tests := item["tests"]; tests {
			t.Fatalf("%s published its tests", e.Name)
		}
	}
	// The directory is not rewritten: the next index goes to a new one.
	if code := Run(build, &out, &errb, clock); code != exitError {
		t.Fatalf("second build = %d", code)
	}
}

func TestHubBuildRefusals(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) }
	keys := t.TempDir()
	var out, errb bytes.Buffer
	if code := Run([]string{"keygen", "--purpose", "packages", "--out-dir", keys}, &out, &errb, clock); code != exitOK {
		t.Fatal(errb.String())
	}
	if code := Run([]string{"keygen", "--purpose", "hub-dev", "--out-dir", keys}, &out, &errb, clock); code != exitOK {
		t.Fatal(errb.String())
	}
	dir := filepath.Join(t.TempDir(), "site")
	// A package root never signs a Hub index (HR-560).
	errb.Reset()
	code := Run([]string{"hub", "build", "--dir", "../../hub", "--out", dir, "--key", filepath.Join(keys, "packages-root.key"), "--version", "1"}, &out, &errb, clock)
	if code != exitError || !strings.Contains(errb.String(), "not a hub root") {
		t.Fatalf("package key = %d: %s", code, errb.String())
	}
	key := filepath.Join(keys, "hub-dev.key")
	if code := Run([]string{"hub", "build", "--dir", "../../hub", "--out", dir, "--key", key}, &out, &errb, clock); code != exitUsage {
		t.Fatalf("no version = %d", code)
	}
	errb.Reset()
	code = Run([]string{"hub", "build", "--dir", "../../hub", "--out", dir, "--key", key, "--version", "1", "--expires-days", "181"}, &out, &errb, clock)
	if code != exitError || !strings.Contains(errb.String(), "--expires-days") {
		t.Fatalf("too long = %d: %s", code, errb.String())
	}
}
