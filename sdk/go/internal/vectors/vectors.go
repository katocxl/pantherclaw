// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Package vectors loads the shared conformance vectors in sdk/conformance
// for the Go SDK's tests.
package vectors

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Format is the vector file format this SDK runs.
const Format = "pantherclaw.conformance/v1"

// Dir returns the directory of the vectors: PANTHERCLAW_CONFORMANCE_DIR,
// or sdk/conformance next to this module.
func Dir() string {
	if d := os.Getenv("PANTHERCLAW_CONFORMANCE_DIR"); d != "" {
		return d
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "conformance")
}

// Load decodes the vector file name into v, failing the test when it is
// missing, not this format or not the group it names.
func Load(t testing.TB, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(Dir(), name)) //nolint:gosec // G304: the vector directory
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.Format != Format {
		t.Fatalf("%s: format %q, want %q (%v)", name, head.Format, Format, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}
