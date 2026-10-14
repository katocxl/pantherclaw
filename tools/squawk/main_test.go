// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestUpSectionBlanksDown(t *testing.T) {
	src := "-- +goose Up\nCREATE TABLE pc.t (id uuid);\n\n-- +goose Down\nDROP TABLE pc.t;\n"
	want := "-- +goose Up\nCREATE TABLE pc.t (id uuid);\n\n\n\n"
	if got := string(upSection([]byte(src))); got != want {
		t.Fatalf("upSection = %q, want %q", got, want)
	}
	// A file without a Down section is linted whole.
	if got := string(upSection([]byte("-- +goose Up\nSELECT 1;"))); got != "-- +goose Up\nSELECT 1;" {
		t.Fatalf("upSection without Down = %q", got)
	}
}

func TestMigrationsAfterBaseline(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"00098_old.sql", "00099_new.sql", "00100_newer.sql", "migrations.go", "00101_Bad-Name.sql"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := migrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"00099_new.sql", "00100_newer.sql"}; !slices.Equal(got, want) {
		t.Fatalf("migrations = %v, want %v", got, want)
	}
}

func TestEveryPinIsADigest(t *testing.T) {
	for platform, a := range assets {
		if len(a.sha256) != 64 || a.name == "" {
			t.Errorf("%s: bad pin %+v", platform, a)
		}
	}
}
