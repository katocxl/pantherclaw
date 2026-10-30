// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

var updateGoldens = flag.Bool("update-goldens", false, "rewrite testdata/v1/*.golden")

// TestHR530_V1GoldensParseUnchanged freezes v1 parsing: the engine re-parses
// stored v1 JSON for running executions, so these canonical forms and
// digests may never change. The goldens were written by the code before
// the v2 format existed.
//
// Covers: F678
func TestHR530_V1GoldensParseUnchanged(t *testing.T) {
	paths, err := filepath.Glob("testdata/v1/*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("goldens: %v, %d files", err, len(paths))
	}
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			d, err := autodomain.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			c, err := d.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			digest, err := d.Digest()
			if err != nil {
				t.Fatal(err)
			}
			got := append(append(c, '\n'), hex.EncodeToString(digest)+"\n"...)
			golden := p[:len(p)-len(".yaml")] + ".golden"
			if *updateGoldens {
				if err := os.WriteFile(golden, got, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("canonical form changed:\n got %s\nwant %s", got, want)
			}
			again, err := autodomain.Parse(c)
			if err != nil {
				t.Fatalf("stored form no longer parses: %v", err)
			}
			if d2, _ := again.Digest(); !bytes.Equal(d2, digest) {
				t.Fatal("the stored form parses to another digest")
			}
		})
	}
}
