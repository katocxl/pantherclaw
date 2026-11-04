// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//nolint:misspell // MITRE is a proper noun (the ATT&CK and ATLAS publisher), and MITRE_MAPPING.md a path.
package mapdoc_test

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapdoc"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
)

var update = flag.Bool("update", false, "rewrite docs/security/MITRE_MAPPING.md")

const docPath = "../../../docs/security/MITRE_MAPPING.md"

// TestMITREMappingDocIsCurrent: the checked-in MITRE_MAPPING.md is what
// the code declares, so the public mapping never drifts from it. Run
// `task docs:mitre` (this test with -update) after changing a mapping.
// Covers: F974
func TestMITREMappingDocIsCurrent(t *testing.T) {
	want := mapdoc.Render(mapset.Load())
	if *update {
		if err := os.WriteFile(docPath, want, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/security/MITRE_MAPPING.md is stale: task docs:mitre")
	}
}

// TestRenderListsEveryMatrixTechnique: each matrix cell of both frameworks
// appears, and the rendering is stable.
// Covers: F974
func TestRenderListsEveryMatrixTechnique(t *testing.T) {
	s := mapset.Load()
	doc := mapdoc.Render(s)
	if !bytes.Equal(doc, mapdoc.Render(s)) {
		t.Fatal("Render is not stable")
	}
	text := string(doc)
	for _, f := range catalog.Frameworks() {
		for _, tech := range catalog.Load(f).Matrix() {
			if !strings.Contains(text, "| ["+tech.ID+"](") {
				t.Errorf("%s %s is missing", f, tech.ID)
			}
		}
	}
	if strings.Contains(text, "| Not placed |") {
		t.Error("a technique has no place; the closure test should have failed")
	}
	if !strings.Contains(text, "It is not a score or a guarantee.") {
		t.Error("the statement is missing")
	}
}
