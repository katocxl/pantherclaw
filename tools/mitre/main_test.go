// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//nolint:misspell // MITRE is a proper noun (the ATT&CK and ATLAS publisher) and mitre-attack its STIX source name.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodATLAS = `format-version: 6.1.0
collection:
  version: '2026.10'
matrix:
  id: ATLAS-matrix
tactics:
  AML.TA0002:
    id: AML.TA0002
    name: Reconnaissance
    description: never copied
  AML.TA0000:
    id: AML.TA0000
    name: AI Model Access
techniques:
  AML.T0000:
    id: AML.T0000
    name: Search
    description: never copied
    platforms: [Enterprise]
  AML.T0000.000:
    id: AML.T0000.000
    name: Journals
relationships:
  ATLAS-matrix:
    sequences:
    - {source: ATLAS-matrix, target: AML.TA0002, relationship-type: sequences, position: 1}
    - {source: ATLAS-matrix, target: AML.TA0000, relationship-type: sequences, position: 2}
  AML.T0000:
    achieves:
    - {source: AML.T0000, target: AML.TA0002, relationship-type: achieves}
    - {source: AML.T0000, target: AML.TA0000, relationship-type: achieves}
  AML.T0000.000:
    achieves:
    - {source: AML.T0000.000, target: AML.TA0002, relationship-type: achieves}
    specializes:
    - {source: AML.T0000.000, target: AML.T0000, relationship-type: specializes}
`

var atlasPin = Pin{Version: "2026.10", URL: "https://example.test/a.yaml", SHA256: strings.Repeat("0", 64)}

// Covers: F974, HR-682
func TestHR682_GeneratorReadsATLASv6(t *testing.T) {
	c, err := buildATLAS([]byte(goodATLAS), atlasPin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{`"short_name": "ai-model-access"`, `"order": 2`, `"parent": "AML.T0000"`, `"reconnaissance",` + "\n        \"ai-model-access\""} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "never copied") {
		t.Error("a description reached the catalog")
	}
	if !strings.HasSuffix(got, "}\n") || strings.Contains(got, "\r") {
		t.Error("output must be LF with a trailing newline")
	}
}

// Covers: F974, HR-682
func TestHR682_GeneratorRefusesUnknownATLASShapes(t *testing.T) {
	cases := map[string]func(string) string{
		"unknown top-level key": func(s string) string { return s + "surprise: 1\n" },
		"tactic without position": func(s string) string {
			return strings.Replace(s, "    - {source: ATLAS-matrix, target: AML.TA0000, relationship-type: sequences, position: 2}\n", "", 1)
		},
		"technique without tactic": func(s string) string {
			return strings.Replace(s, "    - {source: AML.T0000.000, target: AML.TA0002, relationship-type: achieves}\n", "", 1)
		},
		"specializes a tactic": func(s string) string {
			return strings.Replace(s, "target: AML.T0000, relationship-type: specializes", "target: AML.TA0002, relationship-type: specializes", 1)
		},
		"another format version": func(s string) string { return strings.Replace(s, "6.1.0", "5.6.0", 1) },
		"another release":        func(s string) string { return strings.Replace(s, "'2026.10'", "'2026.09'", 1) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := buildATLAS([]byte(edit(goodATLAS)), atlasPin); !errors.Is(err, errShape) {
				t.Fatalf("got %v, want a shape error", err)
			}
		})
	}
}

// Covers: F974, HR-682
func TestHR682_SlugIsTheShortName(t *testing.T) {
	for in, want := range map[string]string{
		"AI Model Access":        "ai-model-access",
		"  Defense Evasion! ":    "defense-evasion",
		"ML Attack Staging/Prep": "ml-attack-staging-prep",
		"Exfiltration":           "exfiltration",
	} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

// Covers: F974, HR-682, T-304
func TestHR682_GeneratorRefusesAChangedDownload(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tools", "mitre"), 0o750); err != nil {
		t.Fatal(err)
	}
	pins := `{"attack":{"version":"20.0","url":"https://example.test/a.json","sha256":"` + strings.Repeat("a", 64) + `"},` +
		`"atlas":{"version":"2026.10","url":"https://example.test/b.yaml","sha256":"` + strings.Repeat("b", 64) + `"}}`
	if err := os.WriteFile(filepath.Join(root, "tools", "mitre", "pins.json"), []byte(pins), 0o600); err != nil {
		t.Fatal(err)
	}
	err := update(root, func(string) ([]byte, error) { return []byte("changed"), nil })
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("got %v, want a sha256 refusal", err)
	}
	if _, err := os.Stat(filepath.Join(root, "internal")); !os.IsNotExist(err) {
		t.Error("a refused download wrote output")
	}
}
