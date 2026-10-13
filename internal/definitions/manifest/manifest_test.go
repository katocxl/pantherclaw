// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// MockPaymentsFile is the reference package, relative to this directory.
const mockPaymentsFile = "../../../packages/mock-payments/package.yaml"

func readMock(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile(mockPaymentsFile)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the golden file; a mapping or definition change must be deliberate (HR-124).\n got: %s\nwant: %s", name, got, want)
	}
}

// TestHR124_MockPaymentsGolden pins the reviewed meaning of the reference
// package: its canonical form and every definition digest.
func TestHR124_MockPaymentsGolden(t *testing.T) {
	raw := readMock(t)
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "mock-payments.canonical.json", append(canon, '\n'))
	var digests strings.Builder
	for _, d := range p.Definitions {
		fmt.Fprintf(&digests, "%s %s\n", d.Operation, d.Digest)
	}
	golden(t, "mock-payments.digests", []byte(digests.String()))
	// Two definitions agents call, two internal reads for the verifier's
	// lookup and the target log (G0 M7), and the connection test's read (G0
	// M8).
	if p.Name != "pc.mock-payments" || p.Version != "1.0.0" || len(p.Definitions) != 5 || len(p.TargetLogs) != 1 {
		t.Fatalf("decoded %s %s with %d definitions", p.Name, p.Version, len(p.Definitions))
	}
}

func TestDigestCoversMappings(t *testing.T) {
	raw := readMock(t)
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte("reason: input.reason"), []byte("reason: input.why"), 1)
	q, err := Decode(changed)
	if err != nil {
		t.Fatal(err)
	}
	if p.Definitions[0].Digest == q.Definitions[0].Digest {
		t.Fatal("a mapping change must change the definition digest")
	}
	if p.Definitions[1].Digest != q.Definitions[1].Digest {
		t.Fatal("an unrelated definition's digest must not change")
	}
	if FileDigest(raw) == FileDigest(changed) {
		t.Fatal("the file digest covers every byte")
	}
	// Formatting, comments and key order do not change a definition's meaning.
	reformatted := bytes.Replace(raw, []byte("summary: Read one refund\n"), []byte("summary: 'Read one refund'   # quoted\n"), 1)
	r, err := Decode(reformatted)
	if err != nil {
		t.Fatal(err)
	}
	if r.Definitions[1].Digest != p.Definitions[1].Digest {
		t.Fatal("YAML formatting must not change the definition digest")
	}
}

const minimal = "format: 1\nname: pc.x\n"

func TestHR100_ManifestIsStrictYAML(t *testing.T) {
	deep := strings.Repeat("- ", MaxDepth+1) + "x"
	for name, doc := range map[string]string{
		"duplicate key":    minimal + "name: pc.y\n",
		"anchor":           minimal + "summary: &s hi\n",
		"alias":            "a: &s hi\nb: *s\n",
		"merge key":        "base: &b {x: 1}\nother:\n  <<: *b\n",
		"merge key only":   minimal + "other:\n  <<: {x: 1}\n",
		"explicit str tag": minimal + "summary: !!str hi\n",
		"custom tag":       minimal + "summary: !secret hi\n",
		"binary":           minimal + "summary: !!binary aGk=\n",
		"float":            minimal + "x: 1.5\n",
		"exponent":         minimal + "x: 1e3\n",
		"infinity":         minimal + "x: .inf\n",
		"hex int":          minimal + "x: 0x10\n",
		"octal int":        minimal + "x: 0o17\n",
		"null":             minimal + "summary: ~\n",
		"empty value":      minimal + "summary:\n",
		"yaml 1.1 bool":    minimal + "x: True\n",
		"two documents":    minimal + "---\n" + minimal,
		"non-string key":   minimal + "1: one\n",
		"complex key":      minimal + "? [a, b]\n: c\n",
		"top-level list":   "- format: 1\n",
		"top-level scalar": "hello\n",
		"byte order mark":  "\xef\xbb\xbf" + minimal,
		"NUL":              minimal + "summary: a\x00b\n",
		"invalid UTF-8":    minimal + "summary: \xff\n",
		"too deep":         "x:\n" + deep + "\n",
		"empty":            "",
	} {
		_, err := ToJSON([]byte(doc))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
		t.Logf("%s: %v", name, err)
	}
	got, err := ToJSON([]byte(minimal + "list: [a, \"b\"]\nn: -3\nok: true\nday: 2027-10-08\nblock: |\n  two\n  lines\n"))
	if want := `{"format":1,"name":"pc.x","list":["a","b"],"n":-3,"ok":true,"day":"2027-10-08","block":"two\nlines\n"}`; err != nil || string(got) != want {
		t.Fatalf("positive control: %s, %v; want %s", got, err, want)
	}
	for name, doc := range map[string]string{
		"unknown field":       minimal + "extra: true\n",
		"wrong type for bool": minimal + "definitions: [{operation: a.b, material: yes}]\n",
		"number for a string": minimal + "version: 1\n",
	} {
		if _, err := Decode([]byte(doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := Decode(make([]byte, MaxBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversized file: %v", err)
	}
}

// TestHR123_VersionIsNeverANumber shows that YAML typing cannot
// silently turn a version into a number.
func TestHR123_VersionIsNeverANumber(t *testing.T) {
	raw := bytes.Replace(readMock(t), []byte("version: 1.0.0"), []byte("version: 1.0"), 1)
	if _, err := Decode(raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("version 1.0 (a YAML float): %v", err)
	}
}

func FuzzManifest(f *testing.F) {
	f.Add(readMock(f))
	f.Add([]byte(minimal))
	f.Add([]byte("a: [1, 2, {b: c}]\n"))
	f.Add([]byte("a: &x 1\nb: *x\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		canon, err := Canonical(raw)
		if err != nil {
			return
		}
		// Canonical JSON is itself an accepted package file whose canonical
		// form is unchanged: one meaning, one byte string.
		again, err := Canonical(canon)
		if err != nil {
			t.Fatalf("canonical form rejected: %v\n%s", err, canon)
		}
		if !bytes.Equal(canon, again) {
			t.Fatalf("canonical form is not a fixed point:\n%s\n%s", canon, again)
		}
		_, _ = Decode(raw)
	})
}
