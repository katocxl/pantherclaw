// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pack_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

var made = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// TestPackZIPIsDeterministicAndReadsBack: the same files give the same
// bytes, in path order, with the manifest last; Read returns every file.
func TestPackZIPIsDeterministicAndReadsBack(t *testing.T) {
	files := []pack.File{{Path: "versions.json", Data: []byte(`{}`)}, {Path: "transactions/a.json", Data: []byte(`{"a":1}`)}}
	a, err := pack.Write(files, "h.p.s", nil, made)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pack.Write([]pack.File{files[1], files[0]}, "h.p.s", nil, made)
	if !bytes.Equal(a, b) {
		t.Fatal("the same files gave different packs")
	}
	got, err := pack.Read(a)
	if err != nil || len(got) != 3 || string(got["transactions/a.json"]) != `{"a":1}` || string(got[pack.ManifestPath]) != "h.p.s" {
		t.Fatalf("Read = %v, %v", got, err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(a), int64(len(a)))
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "transactions/a.json,versions.json,manifest.jws" {
		t.Fatalf("order %v", names)
	}
}

// TestPackRefusesUnsafeNamesAndOversizedFiles: names that climb, are
// absolute, use backslashes or upper case, repeat, or files beyond the
// limits are refused when writing and when reading (a pack is untrusted
// input to `pclaw verify`).
func TestPackRefusesUnsafeNamesAndOversizedFiles(t *testing.T) {
	for _, name := range []string{"../x.json", "/x.json", `a\b.json`, "A.json", "a//b.json", "", "a/../b", ".hidden"} {
		if pack.ValidPath(name) {
			t.Errorf("%q is accepted", name)
		}
		if _, err := pack.Write([]pack.File{{Path: name, Data: []byte("{}")}}, "h.p.s", nil, made); err == nil {
			t.Errorf("Write accepted %q", name)
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(name)
		if err == nil {
			_, _ = w.Write([]byte("{}"))
		}
		_ = zw.Close()
		if _, err := pack.Read(buf.Bytes()); err == nil {
			t.Errorf("Read accepted %q", name)
		}
	}
	if _, err := pack.Write([]pack.File{{Path: "a.json", Data: []byte("1")}, {Path: "a.json", Data: []byte("2")}}, "h.p.s", nil, made); err == nil {
		t.Error("a repeated path was written")
	}
	big := bytes.Repeat([]byte{'0'}, pack.MaxFileBytes+1)
	if _, err := pack.Write([]pack.File{{Path: "big.json", Data: big}}, "h.p.s", nil, made); err == nil {
		t.Error("an oversized file was written")
	}
	// A highly compressible file beyond the per-file limit is refused when
	// read (a ZIP bomb stops at the limit).
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("bomb.json")
	_, _ = w.Write(big)
	_ = zw.Close()
	if _, err := pack.Read(buf.Bytes()); !errors.Is(err, pack.ErrInvalid) {
		t.Fatalf("a ZIP bomb: %v", err)
	}
	if _, err := pack.Read([]byte("not a zip")); !errors.Is(err, pack.ErrInvalid) {
		t.Fatal("garbage was read as a pack")
	}
}

// FuzzPack: a pack is untrusted input to `pclaw verify`; reading it and its
// manifest never panics, and whatever reads back keeps to the limits.
func FuzzPack(f *testing.F) {
	good, err := pack.Write([]pack.File{{Path: "transactions/a.json", Data: []byte(`{"a":1}`)}}, "e30.e30.c2ln", nil, made)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, b []byte) {
		files, err := pack.Read(b)
		if err != nil {
			return
		}
		for name, data := range files {
			if !pack.ValidPath(name) || len(data) > pack.MaxFileBytes {
				t.Fatalf("Read returned %q of %d bytes", name, len(data))
			}
		}
		if s, err := pack.ParseJWS(string(files[pack.ManifestPath])); err == nil {
			_, _ = pack.DecodeManifest(s.Payload)
		}
	})
}

// TestPackManifestJWS: ParseJWS accepts only an EdDSA pap-pack+jwt header
// with a kid; the signature verifies with the signer's key only, and over
// the exact payload.
func TestPackManifestJWS(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, _ := jws.NewSigner("evidence-packs-1", priv)
	compact, err := s.Sign(pack.JWSType, []byte(`{"format":"pantherclaw.pack/v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pack.ParseJWS(compact)
	if err != nil || signed.Kid != "evidence-packs-1" || !signed.Verify(pub) {
		t.Fatalf("ParseJWS = %+v, %v", signed, err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if signed.Verify(other) {
		t.Fatal("another key verifies the manifest")
	}
	receipt, _ := s.Sign("pap-decision+jwt", []byte(`{}`))
	if _, err := pack.ParseJWS(receipt); err == nil {
		t.Fatal("a receipt was taken for a manifest")
	}
	parts := strings.Split(compact, ".")
	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "fQ." + parts[2]
	if s2, err := pack.ParseJWS(tampered); err == nil && s2.Verify(pub) {
		t.Fatal("a changed payload verifies")
	}
}
