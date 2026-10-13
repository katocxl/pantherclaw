// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

// The conformance runner: every vector group this package covers.

func TestConformanceJCS(t *testing.T) {
	var f struct {
		Cases []struct {
			Name      string `json:"name"`
			Input     string `json:"input"`
			InputHex  string `json:"input_hex"`
			Canonical string `json:"canonical"`
			SHA256    string `json:"sha256"`
			Reject    string `json:"reject"`
		} `json:"cases"`
	}
	vectors.Load(t, "jcs.json", &f)
	for _, c := range f.Cases {
		in := []byte(c.Input)
		if c.InputHex != "" {
			var err error
			if in, err = hex.DecodeString(c.InputHex); err != nil {
				t.Fatal(err)
			}
		}
		got, err := pap.Canonical(in)
		switch {
		case c.Reject != "" && err == nil:
			t.Errorf("%s: canonicalized %q, want a refusal (%s)", c.Name, got, c.Reject)
		case c.Reject == "" && (err != nil || string(got) != c.Canonical || sum(got) != c.SHA256):
			t.Errorf("%s: %q %v, want %q", c.Name, got, err, c.Canonical)
		}
	}
}

func TestConformanceActionIR(t *testing.T) {
	var f struct {
		Cases []struct {
			Name       string `json:"name"`
			Input      string `json:"input"`
			InputHex   string `json:"input_hex"`
			Canonical  string `json:"canonical"`
			ActionHash string `json:"action_hash"`
			Reject     string `json:"reject"`
		} `json:"cases"`
	}
	vectors.Load(t, "actionir.json", &f)
	for _, c := range f.Cases {
		in := []byte(c.Input)
		if c.InputHex != "" {
			in, _ = hex.DecodeString(c.InputHex)
		}
		p, err := pap.ParseAction(in)
		switch {
		case c.Reject != "" && err == nil:
			t.Errorf("%s: parsed, want a refusal (%s)", c.Name, c.Reject)
		case c.Reject == "" && (err != nil || p.Hash != c.ActionHash || string(p.Canonical) != c.Canonical):
			t.Errorf("%s: %s %v, want %s", c.Name, p.Hash, err, c.ActionHash)
		}
	}
}

func TestConformanceApprovalBindings(t *testing.T) {
	var f struct {
		Cases []struct {
			Name      string         `json:"name"`
			Input     jsontext.Value `json:"input"`
			Canonical string         `json:"canonical"`
			Binding   string         `json:"binding"`
		} `json:"cases"`
	}
	vectors.Load(t, "approval_bindings.json", &f)
	for _, c := range f.Cases {
		got, err := pap.Canonical(c.Input)
		s := sha256.Sum256(got)
		if err != nil || string(got) != c.Canonical || base64.RawURLEncoding.EncodeToString(s[:]) != c.Binding {
			t.Errorf("%s: %s %v", c.Name, got, err)
		}
	}
}

func TestConformanceKeyFiles(t *testing.T) {
	var f struct {
		Cases []struct {
			Name       string `json:"name"`
			File       string `json:"file"`
			Reject     string `json:"reject"`
			PublicX    string `json:"public_x"`
			JKT        string `json:"jkt"`
			Identifier string `json:"identifier"`
			Server     string `json:"server"`
			RunID      string `json:"run_id"`
		} `json:"cases"`
	}
	vectors.Load(t, "key_files.json", &f)
	for _, c := range f.Cases {
		path := filepath.Join(t.TempDir(), "key.json")
		if err := os.WriteFile(path, []byte(c.File), 0o600); err != nil {
			t.Fatal(err)
		}
		k, err := pap.ReadKeyFile(path)
		if c.Reject != "" {
			if err == nil {
				t.Errorf("%s: read, want a refusal", c.Name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		priv, _ := k.Key()
		pub, _ := priv.Public().(ed25519.PublicKey)
		out, _ := k.Marshal()
		if base64.RawURLEncoding.EncodeToString(pub) != c.PublicX || pap.Thumbprint(pub) != c.JKT || k.Identifier != c.Identifier ||
			k.Server != c.Server || k.RunID != c.RunID || string(out) != c.File {
			t.Errorf("%s: read %+v, writes %q", c.Name, k, out)
		}
		again := filepath.Join(t.TempDir(), "again.json")
		if err := pap.WriteKeyFile(again, k, false); err != nil {
			t.Fatal(err)
		}
		if err := pap.WriteKeyFile(again, k, false); err == nil {
			t.Errorf("%s: an existing key file was overwritten", c.Name)
		}
	}
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
