// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package gen_test generates the cross-language SDK conformance vectors in
// sdk/conformance from the real Go implementation, with fixed test keys
// (G0 M8 track S, S1), and fails when the implementation and the vectors
// disagree. `task sdk:vectors`, which runs
//
//	go test ./internal/conformance/gen -run TestConformanceVectors -update
//
// rewrites them. Without -update the test is the drift check: every group
// is rebuilt and compared byte for byte.
package gen_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"testing/cryptotest"
	"testing/synctest"
)

var update = flag.Bool("update", false, "rewrite the vectors in sdk/conformance")

// Format names the vector file format; every file carries it.
const Format = "pantherclaw.conformance/v1"

// dir is where the vectors live.
var dir = filepath.Join("..", "..", "..", "sdk", "conformance")

// Fixed identities shared by every group (the ids of the mapping goldens).
const (
	orgID      = "01920000-0000-7000-8000-000000000001"
	runID      = "01920000-0000-7000-8000-000000000003"
	instanceID = "01920000-0000-7000-8000-000000000005"
	agentID    = "01920000-0000-7000-8000-000000000006"
	issuer     = "https://pantherclaw.example.test"
)

// seed derives a fixed Ed25519 seed from a name: SHA-256("pantherclaw
// conformance " + name). The README lists the names.
func seed(name string) []byte {
	s := sha256.Sum256([]byte("pantherclaw conformance " + name))
	return s[:]
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// group is one vector file, built from the implementation.
type group struct {
	file  string
	build func(t *testing.T) any
}

func groups() []group {
	return []group{
		{file: "jcs.json", build: buildJCS},
		{file: "actionir.json", build: buildActionIR},
		{file: "approval_bindings.json", build: buildBindings},
		{file: "key_files.json", build: buildKeyFiles},
		{file: "workload_tokens.json", build: buildWorkloadTokens},
		{file: "proofs.json", build: buildProofs},
		{file: "action_tokens.json", build: buildActionTokens},
		{file: "sdk_face.json", build: buildFace},
		{file: "wrappers.json", build: buildWrappers},
	}
}

// TestConformanceVectors writes the vectors (-update) or checks that the
// implementation still agrees with them.
func TestConformanceVectors(t *testing.T) {
	for _, g := range groups() {
		// Tokens and proofs carry UUIDv7s and random ids: each group is built
		// once, in a bubble whose clock starts at the same instant, with
		// crypto/rand seeded, so a rewrite is byte for byte the same.
		t.Run(g.file, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cryptotest.SetGlobalRandom(t, 20261011)
				path := filepath.Join(dir, g.file)
				got := encode(t, g.build(t))
				if *update {
					if err := os.WriteFile(path, got, 0o644); err != nil {
						t.Fatal(err)
					}
					return
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%v (run task sdk:vectors to create it)", err)
				}
				if !bytes.Equal(got, raw) {
					t.Fatalf("%s differs from what the implementation produces now; if the change is intended, run "+
						"task sdk:vectors and review the diff", g.file)
				}
			})
		})
	}
}

// encode writes a vector file: indented JSON, LF, a final newline.
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func canon(t *testing.T, v []byte) []byte {
	t.Helper()
	c := jsontext.Value(bytes.Clone(v))
	if err := c.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	return c
}

// header is the envelope of every vector file.
type header struct {
	Format      string `json:"format"`
	Group       string `json:"group"`
	Description string `json:"description"`
	Source      string `json:"source"`
}

func head(group, source, description string) header {
	return header{Format: Format, Group: group, Description: description, Source: source}
}
