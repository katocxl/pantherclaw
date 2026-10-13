// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gen_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
)

// BindingCase is one approval binding (PAP-1 §8): the binding input, its
// canonical form, and binding = base64url(SHA-256(canonical)).
type BindingCase struct {
	Name      string         `json:"name"`
	Input     jsontext.Value `json:"input"`
	Canonical string         `json:"canonical"`
	Binding   string         `json:"binding"`
}

// BindingFile is approval_bindings.json.
type BindingFile struct {
	header
	Cases []BindingCase `json:"cases"`
}

func buildBindings(t *testing.T) any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "approvals", "domain", "testdata", "binding_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden []struct {
		Name    string `json:"name"`
		Input   string `json:"input"`
		Binding string `json:"binding"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	f := BindingFile{header: head("approval_bindings", "internal/approvals/domain (testdata/binding_vectors.json)",
		"Approval bindings: canonical is the RFC 8785 form of input and binding is base64url (no padding) of its SHA-256. "+
			"The last case is a batch challenge over two bindings.")}
	for _, g := range golden {
		sum := sha256.Sum256([]byte(g.Input))
		if !bytes.Equal(canon(t, []byte(g.Input)), []byte(g.Input)) || b64(sum[:]) != g.Binding {
			t.Fatalf("%s: the golden input is not canonical or its binding is not its SHA-256", g.Name)
		}
		f.Cases = append(f.Cases, BindingCase{Name: g.Name, Input: jsontext.Value(scramble(t, g.Input)), Canonical: g.Input, Binding: g.Binding})
	}
	return f
}
