// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gen_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// KeyFileCase is one workload key file (internal/identity/workloadclient):
// accepted with the key it holds, or refused.
type KeyFileCase struct {
	Name string `json:"name"`
	// File is the exact file text; accepted cases are byte for byte what
	// PantherClaw writes.
	File       string `json:"file"`
	Reject     string `json:"reject,omitzero"`
	PublicX    string `json:"public_x,omitzero"`
	JKT        string `json:"jkt,omitzero"`
	Identifier string `json:"identifier,omitzero"`
	Server     string `json:"server,omitzero"`
	RunID      string `json:"run_id,omitzero"`
}

// KeyFileFile is key_files.json.
type KeyFileFile struct {
	header
	Cases []KeyFileCase `json:"cases"`
}

func identifier() string {
	return "pc:org/" + orgID + "/agent/" + agentID + "/inst/" + instanceID
}

func buildKeyFiles(t *testing.T) any {
	t.Helper()
	f := KeyFileFile{header: head("key_files", "internal/identity/workloadclient WriteKeyFile and ReadKeyFile",
		"The workload key file (PAP-1 §3.1): private_key is the base64url (no padding) Ed25519 seed; unknown or "+
			"duplicate members are refused. jkt is the RFC 7638 thumbprint of the public key.")}
	tmp := t.TempDir()
	for i, k := range []workloadclient.KeyFile{
		{PrivateKey: b64(seed("workload"))},
		{PrivateKey: b64(seed("workload")), Identifier: identifier(), Server: issuer, RunID: runID},
	} {
		path := filepath.Join(tmp, "key"+string(rune('a'+i))+".json")
		if err := workloadclient.WriteKeyFile(path, k, false); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		read, err := workloadclient.ReadKeyFile(path)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := read.Key()
		if err != nil {
			t.Fatal(err)
		}
		name := []string{"a new key", "an enrolled workload"}[i]
		f.Cases = append(f.Cases, KeyFileCase{
			Name: name, File: string(raw), PublicX: b64(pub(priv)), JKT: jws.Thumbprint(pub(priv)),
			Identifier: read.Identifier, Server: read.Server, RunID: read.RunID,
		})
	}
	s := b64(seed("workload"))
	std := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))
	for _, c := range []struct{ name, file string }{
		{"an unknown member", `{"private_key":"` + s + `","public_key":"x"}`},
		{"a duplicate member", `{"private_key":"` + s + `","private_key":"` + s + `"}`},
		{"no private key", `{"identifier":"` + identifier() + `"}`},
		{"a 31-byte seed", `{"private_key":"` + b64(seed("workload")[:31]) + `"}`},
		{"base64 padding", `{"private_key":"` + s + `="}`},
		{"the standard base64 alphabet", `{"private_key":"` + std + `"}`},
		{"not an object", `["` + s + `"]`},
	} {
		path := filepath.Join(tmp, strings.ReplaceAll(c.name, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(c.file+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := workloadclient.ReadKeyFile(path); err == nil {
			t.Fatalf("%s: read, want a refusal", c.name)
		}
		f.Cases = append(f.Cases, KeyFileCase{Name: c.name, File: c.file + "\n", Reject: c.name})
	}
	return f
}
