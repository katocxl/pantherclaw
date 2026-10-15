// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// derEndingIn returns a PKCS #8 DER P-256 private key whose last byte is
// last. The scalars are tried in order from 1, so the key is the same on
// every run.
func derEndingIn(t *testing.T, last byte) []byte {
	t.Helper()
	for i := 1; i < 1<<16; i++ {
		var d [32]byte
		d[30], d[31] = byte(i>>8), byte(i)
		k, err := ecdh.P256().NewPrivateKey(d[:])
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		if der[len(der)-1] == last {
			return der
		}
	}
	t.Fatalf("no key ends in %#x", last)
	return nil
}

func writeCredential(t *testing.T, content []byte) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(f, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestHR204_ReadCredentialKeepsADERKeyEndingInALineBreak: a DER key whose
// last byte is 0x0a or 0x0d is read whole and recognised as a private key,
// a token loses only the line break an editor adds, and a DER key followed
// by a line break is still recognised.
func TestHR204_ReadCredentialKeepsADERKeyEndingInALineBreak(t *testing.T) {
	for _, last := range []byte{'\n', '\r'} {
		der := derEndingIn(t, last)
		got, key, err := readCredential(writeCredential(t, der))
		if err != nil || !key || !bytes.Equal(got, der) {
			t.Errorf("DER ending in %#x: key %v, whole %v, err %v", last, key, bytes.Equal(got, der), err)
		}
		if _, key, err := readCredential(writeCredential(t, append(bytes.Clone(der), '\n'))); err != nil || !key {
			t.Errorf("DER ending in %#x plus a line break: key %v, err %v", last, key, err)
		}
	}
	for content, want := range map[string]string{
		"tok_123\n":   "tok_123",
		"tok_123\r\n": "tok_123",
		"tok_123":     "tok_123",
		"tok_123\n\n": "tok_123\n",
	} {
		got, key, err := readCredential(writeCredential(t, []byte(content)))
		if err != nil || key || string(got) != want {
			t.Errorf("token %q: read %q, key %v, err %v", content, got, key, err)
		}
	}
	for _, content := range []string{"", "\n", "\r\n"} {
		if _, _, err := readCredential(writeCredential(t, []byte(content))); err == nil {
			t.Errorf("%q: an empty credential was read", content)
		}
	}
}

// TestHR204_SealRefusesADERKeyEndingInALineBreak: pclaw seal without
// --github-app seals nothing when the file is a DER key ending in 0x0a or
// 0x0d, the case that let TestHR204_SealAGitHubApp's DER key through about
// once in 128 runs.
func TestHR204_SealRefusesADERKeyEndingInALineBreak(t *testing.T) {
	key, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := &sealServer{key: key, fingerprint: fingerprintOf(key)}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, srv)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	conn := "0192aaaa-bbbb-7ccc-8ddd-000000000002"

	for _, last := range []byte{'\n', '\r'} {
		srv.put = nil
		code, _, errs := run(t, env, "seal", "--connection", conn, "--from-file", writeCredential(t, derEndingIn(t, last)))
		if code == 0 || srv.put != nil || !strings.Contains(errs, "--github-app") {
			t.Errorf("DER ending in %#x was sealed as static: %d %q", last, code, errs)
		}
	}
	srv.put = nil
	if code, out, errs := run(t, env, "seal", "--connection", conn, "--from-file", writeCredential(t, []byte("tok_123\n"))); code != 0 || srv.put == nil {
		t.Fatalf("a token was not sealed: %d %q %q", code, out, errs)
	}
}
