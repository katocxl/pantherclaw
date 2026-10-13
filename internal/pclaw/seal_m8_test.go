// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// TestHR204_SealAGitHubApp: pclaw seal --github-app seals the App's id,
// installation, account and private key as one GitHub App credential, bound
// to its kind, so the gateway can open it only as an App key; the key never
// leaves the machine in plaintext, and a malformed key or account seals
// nothing.
func TestHR204_SealAGitHubApp(t *testing.T) {
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

	app, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(app)})
	file := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(file, pemKey, 0o600); err != nil {
		t.Fatal(err)
	}
	conn := "0192aaaa-bbbb-7ccc-8ddd-000000000002"
	code, out, errs := run(t, env, "seal", "--connection", conn, "--from-file", file, "--github-app", "Iv23liExample",
		"--installation", "7", "--account", "acme")
	if code != 0 || srv.put == nil || srv.put.GetKind() != domain.KindGitHubApp {
		t.Fatalf("seal = %d %q %q", code, out, errs)
	}
	if bytes.Contains(srv.put.GetSealed(), []byte("PRIVATE KEY")) || bytes.Contains([]byte(out+errs), []byte("PRIVATE KEY")) {
		t.Fatal("the App key left the machine in plaintext")
	}
	b := domain.Binding{
		Org: "0192aaaa-bbbb-7ccc-8ddd-000000000001", Connection: conn, Version: 2, AllowedHosts: []string{"payments.example.test"},
		BrokerKey: "0192aaaa-bbbb-7ccc-8ddd-000000000003", Header: "Authorization", Scheme: "Bearer",
	}
	if _, err := pccrypto.Open(key, b.Info(), domain.AAD, srv.put.GetSealed()); err == nil {
		t.Fatal("a GitHub App credential opens as a static one")
	}
	b.Kind = domain.KindGitHubApp
	plain, err := pccrypto.Open(key, b.Info(), domain.AAD, srv.put.GetSealed())
	if err != nil {
		t.Fatal(err)
	}
	g, err := domain.DecodeGitHubApp(plain)
	if err != nil || g.Issuer != "Iv23liExample" || g.Installation != 7 || g.Account != "acme" {
		t.Fatalf("opened %+v %v", g, err)
	}
	if k, err := g.Key(); err != nil || !k.Equal(app) {
		t.Fatalf("the key did not survive sealing: %v", err)
	}
	// The installation travels beside the seal as configuration, the same
	// one the seal holds, and never the key.
	if gh := srv.put.GetGithub(); gh.GetAppClientId() != g.Issuer || gh.GetInstallationId() != g.Installation || gh.GetAccountLogin() != g.Account {
		t.Fatalf("the installation sent with the seal: %+v", gh)
	}

	for name, args := range map[string][]string{
		"no installation":      {"--github-app", "Iv23liExample", "--account", "acme"},
		"an uppercase account": {"--github-app", "Iv23liExample", "--installation", "7", "--account", "Acme"},
		"not an App id":        {"--github-app", "app", "--installation", "7", "--account", "acme"},
		"account without App":  {"--installation", "7", "--account", "acme"},
	} {
		srv.put = nil
		if code, _, _ := run(t, env, append([]string{"seal", "--connection", conn, "--from-file", file}, args...)...); code == 0 || srv.put != nil {
			t.Errorf("%s: sealed", name)
		}
	}
	short, _ := rsa.GenerateKey(rand.Reader, 1024)
	weak := filepath.Join(t.TempDir(), "weak.pem")
	if err := os.WriteFile(weak, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(short)}), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.put = nil
	if code, _, _ := run(t, env, "seal", "--connection", conn, "--from-file", weak, "--github-app", "1", "--installation", "7", "--account", "acme"); code == 0 || srv.put != nil {
		t.Fatal("a 1024-bit App key was sealed")
	}
}
