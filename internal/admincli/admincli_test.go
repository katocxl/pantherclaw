// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package admincli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	now := func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }
	code := Run(args, &out, &errb, now)
	return code, out.String(), errb.String()
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKeygenSignVerifyFlow(t *testing.T) {
	dir := t.TempDir()
	pp := write(t, dir, "pass", "a long offline passphrase\n")
	code, out, errs := run(t, "keygen", "--purpose", "licence", "--out-dir", dir, "--passphrase-file", pp)
	if code != 0 {
		t.Fatalf("keygen exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "licence-root-") || !strings.Contains(out, "roots.json") {
		t.Fatalf("keygen output:\n%s", out)
	}
	keyFile := filepath.Join(dir, "licence-root.key")
	if b, _ := os.ReadFile(keyFile); !bytes.Contains(b, []byte("ENCRYPTED ROOT PRIVATE KEY")) {
		t.Fatal("private key was not encrypted")
	}
	if code, _, _ := run(t, "keygen", "--purpose", "licence", "--out-dir", dir); code == 0 {
		t.Fatal("keygen overwrote an existing root key")
	}
	claims := write(t, dir, "claims.json", `{"sub":"Acme Ltd","cid":"cus_1","edition":"team","max_agents":25,"max_orgs":2,
		"not_before":"2026-10-01T00:00:00Z","expires_at":"2027-10-01T00:00:00Z"}`)
	lic := filepath.Join(dir, "acme.licence")
	code, out, errs = run(t, "licence", "sign", "--key", keyFile, "--passphrase-file", pp, "--claims", claims, "--out", lic)
	if code != 0 {
		t.Fatalf("sign exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "Signed licence") {
		t.Fatalf("sign output: %s", out)
	}
	code, out, errs = run(t, "licence", "verify", "--roots", filepath.Join(dir, "licence-root.pub.json"), "--in", lic)
	if code != 0 || !strings.Contains(out, "status now: VALID") {
		t.Fatalf("verify exit %d:\n%s%s", code, out, errs)
	}
}

func TestSignRefusesPackageRootAndBadClaims(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := run(t, "keygen", "--purpose", "packages", "--out-dir", dir); code != 0 {
		t.Fatal(errs)
	}
	claims := write(t, dir, "claims.json", `{"sub":"A","cid":"c","edition":"team","max_agents":1,"max_orgs":1,"not_before":"2026-10-01T00:00:00Z","expires_at":"2027-10-01T00:00:00Z"}`)
	if code, _, errs := run(t, "licence", "sign", "--key", filepath.Join(dir, "packages-root.key"), "--claims", claims, "--out", filepath.Join(dir, "x")); code == 0 || !strings.Contains(errs, "not a licence root") {
		t.Fatalf("package root signed a licence: %d %s", code, errs)
	}
	if code, _, _ := run(t, "keygen", "--purpose", "licence", "--out-dir", dir); code != 0 {
		t.Fatal("keygen failed")
	}
	badClaims := write(t, dir, "bad.json", `{"sub":"A","edition":"team","unexpected":true}`)
	if code, _, _ := run(t, "licence", "sign", "--key", filepath.Join(dir, "licence-root.key"), "--claims", badClaims, "--out", filepath.Join(dir, "y")); code == 0 {
		t.Fatal("claims with unknown fields signed")
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"nope"},
		{"licence"},
		{"keygen"},
		{"keygen", "--purpose", "admin", "--out-dir", "."},
		{"keygen", "--purpose", "org-packages", "--out-dir", "."}, // an org key, not a PantherClaw root
		{"keygen", "--purpose", "packages-dev", "--out-dir", "."}, // only dev seed makes the development key (HR-163)
		{"packages"},
		{"packages", "sign", "--key", "k", "--version", "0", "--expires-days", "180", "--out", "o", "p.yaml"}, // version 0
		{"packages", "sign", "--key", "k", "--version", "1", "--expires-days", "180", "--out", "o"},           // no files
		{"packages", "verify", "--roots", "r", "p.yaml"},
	} {
		if code, _, _ := run(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
	_, _, errs := run(t)
	for _, want := range []string{
		"packages sign --key FILE [--passphrase-file FILE] --version N [--expires-days 180] --out FILE PACKAGE.yaml...",
		"packages verify --roots FILE --targets FILE PACKAGE.yaml...",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("usage text lacks %q:\n%s", want, errs)
		}
	}
	if code, out, _ := run(t, "version"); code != 0 || !strings.HasPrefix(out, "pclaw-admin ") {
		t.Fatalf("version: %d %q", code, out)
	}
}

// TestHR063_AdminToolHasNoNetworkClients keeps pclaw-admin offline by
// construction: no HTTP, TLS, SMTP or RPC client code is linked in.
func TestHR063_AdminToolHasNoNetworkClients(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list")
	}
	out, err := exec.Command("go", "list", "-deps", "github.com/katocxl/pantherclaw/cmd/pclaw-admin").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, banned := range []string{"net/http", "crypto/tls", "net/smtp", "net/rpc", "github.com/jackc/pgx/v5"} {
		for _, dep := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(dep) == banned {
				t.Errorf("pclaw-admin links %s", banned)
			}
		}
	}
}
