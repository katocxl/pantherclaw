// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/hosting/agent"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// TestHR500_AddHostIssuesWhatTheAgentInstalls: hosting add-host records the
// host and writes a bundle the agent installs against the printed pin, and
// it never overwrites a bundle or records a host for a bad request (D226).
//
// Covers: PN-010.4
func TestHR500_AddHostIssuesWhatTheAgentInstalls(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI)
	dir := t.TempDir()
	identity, csr, bundle := filepath.Join(dir, "id"), filepath.Join(dir, "host.csr"), filepath.Join(dir, "bundle.json")
	var out, errb bytes.Buffer
	if code := agent.Run(context.Background(), []string{"keygen", "--identity-dir", identity, "--csr-out", csr}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("keygen = %d %s", code, errb.String())
	}
	addHost := func(name, request string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Run(context.Background(), []string{
			"hosting", "add-host", "--config", cfgPath, "--name", name, "--domain", name + ".example.test",
			"--capacity", "5", "--milli-cpus", "4000", "--memory-mib", "8192", "--csr", request, "--bundle-out", bundle,
		}, &out, &errb, noEnv)
		return code, out.String(), errb.String()
	}
	bad := filepath.Join(dir, "bad.csr")
	if err := os.WriteFile(bad, []byte("not a request"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := addHost("h0", bad); code == 0 {
		t.Fatal("a bad request was accepted")
	}
	code, stdout, errs := addHost("h1", csr)
	pin := regexp.MustCompile(`sha256:[0-9a-f]{64}`).FindString(stdout)
	if code != 0 || pin == "" {
		t.Fatalf("add-host = %d %q %q", code, stdout, errs)
	}
	if code, _, _ := addHost("h2", csr); code == 0 {
		t.Fatal("add-host overwrote a bundle")
	}
	var hosts int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.hosting_hosts WHERE name IN ('h0', 'h1', 'h2')", nil, &hosts)
	if hosts != 1 {
		t.Fatalf("%d hosts recorded", hosts)
	}
	out.Reset()
	if code := agent.Run(context.Background(), []string{"install", "--identity-dir", identity, "--cert", bundle, "--ca-sha256", pin}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("install = %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "installed host") {
		t.Fatalf("install: %q", out.String())
	}
}
