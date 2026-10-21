// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pclaw

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestNodeUp_RealDocker runs pclaw up, status and down against Docker with
// the images this build names: PostgreSQL over TLS, db bootstrap, migrate,
// org create, the server ready on 127.0.0.1. It skips, saying why, without
// a Docker engine or without the images (task images builds the
// development ones).
func TestNodeUp_RealDocker(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipped: no docker binary on PATH (pclaw up needs Docker with Compose v2)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "compose", "version", "--short").Output(); err != nil || len(bytes.TrimSpace(out)) == 0 {
		t.Skip("skipped: Docker Compose v2 is not available")
	}
	if err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		t.Skip("skipped: the Docker engine is not running")
	}
	server, gateway, _ := nodeImages()
	for _, img := range []string{server, gateway} {
		if err := exec.CommandContext(ctx, "docker", "image", "inspect", img).Run(); err != nil {
			t.Skipf("skipped: image %s is not present locally (build the development images with: task images)", img)
		}
	}
	dir := t.TempDir()
	api, gw := freePort(t), freePort(t)
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Run(ctx, args, &out, &errb, func(k string) (string, bool) {
			if k == "PANTHERCLAW_CONFIG_DIR" {
				return t.TempDir(), true
			}
			return "", false
		}, Options{})
		return code, out.String(), errb.String()
	}
	t.Cleanup(func() {
		// Remove the containers and every volume of this test node.
		_ = exec.Command("docker", "compose", "--file", filepath.Join(dir, nodeComposeFile), "--project-directory", dir, //nolint:gosec // test cleanup
			"--profile", "tools", "--profile", "gateway", "down", "--volumes", "--remove-orphans").Run()
	})
	code, out, errs := run("up", "--dir", dir, "--port", strconv.Itoa(api), "--gateway-port", strconv.Itoa(gw))
	if code != 0 {
		t.Fatalf("pclaw up = %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"PantherClaw is up: http://localhost:" + strconv.Itoa(api), "--invitation pci_", "gateway: not enrolled yet"} {
		if !strings.Contains(out, want) {
			t.Errorf("pclaw up output lacks %q:\n%s", want, out)
		}
	}
	code, out, errs = run("status", "--dir", dir)
	if code != 0 || !strings.Contains(out, ", ready (/readyz") {
		t.Errorf("pclaw status = %d\n%s\n%s", code, out, errs)
	}
	// Idempotent: a second run bootstraps and creates nothing.
	code, out, errs = run("up", "--dir", dir)
	if code != 0 || strings.Contains(out, "pci_") || !strings.Contains(errs, "database roles and schema: done before") {
		t.Errorf("second pclaw up = %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = run("down", "--dir", dir)
	if code != 0 || !strings.Contains(out, "The node is stopped") {
		t.Errorf("pclaw down = %d\n%s\n%s", code, out, errs)
	}
}
