// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/config"
)

// TestD93b_ExternalChecksLoopbackOnlyOnALocalServer (G0 M16 D93b): a
// configuration that lets external checks reach loopback is refused unless
// the server is local only, no environment variable sets it, and it adds
// 127.0.0.1 and ::1 and nothing else to the checks' allowed addresses.
// Covers: F366
func TestD93b_ExternalChecksLoopbackOnlyOnALocalServer(t *testing.T) {
	local := func() Config {
		c := devKeyConfig(t.TempDir())
		c.Dev.PackageKeyFile, c.Dev.ExternalChecksLoopback = "", true
		return c
	}
	if c := local(); c.Validate() != nil {
		t.Fatalf("a local server refused the setting: %v", c.Validate())
	}
	for name, mutate := range map[string]func(*Config){
		"all interfaces": func(c *Config) { c.HTTP.Addr = "0.0.0.0:8080" },
		"public url":     func(c *Config) { c.Auth.PublicURL = "https://pantherclaw.example.com" },
		"behind a proxy": func(c *Config) { c.HTTP.PlaintextBehindProxy = true },
		"live api keys":  func(c *Config) { c.Auth.APIKeyEnv = "live" },
	} {
		c := local()
		mutate(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "dev.external_checks_loopback") {
			t.Errorf("%s: %v, want the setting refused", name, err)
		}
		c.Dev.ExternalChecksLoopback = false
		if err := c.Validate(); err != nil {
			t.Errorf("%s: refused even without the setting: %v", name, err)
		}
	}

	loaded := DefaultConfig()
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(`{"database": {"app_password_file": "pw"}, "kek_files": ["kek"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	everyEnv := func(name string) (string, bool) { return "true", strings.HasPrefix(name, "PC_DEV") }
	if err := config.Load(&loaded, path, everyEnv); err != nil || loaded.Dev.ExternalChecksLoopback {
		t.Fatalf("the environment set the setting: %v, %v", loaded.Dev.ExternalChecksLoopback, err)
	}

	c := local()
	got := externalChecksConfig(&c).AllowedAddrs
	want := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	if !slices.Equal(got, want) {
		t.Fatalf("allowed addresses %v, want %v", got, want)
	}
	c.Dev.ExternalChecksLoopback = false
	if got := externalChecksConfig(&c).AllowedAddrs; len(got) != 0 {
		t.Fatalf("without the setting: %v", got)
	}
}
