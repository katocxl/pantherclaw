// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/platform/config"
)

// TestHR217_TheClaimTimeoutIsASettingWithinBounds: coverage.claim_timeout
// (PC_COVERAGE_CLAIM_TIMEOUT) is 50 ms when unset, set from the
// environment, and refused outside 10 ms to 2 s.
func TestHR217_TheClaimTimeoutIsASettingWithinBounds(t *testing.T) {
	c := DefaultConfig()
	c.DB.AppPasswordFile, c.KEKFiles = "pw", []string{"kek"}
	if d := claimTimeoutOf(&c); d != 50*time.Millisecond {
		t.Fatalf("unset: %v", d)
	}
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(`{"database": {"app_password_file": "pw"}, "kek_files": ["kek"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded := DefaultConfig()
	env := func(name string) (string, bool) {
		if name == "PC_COVERAGE_CLAIM_TIMEOUT" {
			return "200ms", true
		}
		return "", false
	}
	if err := config.Load(&loaded, path, env); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Validate(); err != nil || claimTimeoutOf(&loaded) != 200*time.Millisecond {
		t.Fatalf("from the environment: %v, %v", claimTimeoutOf(&loaded), err)
	}
	for _, d := range []time.Duration{10 * time.Millisecond, 2 * time.Second} {
		cc := c
		cc.Coverage.ClaimTimeout = config.Duration(d)
		if err := cc.Validate(); err != nil {
			t.Fatalf("%v refused: %v", d, err)
		}
	}
	for _, d := range []time.Duration{9 * time.Millisecond, 2*time.Second + time.Millisecond, -time.Second} {
		cc := c
		cc.Coverage.ClaimTimeout = config.Duration(d)
		if err := cc.Validate(); err == nil {
			t.Fatalf("%v accepted", d)
		}
		if claimTimeoutOf(&cc) != finalize.DefaultClaimTimeout {
			t.Fatalf("%v: %v", d, claimTimeoutOf(&cc))
		}
	}
}
