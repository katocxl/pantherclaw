// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"errors"
	"testing"
)

// TestHR502_AHostedGatewayEnrollsOnlyFromItsTokenFile: a hosted gateway
// takes its token from the file its host agent wrote, never a second way
// in, and refuses a configuration that would run connectors (HR-084).
//
// Covers: PN-010.4
func TestHR502_AHostedGatewayEnrollsOnlyFromItsTokenFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control.APIURL, cfg.Control.CASHA256 = "https://gw-api.example.test:8443", "sha256:aa"
	if err := checkHosted(&cfg, "", ""); err != nil {
		t.Fatalf("not hosted: %v", err)
	}
	if err := checkHosted(&cfg, "enroll.json", "/run/pantherclaw/enroll/token"); err == nil {
		t.Fatal("two ways to enroll accepted")
	}
	cfg.Connectors.Enabled = true
	if err := checkHosted(&cfg, "", "/run/pantherclaw/enroll/token"); !errors.Is(err, errHostedConnectors) {
		t.Fatalf("connectors on a hosted gateway: %v", err)
	}
	cfg.Connectors.Enabled = false
	cfg.Control.CASHA256 = ""
	if err := checkHosted(&cfg, "", "/run/pantherclaw/enroll/token"); err == nil {
		t.Fatal("a hosted gateway without a CA pin accepted")
	}
}
