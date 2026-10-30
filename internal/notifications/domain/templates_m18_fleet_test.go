// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/notifications/domain"
)

// TestM18FleetTemplatesRender: the fleet notices render from their fixed
// templates with every parameter the sweep sends (G0 M18 D151).
// Covers: PN-010.6
func TestM18FleetTemplatesRender(t *testing.T) {
	gw := "0199f0aa-1111-7222-8333-444455556666"
	for typ, params := range map[string]map[string]string{
		"gateway.silent":        {"gateway": gw, "since": "2026-10-30T10:00:00Z", "threshold": "300"},
		"gateway.recovered":     {"gateway": gw, "since": "2026-10-30T10:00:00Z"},
		"gateway.below_minimum": {"gateway": gw, "version": "unknown", "minimum": "v2.0.0"},
	} {
		r, err := domain.Render(typ, params)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if strings.Contains(r.Body, "{") || !strings.Contains(r.Body, gw) || r.Link != "/gateways" {
			t.Errorf("%s rendered %+v", typ, r)
		}
	}
}
