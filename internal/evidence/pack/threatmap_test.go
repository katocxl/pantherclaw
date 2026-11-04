// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pack_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// TestThreatMapStatementIsTheThreatMaps: a threat map pack's manifest
// carries the threat map's own Statement word for word (G0 M28 D717, D720).
// Covers: F968, HR-681, HR-688
func TestThreatMapStatementIsTheThreatMaps(t *testing.T) {
	if pack.ThreatMapStatement != domain.Statement {
		t.Fatalf("pack %q\nthreat map %q", pack.ThreatMapStatement, domain.Statement)
	}
	if got := (pack.Scope{Kind: pack.ScopeThreatMap}).ExpectedStatement(); got != domain.Statement {
		t.Errorf("expected statement %q", got)
	}
}
