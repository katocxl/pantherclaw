// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package automationsrpc

import (
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

// TestGraphEdgeCarriesItsBranch: a BRANCH edge's label and guard reach the
// response.
//
// Covers: F678
func TestGraphEdgeCarriesItsBranch(t *testing.T) {
	e := graphEdge(autodomain.GraphEdge{From: "a", To: "b", Type: autodomain.EdgeBranch, Label: "then", Guard: "x"})
	if e.GetFrom() != "a" || e.GetTo() != "b" || e.GetType() != "BRANCH" || e.GetLabel() != "then" || e.GetGuard() != "x" {
		t.Fatalf("edge %+v", e)
	}
}
