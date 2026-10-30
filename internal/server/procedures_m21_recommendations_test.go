// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/recommendations/domain"
)

// TestRecommendationLinksAreProcedures: every catalogue entry's evidence
// link is a procedure the API serves.
//
// Covers: F343
func TestRecommendationLinksAreProcedures(t *testing.T) {
	for _, e := range domain.Catalogue() {
		if _, ok := procedurePermissions[e.Link]; !ok {
			t.Errorf("%s: %s is not a procedure", e.ID, e.Link)
		}
	}
}
