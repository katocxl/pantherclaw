// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sources

import (
	"context"
	"errors"
	"testing"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func viewer(posture, other ports.Reach) ports.Viewer {
	return ports.Viewer{
		Posture: posture,
		Under:   func(context.Context, td.Permission) (ports.Reach, error) { return other, nil },
	}
}

// TestD255_BelowScopeIsDeniedNeverEmpty: a source the viewer is below answers
// permission-denied, which the queue shows as RESTRICTED, and these checks
// run before any read.
// Covers: F863
func TestD255_BelowScopeIsDeniedNeverEmpty(t *testing.T) {
	mine, theirs := ids.NewV7(), ids.NewV7()
	onMine := ports.Reach{Agents: []ids.UUID{mine}}
	for name, c := range map[string]struct {
		src ports.Source
		v   ports.Viewer
	}{
		"coverage held elsewhere":   {Coverage{}, viewer(onMine, ports.Reach{Agents: []ids.UUID{theirs}})},
		"discovery held elsewhere":  {Discovery{}, viewer(onMine, ports.Reach{Agents: []ids.UUID{theirs}})},
		"inventory below the org":   {Inventory{}, viewer(onMine, onMine)},
		"recommendations below org": {Recommendations{}, viewer(onMine, onMine)},
	} {
		_, _, err := c.src.Findings(context.Background(), c.v, domain.Filter{})
		var e *pcerr.Error
		if !errors.As(err, &e) || e.Code() != pcerr.PermissionDenied {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestBothKeepsWhatOverlaps: a partial overlap is that overlap, and a viewer
// whose posture.read reaches nothing has nothing to be refused.
func TestBothKeepsWhatOverlaps(t *testing.T) {
	a, b := ids.NewV7(), ids.NewV7()
	r, err := both(context.Background(), viewer(ports.Reach{Agents: []ids.UUID{a, b}}, ports.Reach{Agents: []ids.UUID{a}}), td.PermCoverageRead)
	if err != nil || len(r.Agents) != 1 || r.Agents[0] != a {
		t.Errorf("overlap: %+v %v", r, err)
	}
	if _, err := both(context.Background(), viewer(ports.Reach{}, ports.Reach{Agents: []ids.UUID{a}}), td.PermCoverageRead); err != nil {
		t.Errorf("nothing reached: %v", err)
	}
}
