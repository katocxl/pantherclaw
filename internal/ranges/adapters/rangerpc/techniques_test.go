// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rangerpc

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
)

// TestHR685_RangeResultLabelsComeOnlyFromAnUnchangedLibraryScenario: a
// library result whose digest is the library's carries the entry's ATLAS
// and ATT&CK labels; a stale digest and a customer (CX) scenario carry none
// (G0 M28 D718, D718c L1). Covers: HR-685, F964
func TestHR685_RangeResultLabelsComeOnlyFromAnUnchangedLibraryScenario(t *testing.T) {
	var id string
	var e library.Entry
	all := library.All()
	for _, k := range slices.Sorted(maps.Keys(all)) {
		if x := all[k]; len(x.ATLAS) > 0 && len(x.ATTACK) > 0 {
			id, e = k, x
			break
		}
	}
	if id == "" {
		t.Fatal("no library entry maps to both frameworks")
	}

	got := resultPB(domain.Result{Scenario: domain.Scenario{ID: id, Digest: e.Digest}})
	if !slices.Equal(got.GetAtlas(), e.ATLAS) || !slices.Equal(got.GetAttack(), e.ATTACK) {
		t.Errorf("matching digest: atlas %v attack %v, want %v %v", got.GetAtlas(), got.GetAttack(), e.ATLAS, e.ATTACK)
	}

	stale := resultPB(domain.Result{Scenario: domain.Scenario{ID: id, Digest: strings.Repeat("0", len(e.Digest))}})
	if len(stale.GetAtlas())+len(stale.GetAttack()) != 0 {
		t.Errorf("stale digest labeled: %v %v", stale.GetAtlas(), stale.GetAttack())
	}

	cx := resultPB(domain.Result{Scenario: domain.Scenario{ID: "CX-" + id, Digest: e.Digest}})
	if cx.GetOrigin() == domain.OriginLibrary || len(cx.GetAtlas())+len(cx.GetAttack()) != 0 {
		t.Errorf("customer scenario labeled: origin %s %v %v", cx.GetOrigin(), cx.GetAtlas(), cx.GetAttack())
	}
}
