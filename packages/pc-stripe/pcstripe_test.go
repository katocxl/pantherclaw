// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcstripe_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
)

func TestPackageDecodes(t *testing.T) {
	p, err := manifest.Decode(pcstripe.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pcstripe.Name || p.Version != pcstripe.Version {
		t.Fatalf("package %s %v", p.Name, p.Version)
	}
}
