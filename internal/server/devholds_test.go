// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"os"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
)

type devDefs struct{ ds []*defs.Definition }

func (d devDefs) ActiveDefinitions(context.Context, ids.OrgID) ([]*defs.Definition, error) {
	return d.ds, nil
}

type devCatalog map[string]fdomain.Type

func (c devCatalog) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return c, nil
}

// TestDevHoldBundlePassesTheGate (G0 M11.1 D10, D26): the dev seed's hold
// policy passes its own scenario tests, every mutant killed, in an org with
// no fact provider yet (as dev seed publishes it), so dev seed publishes it
// through the gate.
func TestDevHoldBundlePassesTheGate(t *testing.T) {
	raw, err := os.ReadFile("../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	ds := make([]*defs.Definition, len(pkg.Definitions))
	for i := range pkg.Definitions {
		ds[i] = &pkg.Definitions[i]
	}
	limit, err := money.ParseMoney("50.00", "USD")
	if err != nil {
		t.Fatal(err)
	}
	r := scenario.New(devDefs{ds}, devCatalog{}, celenv.DefaultLimits, policyapp.DefaultBudget)
	res, err := r.Run(context.Background(), ids.New[ids.Org](), devHoldBundle(limit))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Fatalf("the dev hold policy does not pass its tests: %+v", res)
	}
}
