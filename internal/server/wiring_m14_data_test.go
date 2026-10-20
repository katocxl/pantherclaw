// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestWireM14Data_PostgresHostedIsAlwaysWired (D121): the postgres store
// and the confirm page always get Hosted over the configured list, an
// empty one included, so internal is refused only on the gateways
// PantherClaw hosts; a nil Hosted would refuse it everywhere.
func TestWireM14Data_PostgresHostedIsAlwaysWired(t *testing.T) {
	hosted, own := ids.NewV7(), ids.NewV7()
	for name, list := range map[string][]ids.UUID{"empty": nil, "one": {hosted}} {
		t.Run(name, func(t *testing.T) {
			m6 := &m6Services{gateways: gwapp.New(nil, nil, "", clock.System{}).WithPantherClawHosted(list)}
			c := wireM14Core(nil)
			wireM14Data(c, m6)
			kc, ok := c.kinds.Get(capp.KindPostgres)
			if !ok {
				t.Fatal("the postgres store is not registered")
			}
			store, ok := kc.(pgmanifest.Store)
			if !ok || store.Hosted == nil {
				t.Fatalf("the postgres store has no Hosted: %#v", kc)
			}
			svc := postgresManifests(apiDeps{m6: m6})
			if svc.Hosted == nil {
				t.Fatal("the confirm page has no Hosted")
			}
			for _, h := range []func(ids.UUID) bool{store.Hosted, svc.Hosted} {
				if h(own) || h(hosted) != (len(list) > 0) {
					t.Fatalf("Hosted does not follow the list %v", list)
				}
			}
		})
	}
}
