// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// TestM10Ports_EveryPortIsWired (G0 M10 D49): every cross-stream port has
// its provider, so no consumer reads "not available" on a full server.
func TestM10Ports_EveryPortIsWired(t *testing.T) {
	pool := &db.Pool{}
	d := apiDeps{pool: pool}
	c := responseContainment(pool, nil, nil)
	if c.Reach == nil || c.Raiser == nil || c.Failures == nil {
		t.Fatalf("response containment ports: reach %v raiser %v failures %v", c.Reach, c.Raiser, c.Failures)
	}
	if _, ok := c.Raiser.(m10Raiser); !ok {
		t.Fatalf("response raises through %T, not core's raiser", c.Raiser)
	}
	cs := caseService(d)
	if cs.Reach == nil || cs.Response == nil {
		t.Fatal("cases lenses are not wired")
	}
	if edgesCaseOpener == nil || edgesContainer == nil || edgesCaseOpener(pool, nil) == nil || edgesContainer(pool, nil) == nil {
		t.Fatal("edges ports are not wired")
	}
	if _, ok := edgesRaiser(pool).(m10Raiser); !ok {
		t.Fatal("edges do not raise through core's raiser")
	}
	s := opsSources(d)
	if s.Containment == nil || s.Findings == nil {
		t.Fatalf("operations sources: %+v", s)
	}
}
