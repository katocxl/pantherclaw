// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"net/http"
	"testing"

	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// TestM14_A2APinPageNeedsTheQuarantineLifter (D122): the pin confirm page
// is never mounted without the connections service that lifts a card-drift
// quarantine: start-up fails with a wiring error instead, and the pins'
// constructor refuses a missing lifter.
func TestM14_A2APinPageNeedsTheQuarantineLifter(t *testing.T) {
	pool := &db.Pool{}
	d := apiDeps{pool: pool, web: &webhttp.Handler{}}
	if err := mountM14A2A(http.NewServeMux(), d); !errors.Is(err, a2astore.ErrPinsWiring) {
		t.Fatalf("no m6 services: %v", err)
	}
	d.m6 = &m6Services{}
	if err := mountM14A2A(http.NewServeMux(), d); !errors.Is(err, a2astore.ErrPinsWiring) {
		t.Fatalf("no connections service: %v", err)
	}
	if err := mountM14A2A(http.NewServeMux(), apiDeps{pool: pool}); err != nil {
		t.Fatalf("no web pages, nothing to mount: %v", err)
	}
	if _, err := a2astore.NewPins(pool, a2astore.NewPinner(), nil); !errors.Is(err, a2astore.ErrPinsWiring) {
		t.Fatalf("pins without a lifter: %v", err)
	}
	if p, err := a2astore.NewPins(pool, a2astore.NewPinner(), capp.New(pool, nil, "", "")); err != nil || p.Quarantines == nil {
		t.Fatalf("pins with the connections service: %+v %v", p, err)
	}
}
