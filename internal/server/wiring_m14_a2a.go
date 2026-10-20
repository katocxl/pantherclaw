// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"fmt"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// wireM14A2A registers the a2a kind's configuration store (G0 M14 D30,
// D64): a2a connections can then be created, their card pinned in the
// creating transaction, and gateways get the pin with the connection. It also
// records reported card drift on the pin (D86).
func wireM14A2A(core *m14Core) {
	if core == nil {
		return
	}
	core.kinds.Register(capp.KindA2A, &a2astore.Adapter{Pinner: a2astore.NewPinner()})
	core.kinds.RegisterDrift(capp.KindA2A, a2astore.DriftHook{})
}

// wireM14A2APeer gives the Authority its peer delegation (D33, D89): the
// decision-time check, and the child run and delegated grant at
// BeginDispatch, through the process's one grants service (the M11 core's,
// K6).
func wireM14A2APeer(svc *authority.Service, store *pgauthority.Store, autos *automationsCore, pool *db.Pool) {
	if svc == nil || store == nil || autos == nil || autos.grants == nil {
		return
	}
	peer := &authority.Peer{Grants: autos.grants, Pool: pool}
	store.Peer = peer.Delegate
	svc.WithPeerCheck(peer.Check)
}

// mountM14A2A adds the a2a pin confirm page (D85): a proposed card serves
// only once a person holding connection.manage confirms it there with a
// security key (D92), and the confirmation lifts a card-drift quarantine
// (D118), so the page is never mounted without the connections service
// (D122).
func mountM14A2A(mux *http.ServeMux, d apiDeps) error {
	if d.web == nil {
		return nil
	}
	if d.m6 == nil || d.m6.connections == nil {
		return fmt.Errorf("server: a2a pin page: %w", a2astore.ErrPinsWiring)
	}
	pins, err := a2astore.NewPins(d.pool, a2astore.NewPinner(), d.m6.connections)
	if err != nil {
		return fmt.Errorf("server: a2a pin page: %w", err)
	}
	d.web.MountA2APins(mux, pins)
	return nil
}
