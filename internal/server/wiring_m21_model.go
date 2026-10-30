// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/model/adapters/anthropic"
	"github.com/katocxl/pantherclaw/internal/model/adapters/modelrpc"
	modelapp "github.com/katocxl/pantherclaw/internal/model/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/search"
)

// newModel builds model drafting's service (G0 M21 D304, D309). Without the
// server's switch it is still built, so an organization can always read that
// it is off and clear its key.
func newModel(d apiDeps) *modelapp.Service {
	svc := &modelapp.Service{
		Pool: d.pool, Envelope: pccrypto.NewEnvelope(keystore.NewDEKStore(d.pool, d.kp)), Provider: anthropic.New(),
		Config: modelapp.Config{Enabled: d.model.Enabled, CallsPerMinute: d.model.CallsPerMinute, TokensPerDay: d.model.TokensPerDay},
	}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	if n := edgesNotifier(d.m5); n != nil {
		svc.Notify = n
	}
	return svc
}

// registerM21Model registers ModelService.
func registerM21Model(rs *connect.Server, d apiDeps) {
	svc := newModel(d)
	defs := &defspg.Store{Pool: d.pool}
	queries := &search.Service{Pool: d.pool, Defs: defs, Clock: clock.System{}}
	if d.billing != nil {
		queries.Editions = d.billing
	}
	drafter := &search.Drafter{Search: queries, Model: svc}
	svc.Operations = drafter
	svc.Policies = securitysteps.NewPolicyDrafts(&factspg.Store{Pool: d.pool}, defs, d.cel)
	pantherclawv1connect.RegisterModelServiceHandler(rs, modelrpc.New(svc, drafter))
	if d.web != nil {
		d.web.WithModelDrafting(svc)
	}
}
