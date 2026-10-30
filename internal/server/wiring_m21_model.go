// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/model/adapters/anthropic"
	"github.com/katocxl/pantherclaw/internal/model/adapters/modelrpc"
	modelapp "github.com/katocxl/pantherclaw/internal/model/app"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
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
	pantherclawv1connect.RegisterModelServiceHandler(rs, modelrpc.New(svc))
	if d.web != nil {
		d.web.WithModelDrafting(svc)
	}
}
