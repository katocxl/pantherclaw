// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/idps"
	"github.com/katocxl/pantherclaw/internal/idps/idpsrpc"
	"github.com/katocxl/pantherclaw/internal/keystore"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Organization identity providers (G0 M18 D155, D161, D162): the browser
// and device sign-in resolve an org's ACTIVE providers on each request in
// every edition, and IdentityProviderService files every change as an
// always-held protected change. The procedure permissions are in
// procedures_m18_idps.go.

// m18IdPs is the store the sign-in resolver and the service share.
type m18IdPs struct {
	store    *idps.Store
	resolver *idps.Resolver
}

// newM18IdPs builds the store, with the deployment's providers for the
// name check and the lock-out guard, and the per-request resolver.
func newM18IdPs(cfg *Config, pool *db.Pool, kp keys.KeyProvider, log *slog.Logger) m18IdPs {
	st := &idps.Store{Envelope: pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))}
	for _, p := range cfg.Auth.OIDCProviders {
		st.Deployment = append(st.Deployment, idps.Deployment{Name: p.Name, Issuer: p.Issuer})
	}
	return m18IdPs{store: st, resolver: &idps.Resolver{Pool: pool, Store: st, Log: log}}
}

// registerM18IdPs serves IdentityProviderService and registers its
// surfaces on the protect Gate.
func registerM18IdPs(rs *connect.Server, d apiDeps) {
	st := d.idps.store
	if st == nil {
		st = &idps.Store{Envelope: pccrypto.NewEnvelope(keystore.NewDEKStore(d.pool, d.kp))}
	}
	svc := &idps.Service{Pool: d.pool, Store: st, Gate: d.m11protect.gate, Probe: idps.DiscoveryProbe(nil)}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	if d.m5 != nil && d.m5.notifications != nil {
		svc.Notify = d.m5.notifications
	}
	if d.m11protect.gate != nil {
		svc.Register(d.m11protect.gate)
	}
	pantherclawv1connect.RegisterIdentityProviderServiceHandler(rs, idpsrpc.New(svc))
}
