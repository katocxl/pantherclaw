// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/provisioning/adapters/provisioningrpc"
	papp "github.com/katocxl/pantherclaw/internal/provisioning/app"
)

// Provisioning (G0 M26 D405, D406, D409): the core keeps the directory,
// group role mappings and SAML connections, and ProvisioningService files
// every change that widens what a provider may do as an always-held
// protected change. The SCIM and SAML protocols are served by the
// enterprise build's extension, which is handed the directory and the
// sign-in through extension.Deps. The procedure permissions are in
// procedures_m26_provisioning.go.

// registerM26Provisioning serves ProvisioningService, registers its
// surfaces on the protect Gate and returns the extension's dependencies
// with the directory and the sign-in.
func registerM26Provisioning(rs *connect.Server, d apiDeps) extension.Deps {
	svc := &papp.Service{Pool: d.pool, IdPs: d.idps.store, Gate: d.m11protect.gate, CheckURL: oidcrp.CheckOrgURL, Clock: clock.System{}, Log: d.log}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	if d.m5 != nil && d.m5.notifications != nil {
		svc.Notify = d.m5.notifications
	}
	if d.m11protect.gate != nil {
		svc.Register(d.m11protect.gate)
	}
	pantherclawv1connect.RegisterProvisioningServiceHandler(rs, provisioningrpc.New(svc))
	deps := d.extDeps
	deps.Directory = svc
	if d.m5 != nil && d.m5.browser != nil && d.web != nil {
		deps.SignIn = &papp.SignIn{Pool: d.pool, Browser: d.m5.browser, Web: d.web, Clock: clock.System{}}
	}
	if deps.Audit == nil {
		deps.Audit = extAudit{pool: d.pool}
	}
	return deps
}

// closeM26Provisioning lets the Gate lapse a SCIM token or a SAML
// connection whose activation was declined or expired, in every role: the
// jobs role expires requests.
func closeM26Provisioning(g *protect.Gate) {
	if g != nil {
		papp.RegisterClosers(g)
	}
}

func init() { postureSourceFactories = append(postureSourceFactories, newProvisioningPostureSource) }

// newProvisioningPostureSource lists the API keys of deprovisioned people
// (D409 point 4).
func newProvisioningPostureSource(pool *db.Pool, _ exapp.Entitlements) ports.Source {
	return papp.Source{Pool: pool}
}
