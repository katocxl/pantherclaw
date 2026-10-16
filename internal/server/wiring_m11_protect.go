// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"connectrpc.com/connect/v2"

	covapp "github.com/katocxl/pantherclaw/internal/coverage/app"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/protect/adapters/protectrpc"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// m11Protect is the protected-change Gate every hooked surface shares and
// the compromised-publisher use cases (G0 M11 part 2 D42, D43).
type m11Protect struct {
	gate       *protect.Gate
	publishers *protect.Publishers
}

// newM11Protect builds the Gate and the publishers. The change ceremony
// (internal/changes) is wired as the Gate's Requests in phase 2; until
// then a category that is turned on refuses its changes
// (PROTECTED_CHANGES_UNAVAILABLE) and nothing protected applies.
func newM11Protect(d apiDeps) m11Protect {
	gate := &protect.Gate{}
	pub := &protect.Publishers{Pool: d.pool, Gate: gate}
	if d.billing != nil {
		pub.Editions = d.billing
	}
	gate.Compromise = pub
	return m11Protect{gate: gate, publishers: pub}
}

// registerM11Protect serves ProtectedChangeService and PublisherService and
// holds the M6 surfaces' custody changes (connection settings, route
// modes, sealed credentials) behind the Gate. The procedure permissions
// are in procedures_m11_protect.go.
func registerM11Protect(rs *connect.Server, d apiDeps) {
	p := d.m11protect
	if d.m6 != nil {
		d.m6.connections.WithProtect(p.gate)
		d.m6.credentials.WithProtect(p.gate)
	}
	svc := &protect.Service{Pool: d.pool, Gate: p.gate, Failures: &failures.Sink{}}
	pantherclawv1connect.RegisterProtectedChangeServiceHandler(rs, protectrpc.NewChanges(svc))
	pantherclawv1connect.RegisterPublisherServiceHandler(rs, protectrpc.NewPublishers(p.publishers))
	if d.web != nil {
		d.web.WithProtect(protectPages{Service: svc, Publishers: p.publishers})
	}
}

// protectPages is the step-up use cases of the protected-change pages
// (D53).
type protectPages struct {
	*protect.Service
	*protect.Publishers
}

func (p protectPages) ProtectedChange(ctx context.Context, request ids.UUID) (dbq.PcProtectedChange, error) {
	return p.ByRequest(ctx, request)
}

// protectCoverage holds coverage exclusions behind the Gate.
func protectCoverage(svc *covapp.Service, p m11Protect) {
	if p.gate == nil {
		return
	}
	svc.Protect = p.gate
	p.gate.Register(protect.SurfaceExclusionCreate, svc.ApplyProtectedExclusion)
}

// protectPackages holds package activations behind the Gate.
func protectPackages(a *defsapp.Admin, d apiDeps) *defsapp.Admin {
	if p := d.m11protect; p.gate != nil {
		a.Protect = protect.PackageGate{Pool: d.pool, Gate: p.gate}
		p.gate.Register(protect.SurfacePackageActivate, a.ApplyProtectedActivation)
	}
	return a
}
