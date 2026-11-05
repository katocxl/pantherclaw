// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"net/http"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/payments/anchors"
	paymentsapp "github.com/katocxl/pantherclaw/internal/payments/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// The M39 agent payment verification wiring (G0 M39 D1120–D1123):
// PaymentsService (trust anchors and agent request signatures) and the
// anchor activation page. Mandates are verified by internal/payments/ap2
// with anchors.Service.ForOrg; PantherClaw never signs and holds no
// payment credential.

// newPaymentAnchors builds the trust anchor service as pc_app with the
// licence (Business); nil without a pool.
func newPaymentAnchors(d apiDeps) (*anchors.Service, error) {
	if d.pool == nil {
		return nil, nil
	}
	svc, err := anchors.New(d.pool, anchors.Config{PublicURL: d.publicURL}, clock.System{}, d.log)
	if err != nil {
		return nil, err
	}
	if d.billing != nil {
		svc.WithEditions(d.billing)
	}
	return svc, nil
}

// registerM39Payments serves PaymentsService and returns the activation
// page's mount; nil when the service cannot run.
func registerM39Payments(rs *connect.Server, d apiDeps) (func(mux *http.ServeMux), error) {
	svc, err := newPaymentAnchors(d)
	if err != nil || svc == nil {
		return nil, err
	}
	pantherclawv1connect.RegisterPaymentsServiceHandler(rs, paymentsapp.New(svc))
	if d.web == nil {
		return nil, nil
	}
	web := d.web
	return func(mux *http.ServeMux) { web.MountPaymentAnchors(mux, svc) }, nil
}
