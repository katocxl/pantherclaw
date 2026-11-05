// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"sync"

	"github.com/katocxl/pantherclaw/internal/payments/caps"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// The M39 agent payment actions wiring (G0 M39 D1124, D1124a): merchant
// caps are activated through the policy gate's change requests (kind
// PAYMENT_CAP, confirmed by two distinct people with security keys), so
// the caps service registers its apply callback on the server's change
// requests before anything is served.

// paymentCaps are the merchant cap services per server (by pool), built on
// the policy gate's change requests.
var paymentCaps = struct {
	sync.Mutex
	by map[*db.Pool]*caps.Service
}{by: map[*db.Pool]*caps.Service{}}

func init() {
	policyGateExtensions = append(policyGateExtensions, func(d apiDeps, v *policyapp.Versions) {
		svc := &caps.Service{Pool: d.pool, Changes: v.Changes}
		if d.billing != nil {
			svc.Editions = d.billing
		}
		v.Changes.Register(policyapp.ChangePaymentCap, svc.Apply)
		paymentCaps.Lock()
		defer paymentCaps.Unlock()
		paymentCaps.by[d.pool] = svc
	})
}

// paymentCapsOf is the server's merchant cap service, or nil before the
// policy gate is registered (no cap can then be proposed: fail closed).
func paymentCapsOf(pool *db.Pool) *caps.Service {
	paymentCaps.Lock()
	defer paymentCaps.Unlock()
	return paymentCaps.by[pool]
}
