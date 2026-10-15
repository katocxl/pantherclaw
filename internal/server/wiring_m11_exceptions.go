// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"sync"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/exceptionsrpc"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
)

// gateChanges are the policy gate's change requests per server (by pool),
// with EXCEPTION registered: exception requests are created through the
// same change requests, and the same apply callback, that the policy
// changes page confirms (G0 M11.1 D11, D14, D23).
var gateChanges = struct {
	sync.Mutex
	by map[*db.Pool]*policyapp.Changes
}{by: map[*db.Pool]*policyapp.Changes{}}

func init() {
	policyGateExtensions = append(policyGateExtensions, func(d apiDeps, v *policyapp.Versions) {
		v.Changes.Register(policyapp.ChangeException, policyExceptions(d.pool, exceptionNotifier(d), v.Changes).Apply)
		gateChanges.Lock()
		defer gateChanges.Unlock()
		gateChanges.by[d.pool] = v.Changes
	})
}

func exceptionNotifier(d apiDeps) exceptions.Notifier {
	if d.m5 != nil && d.m5.notifications != nil {
		return d.m5.notifications
	}
	return nil
}

// policyExceptions builds the exception service as pc_app, telling owners
// through the M5 notifier when there is one.
func policyExceptions(pool *db.Pool, notify exceptions.Notifier, changes exceptions.ChangeRequester) *exceptions.Service {
	svc := &exceptions.Service{Pool: pool, Notify: notify}
	if changes != nil {
		svc.Changes = changes
	}
	return svc
}

// registerPolicyExceptions serves PolicyExceptionService on the public API,
// after registerPolicyGate. Without the gate's change requests no
// exception can be requested (fail closed).
func registerPolicyExceptions(rs *connect.Server, d apiDeps) *exceptions.Service {
	gateChanges.Lock()
	changes := gateChanges.by[d.pool]
	gateChanges.Unlock()
	var svc *exceptions.Service
	if changes != nil {
		svc = policyExceptions(d.pool, exceptionNotifier(d), changes)
	} else {
		svc = policyExceptions(d.pool, exceptionNotifier(d), nil)
	}
	pantherclawv1connect.RegisterPolicyExceptionServiceHandler(rs, exceptionsrpc.New(svc))
	return svc
}

// registerPolicyExceptionJobs adds the exception sweep (expiry, pending
// requests that ended unapproved, and the owner's notice a day before the
// expiry) and returns its schedule.
func registerPolicyExceptionJobs(reg *jobs.Registry, pool *db.Pool, notify exceptions.Notifier, log *slog.Logger) (
	[]*river.PeriodicJob, error,
) {
	return exceptions.RegisterSweep(reg, policyExceptions(pool, notify, nil), log)
}
