// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/exceptionsrpc"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
)

// The policy gate's change requests apply an approved EXCEPTION request by
// activating its exception (G0 M11.1 D11, D14, D23), from the policy
// changes page.
func init() {
	policyGateExtensions = append(policyGateExtensions, func(d apiDeps, v *policyapp.Versions) {
		v.Changes.Register(policyapp.ChangeException, policyExceptions(d.pool, exceptionNotifier(d), nil).Apply)
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
	return &exceptions.Service{Pool: pool, Notify: notify, Changes: changes}
}

// registerPolicyExceptions serves PolicyExceptionService on the public API.
// Its requests go through change requests configured as the gate's, with
// the same EXCEPTION apply callback.
func registerPolicyExceptions(rs *connect.Server, d apiDeps) {
	var notify policyapp.Notifier
	if d.m5 != nil && d.m5.notifications != nil {
		notify = d.m5.notifications
	}
	changes := policyapp.NewChanges(d.pool, notify, d.publicURL,
		currentPolicyDigests(&defspg.Store{Pool: d.pool}, &factspg.Store{Pool: d.pool}))
	svc := policyExceptions(d.pool, exceptionNotifier(d), changes)
	changes.Register(policyapp.ChangeException, svc.Apply)
	pantherclawv1connect.RegisterPolicyExceptionServiceHandler(rs, exceptionsrpc.New(svc))
}

// registerPolicyExceptionJobs adds the exception sweep (expiry, pending
// requests that ended unapproved, and the owner's notice a day before the
// expiry) and returns its schedule.
func registerPolicyExceptionJobs(reg *jobs.Registry, pool *db.Pool, notify exceptions.Notifier, log *slog.Logger) (
	[]*river.PeriodicJob, error,
) {
	return exceptions.RegisterSweep(reg, policyExceptions(pool, notify, nil), log)
}
